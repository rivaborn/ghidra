/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "statusreport.hh"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

#ifdef _WINDOWS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define PSAPI_VERSION 2		// GetProcessMemoryInfo from kernel32, no psapi.lib
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602	// GetCurrentThreadStackLimits (Windows 8)
#endif
#include <windows.h>
#include <psapi.h>
#include <process.h>
#include <malloc.h>
#else
#include <sys/resource.h>
#include <unistd.h>
#endif

namespace ghidra {

bool StatusReport::enabled = false;

namespace {

std::mutex statusMutex;
string currentFunction;				///< "name @ address", empty between decompiles
std::chrono::steady_clock::time_point functionStart;
std::vector<const string *> actionStack;	///< Names of the Actions running, outermost first
std::atomic<int4> instructions(0);
uintb limitMB = 0;
string statusPath;
char *reserve = (char *)0;		///< Freed when an allocation fails, so the error can still be reported

/// Current and peak memory in MB: private commit on Windows, resident set elsewhere
void memoryMB(uintb &current,uintb &peak)

{
  current = 0;
  peak = 0;
#ifdef _WINDOWS
  PROCESS_MEMORY_COUNTERS pmc;
  if (GetProcessMemoryInfo(GetCurrentProcess(),&pmc,sizeof(pmc))) {
    current = pmc.PagefileUsage >> 20;
    peak = pmc.PeakPagefileUsage >> 20;
  }
#else
  FILE *f = fopen("/proc/self/status","r");
  if (f == (FILE *)0) return;
  char line[256];
  while(fgets(line,sizeof(line),f) != (char *)0) {
    unsigned long kb;
    if (sscanf(line,"VmRSS: %lu kB",&kb) == 1) current = kb >> 10;
    else if (sscanf(line,"VmHWM: %lu kB",&kb) == 1) peak = kb >> 10;
  }
  fclose(f);
#endif
}

long processId(void)

{
#ifdef _WINDOWS
  return (long)_getpid();
#else
  return (long)getpid();
#endif
}

/// Apply GHIDRA_DECOMPILER_MAXMEM_MB to this process
void applyMemoryLimit(void)

{
  const char *env = getenv("GHIDRA_DECOMPILER_MAXMEM_MB");
  if (env == (const char *)0 || *env == '\0') return;
  uintb mb = strtoull(env,(char **)0,10);
  if (mb == 0) return;
#ifdef _WINDOWS
  // The job limit counts committed memory, and the stack grows by committing pages: at the limit
  // a deeper call then dies with a stack overflow (0xC00000FD) instead of a catchable bad_alloc.
  // So commit the whole main-thread stack first: _alloca probes every page on the way down, and
  // the pages stay committed after this function returns.
  ULONG_PTR stackLow,stackHigh;
  GetCurrentThreadStackLimits(&stackLow,&stackHigh);
  ULONG_PTR here = (ULONG_PTR)&stackLow;
  const ULONG_PTR margin = 64 << 10;	// keep clear of the guard page
  if (here > stackLow + margin) {
    volatile char *probe = (volatile char *)_alloca(here - stackLow - margin);
    probe[0] = 0;
  }
  // A job object of our own (nested jobs need Windows 8+); the handle stays open for our lifetime
  HANDLE job = CreateJobObjectA((LPSECURITY_ATTRIBUTES)0,(LPCSTR)0);
  if (job == (HANDLE)0) return;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
  ZeroMemory(&info,sizeof(info));
  info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
  info.ProcessMemoryLimit = (SIZE_T)(mb << 20);
  if (!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&info,sizeof(info))) return;
  if (!AssignProcessToJobObject(job,GetCurrentProcess())) return;
#else
  struct rlimit rl;
  rl.rlim_cur = (rlim_t)(mb << 20);
  rl.rlim_max = (rlim_t)(mb << 20);
  if (setrlimit(RLIMIT_AS,&rl) != 0) return;
#endif
  limitMB = mb;
  // At the limit, the half-built function still holds the memory: keep a reserve to free so that
  // the "Out of memory" reply (strings, encoding) can be built and sent
  reserve = new char[8 << 20];
  for(size_t i=0;i<(8 << 20);i+=4096)
    reserve[i] = 0;		// commit the pages now
}

/// Write the status file once
void writeStatus(void)

{
  std::ostringstream s;
  {
    std::lock_guard<std::mutex> lock(statusMutex);
    if (currentFunction.empty())
      s << "function -\n";
    else {
      auto secs = std::chrono::duration_cast<std::chrono::seconds>(
	  std::chrono::steady_clock::now() - functionStart).count();
      s << "function " << currentFunction << "\n";
      s << "elapsed_s " << secs << "\n";
      s << "stage ";
      for(size_t i=0;i<actionStack.size();++i)
	s << (i == 0 ? "" : " > ") << *actionStack[i];
      s << "\n";
      s << "instructions " << instructions.load() << "\n";
    }
  }
  uintb cur,peak;
  memoryMB(cur,peak);
  s << "memory_mb " << cur << "\npeak_mb " << peak << "\nlimit_mb " << limitMB << "\n";
  string text = s.str();
  FILE *f = fopen(statusPath.c_str(),"wb");
  if (f == (FILE *)0) return;
  fwrite(text.data(),1,text.size(),f);
  fclose(f);
}

} // End anonymous namespace

void StatusReport::initialize(void)

{
  applyMemoryLimit();
  const char *dir = getenv("GHIDRA_DECOMPILER_STATUS");
  if (dir == (const char *)0 || *dir == '\0') return;
  std::ostringstream path;
  path << dir << "/decompile-" << processId() << ".status";
  statusPath = path.str();
  enabled = true;
  std::thread([]() {
    for(;;) {
      try {
	writeStatus();
      }
      catch(...) {
	// at the memory limit this thread's own allocations fail: an exception leaving the
	// thread would end the process, so skip this report instead
      }
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  }).detach();
}

void StatusReport::beginFunction(const string &name,const string &addr)

{
  if (!enabled) return;
  std::lock_guard<std::mutex> lock(statusMutex);
  currentFunction = name + " @ " + addr;
  functionStart = std::chrono::steady_clock::now();
  actionStack.clear();
  instructions = 0;
}

void StatusReport::endFunction(void)

{
  if (!enabled) return;
  std::lock_guard<std::mutex> lock(statusMutex);
  currentFunction.clear();
  actionStack.clear();
  instructions = 0;
}

void StatusReport::pushAction(const string *name)

{
  std::lock_guard<std::mutex> lock(statusMutex);
  actionStack.push_back(name);
}

void StatusReport::popAction(void)

{
  std::lock_guard<std::mutex> lock(statusMutex);
  if (!actionStack.empty())
    actionStack.pop_back();
}

void StatusReport::setInstructions(int4 count)

{
  if (enabled)
    instructions = count;
}

void StatusReport::releaseReserve(void)

{
  delete [] reserve;
  reserve = (char *)0;
}

uintb StatusReport::memoryLimitMB(void)

{
  return limitMB;
}

string StatusReport::memoryText(void)

{
  // Called right after an allocation failed: format into a fixed buffer
  uintb cur,peak;
  memoryMB(cur,peak);
  char buf[160];
  if (limitMB != 0)
    snprintf(buf,sizeof(buf),"%llu MB in use, peak %llu MB, limit %llu MB (GHIDRA_DECOMPILER_MAXMEM_MB)",
	     (unsigned long long)cur,(unsigned long long)peak,(unsigned long long)limitMB);
  else
    snprintf(buf,sizeof(buf),"%llu MB in use, peak %llu MB",(unsigned long long)cur,(unsigned long long)peak);
  return string(buf);
}

} // End namespace ghidra
