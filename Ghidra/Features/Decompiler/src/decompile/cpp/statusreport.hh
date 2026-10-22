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
/// \file statusreport.hh
/// \brief Status file and memory limit for long-running decompiles
///
/// Both are off unless the environment asks for them:
///   - \b GHIDRA_DECOMPILER_STATUS names a directory. A background thread writes
///     \<dir>/decompile-\<pid>.status every second: the function being decompiled, its elapsed
///     time, the stack of Actions running, the instructions translated so far, and the memory
///     the process uses. The Java side (telemetry) reads it.
///   - \b GHIDRA_DECOMPILER_MAXMEM_MB caps the memory of this process. Allocation beyond it fails,
///     the current decompile reports "Out of memory", and the process exits so a fresh one
///     takes the next function.
#ifndef __STATUSREPORT_HH__
#define __STATUSREPORT_HH__

#include "types.h"
#include <string>

namespace ghidra {

using std::string;

/// \brief Optional progress reporting and memory limit for the decompiler process
class StatusReport {
public:
  static bool enabled;				///< True when a status file is being written
  static void initialize(void);			///< Read the environment, apply the memory limit, start the writer
  static void beginFunction(const string &name,const string &addr);	///< A decompile starts
  static void endFunction(void);		///< The decompile ended
  static void pushAction(const string *name);	///< An Action starts (name must outlive the call)
  static void popAction(void);			///< The innermost Action ended
  static void setInstructions(int4 count);	///< Instructions translated so far in the current function
  static uintb memoryLimitMB(void);		///< The memory limit in MB (0 = none)
  static void releaseReserve(void);		///< Free the emergency reserve (after an allocation failed)
  static string memoryText(void);		///< Current and peak memory, for messages
};

/// \brief Pushes an Action on the status stack for the lifetime of the object
class StatusActionScope {
  bool active;
public:
  StatusActionScope(const string &name) {
    active = StatusReport::enabled; if (active) StatusReport::pushAction(&name); }
  ~StatusActionScope(void) { if (active) StatusReport::popAction(); }
};

} // End namespace ghidra
#endif
