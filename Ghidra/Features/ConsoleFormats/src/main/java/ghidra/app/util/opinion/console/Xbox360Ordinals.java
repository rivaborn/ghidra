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
package ghidra.app.util.opinion.console;

import java.util.*;

/**
 * A PARTIAL table of Xbox 360 system-module exports by ordinal (xboxkrnl.exe ordinals 1-65 and
 * a few xam.xex input exports). Everything else imports as {@code Ordinal_N}. A complete list
 * can be supplied with the loader's export-names file option ({@code <library> <ordinal> <name>}
 * per line), which takes precedence over this table.
 */
public final class Xbox360Ordinals {

	private Xbox360Ordinals() {
		// table only
	}

	private static final String[] KERNEL = { "DbgBreakPoint", "DbgBreakPointWithStatus",
		"DbgPrint", "DbgPrompt", "DumpGetRawDumpInfo", "DumpWriteDump",
		"ExAcquireReadWriteLockExclusive", "ExAcquireReadWriteLockShared", "ExAllocatePool",
		"ExAllocatePoolWithTag", "ExAllocatePoolTypeWithTag", "ExConsoleGameRegion",
		"ExCreateThread", "ExEventObjectType", "ExFreePool", "ExGetXConfigSetting",
		"ExInitializeReadWriteLock", "ExMutantObjectType", "ExQueryPoolBlockSize",
		"ExRegisterThreadNotification", "ExRegisterTitleTerminateNotification",
		"ExReleaseReadWriteLock", "ExSemaphoreObjectType", "ExSetXConfigSetting",
		"ExTerminateThread", "ExTerminateTitleProcess", "ExThreadObjectType",
		"ExTimerObjectType", "MmDoubleMapMemory", "MmUnmapMemory", "XeKeysGetConsoleCertificate",
		"FscGetCacheElementCount", "FscSetCacheElementCount", "HalGetCurrentAVPack",
		"HalGpioControl", "HalOpenCloseODDTray", "HalReadWritePCISpace",
		"HalRegisterPowerDownNotification", "HalRegisterSMCNotification", "HalReturnToFirmware",
		"HalSendSMCMessage", "HalSetAudioEnable", "InterlockedFlushSList",
		"InterlockedPopEntrySList", "InterlockedPushEntrySList", "IoAcquireDeviceObjectLock",
		"IoAllocateIrp", "IoBuildAsynchronousFsdRequest", "IoBuildDeviceIoControlRequest",
		"IoBuildSynchronousFsdRequest", "IoCallDriver", "IoCheckShareAccess",
		"IoCompleteRequest", "IoCompletionObjectType", "IoCreateDevice", "IoCreateFile",
		"IoDeleteDevice", "IoDeviceObjectType", "IoDismountVolume",
		"IoDismountVolumeByFileHandle", "IoDismountVolumeByName", "IoFileObjectType",
		"IoFreeIrp", "IoInitializeIrp", "IoInvalidDeviceRequest" };

	private static final Map<Integer, String> XAM = Map.of(400, "XamInputGetCapabilities", 401,
		"XamInputGetState", 402, "XamInputSetState");

	/** Data (variable) exports among the names above. */
	public static final Set<String> DATA =
		Set.of("ExConsoleGameRegion", "ExEventObjectType", "ExMutantObjectType",
			"ExSemaphoreObjectType", "ExThreadObjectType", "ExTimerObjectType",
			"IoCompletionObjectType", "IoDeviceObjectType", "IoFileObjectType");

	/** {@return the name for {@code library}'s export {@code ordinal}, or Ordinal_N} */
	public static String name(String library, int ordinal) {
		String lib = library.toLowerCase(Locale.ROOT);
		if (lib.equals("xboxkrnl.exe") && ordinal >= 1 && ordinal <= KERNEL.length) {
			return KERNEL[ordinal - 1];
		}
		if (lib.equals("xam.xex") && XAM.containsKey(ordinal)) {
			return XAM.get(ordinal);
		}
		return "Ordinal_" + ordinal;
	}
}
