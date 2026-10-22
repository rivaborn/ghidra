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

import java.util.Set;

/**
 * Export names of the original Xbox kernel (xboxkrnl.exe) by ordinal, as imported through an
 * XBE's kernel thunk table (each thunk is 0x80000000 | ordinal). Ordinals 1-366 are the retail
 * kernel exports; 374-378 are debug-kernel extras. Names listed in {@link #DATA} are exported
 * variables, not functions.
 */
public final class XboxKernelOrdinals {

	private XboxKernelOrdinals() {
		// table only
	}

	public static final String LIBRARY = "xboxkrnl.exe";

	/** NAMES[ordinal - 1] for ordinals 1..366 (the comment gives the first ordinal per row). */
	private static final String[] NAMES = {
		"AvGetSavedDataAddress", "AvSendTVEncoderOption", "AvSetDisplayMode", "AvSetSavedDataAddress",  // 1
		"DbgBreakPoint", "DbgBreakPointWithStatus", "DbgLoadImageSymbols", "DbgPrint",  // 5
		"HalReadSMCTrayState", "DbgPrompt", "DbgUnLoadImageSymbols", "ExAcquireReadWriteLockExclusive",  // 9
		"ExAcquireReadWriteLockShared", "ExAllocatePool", "ExAllocatePoolWithTag", "ExEventObjectType",  // 13
		"ExFreePool", "ExInitializeReadWriteLock", "ExInterlockedAddLargeInteger", "ExInterlockedAddLargeStatistic",  // 17
		"ExInterlockedCompareExchange64", "ExMutantObjectType", "ExQueryPoolBlockSize", "ExQueryNonVolatileSetting",  // 21
		"ExReadWriteRefurbInfo", "ExRaiseException", "ExRaiseStatus", "ExReleaseReadWriteLock",  // 25
		"ExSaveNonVolatileSetting", "ExSemaphoreObjectType", "ExTimerObjectType", "ExfInterlockedInsertHeadList",  // 29
		"ExfInterlockedInsertTailList", "ExfInterlockedRemoveHeadList", "FscGetCacheSize", "FscInvalidateIdleBlocks",  // 33
		"FscSetCacheSize", "HalClearSoftwareInterrupt", "HalDisableSystemInterrupt", "HalDiskCachePartitionCount",  // 37
		"HalDiskModelNumber", "HalDiskSerialNumber", "HalEnableSystemInterrupt", "HalGetInterruptVector",  // 41
		"HalReadSMBusValue", "HalReadWritePCISpace", "HalRegisterShutdownNotification", "HalRequestSoftwareInterrupt",  // 45
		"HalReturnToFirmware", "HalWriteSMBusValue", "InterlockedCompareExchange", "InterlockedDecrement",  // 49
		"InterlockedIncrement", "InterlockedExchange", "InterlockedExchangeAdd", "InterlockedFlushSList",  // 53
		"InterlockedPopEntrySList", "InterlockedPushEntrySList", "IoAllocateIrp", "IoBuildAsynchronousFsdRequest",  // 57
		"IoBuildDeviceIoControlRequest", "IoBuildSynchronousFsdRequest", "IoCheckShareAccess", "IoCompletionObjectType",  // 61
		"IoCreateDevice", "IoCreateFile", "IoCreateSymbolicLink", "IoDeleteDevice",  // 65
		"IoDeleteSymbolicLink", "IoDeviceObjectType", "IoFileObjectType", "IoFreeIrp",  // 69
		"IoInitializeIrp", "IoInvalidDeviceRequest", "IoQueryFileInformation", "IoQueryVolumeInformation",  // 73
		"IoQueueThreadIrp", "IoRemoveShareAccess", "IoSetIoCompletion", "IoSetShareAccess",  // 77
		"IoStartNextPacket", "IoStartNextPacketByKey", "IoStartPacket", "IoSynchronousDeviceIoControlRequest",  // 81
		"IoSynchronousFsdRequest", "IofCallDriver", "IofCompleteRequest", "KdDebuggerEnabled",  // 85
		"KdDebuggerNotPresent", "IoDismountVolume", "IoDismountVolumeByName", "KeAlertResumeThread",  // 89
		"KeAlertThread", "KeBoostPriorityThread", "KeBugCheck", "KeBugCheckEx",  // 93
		"KeCancelTimer", "KeConnectInterrupt", "KeDelayExecutionThread", "KeDisconnectInterrupt",  // 97
		"KeEnterCriticalRegion", "MmGlobalData", "KeGetCurrentIrql", "KeGetCurrentThread",  // 101
		"KeInitializeApc", "KeInitializeDeviceQueue", "KeInitializeDpc", "KeInitializeEvent",  // 105
		"KeInitializeInterrupt", "KeInitializeMutant", "KeInitializeQueue", "KeInitializeSemaphore",  // 109
		"KeInitializeTimerEx", "KeInsertByKeyDeviceQueue", "KeInsertDeviceQueue", "KeInsertHeadQueue",  // 113
		"KeInsertQueue", "KeInsertQueueApc", "KeInsertQueueDpc", "KeInterruptTime",  // 117
		"KeIsExecutingDpc", "KeLeaveCriticalRegion", "KePulseEvent", "KeQueryBasePriorityThread",  // 121
		"KeQueryInterruptTime", "KeQueryPerformanceCounter", "KeQueryPerformanceFrequency", "KeQuerySystemTime",  // 125
		"KeRaiseIrqlToDpcLevel", "KeRaiseIrqlToSynchLevel", "KeReleaseMutant", "KeReleaseSemaphore",  // 129
		"KeRemoveByKeyDeviceQueue", "KeRemoveDeviceQueue", "KeRemoveEntryDeviceQueue", "KeRemoveQueue",  // 133
		"KeRemoveQueueDpc", "KeResetEvent", "KeRestoreFloatingPointState", "KeResumeThread",  // 137
		"KeRundownQueue", "KeSaveFloatingPointState", "KeSetBasePriorityThread", "KeSetDisableBoostThread",  // 141
		"KeSetEvent", "KeSetEventBoostPriority", "KeSetPriorityProcess", "KeSetPriorityThread",  // 145
		"KeSetTimer", "KeSetTimerEx", "KeStallExecutionProcessor", "KeSuspendThread",  // 149
		"KeSynchronizeExecution", "KeSystemTime", "KeTestAlertThread", "KeTickCount",  // 153
		"KeTimeIncrement", "KeWaitForMultipleObjects", "KeWaitForSingleObject", "KfRaiseIrql",  // 157
		"KfLowerIrql", "KiBugCheckData", "KiUnlockDispatcherDatabase", "LaunchDataPage",  // 161
		"MmAllocateContiguousMemory", "MmAllocateContiguousMemoryEx", "MmAllocateSystemMemory", "MmClaimGpuInstanceMemory",  // 165
		"MmCreateKernelStack", "MmDeleteKernelStack", "MmFreeContiguousMemory", "MmFreeSystemMemory",  // 169
		"MmGetPhysicalAddress", "MmIsAddressValid", "MmLockUnlockBufferPages", "MmLockUnlockPhysicalPage",  // 173
		"MmMapIoSpace", "MmPersistContiguousMemory", "MmQueryAddressProtect", "MmQueryAllocationSize",  // 177
		"MmQueryStatistics", "MmSetAddressProtect", "MmUnmapIoSpace", "NtAllocateVirtualMemory",  // 181
		"NtCancelTimer", "NtClearEvent", "NtClose", "NtCreateDirectoryObject",  // 185
		"NtCreateEvent", "NtCreateFile", "NtCreateIoCompletion", "NtCreateMutant",  // 189
		"NtCreateSemaphore", "NtCreateTimer", "NtDeleteFile", "NtDeviceIoControlFile",  // 193
		"NtDuplicateObject", "NtFlushBuffersFile", "NtFreeVirtualMemory", "NtFsControlFile",  // 197
		"NtOpenDirectoryObject", "NtOpenFile", "NtOpenSymbolicLinkObject", "NtProtectVirtualMemory",  // 201
		"NtPulseEvent", "NtQueueApcThread", "NtQueryDirectoryFile", "NtQueryDirectoryObject",  // 205
		"NtQueryEvent", "NtQueryFullAttributesFile", "NtQueryInformationFile", "NtQueryIoCompletion",  // 209
		"NtQueryMutant", "NtQuerySemaphore", "NtQuerySymbolicLinkObject", "NtQueryTimer",  // 213
		"NtQueryVirtualMemory", "NtQueryVolumeInformationFile", "NtReadFile", "NtReadFileScatter",  // 217
		"NtReleaseMutant", "NtReleaseSemaphore", "NtRemoveIoCompletion", "NtResumeThread",  // 221
		"NtSetEvent", "NtSetInformationFile", "NtSetIoCompletion", "NtSetSystemTime",  // 225
		"NtSetTimerEx", "NtSignalAndWaitForSingleObjectEx", "NtSuspendThread", "NtUserIoApcDispatcher",  // 229
		"NtWaitForSingleObject", "NtWaitForSingleObjectEx", "NtWaitForMultipleObjectsEx", "NtWriteFile",  // 233
		"NtWriteFileGather", "NtYieldExecution", "ObCreateObject", "ObDirectoryObjectType",  // 237
		"ObInsertObject", "ObMakeTemporaryObject", "ObOpenObjectByName", "ObOpenObjectByPointer",  // 241
		"ObpObjectHandleTable", "ObReferenceObjectByHandle", "ObReferenceObjectByName", "ObReferenceObjectByPointer",  // 245
		"ObSymbolicLinkObjectType", "ObfDereferenceObject", "ObfReferenceObject", "PhyGetLinkState",  // 249
		"PhyInitialize", "PsCreateSystemThread", "PsCreateSystemThreadEx", "PsQueryStatistics",  // 253
		"PsSetCreateThreadNotifyRoutine", "PsTerminateSystemThread", "PsThreadObjectType", "RtlAnsiStringToUnicodeString",  // 257
		"RtlAppendStringToString", "RtlAppendUnicodeStringToString", "RtlAppendUnicodeToString", "RtlAssert",  // 261
		"RtlCaptureContext", "RtlCaptureStackBackTrace", "RtlCharToInteger", "RtlCompareMemory",  // 265
		"RtlCompareMemoryUlong", "RtlCompareString", "RtlCompareUnicodeString", "RtlCopyString",  // 269
		"RtlCopyUnicodeString", "RtlCreateUnicodeString", "RtlDowncaseUnicodeChar", "RtlDowncaseUnicodeString",  // 273
		"RtlEnterCriticalSection", "RtlEnterCriticalSectionAndRegion", "RtlEqualString", "RtlEqualUnicodeString",  // 277
		"RtlExtendedIntegerMultiply", "RtlExtendedLargeIntegerDivide", "RtlExtendedMagicDivide", "RtlFillMemory",  // 281
		"RtlFillMemoryUlong", "RtlFreeAnsiString", "RtlFreeUnicodeString", "RtlGetCallersAddress",  // 285
		"RtlInitAnsiString", "RtlInitUnicodeString", "RtlInitializeCriticalSection", "RtlIntegerToChar",  // 289
		"RtlIntegerToUnicodeString", "RtlLeaveCriticalSection", "RtlLeaveCriticalSectionAndRegion", "RtlLowerChar",  // 293
		"RtlMapGenericMask", "RtlMoveMemory", "RtlMultiByteToUnicodeN", "RtlMultiByteToUnicodeSize",  // 297
		"RtlNtStatusToDosError", "RtlRaiseException", "RtlRaiseStatus", "RtlTimeFieldsToTime",  // 301
		"RtlTimeToTimeFields", "RtlTryEnterCriticalSection", "RtlUlongByteSwap", "RtlUnicodeStringToAnsiString",  // 305
		"RtlUnicodeStringToInteger", "RtlUnicodeToMultiByteN", "RtlUnicodeToMultiByteSize", "RtlUnwind",  // 309
		"RtlUpcaseUnicodeChar", "RtlUpcaseUnicodeString", "RtlUpcaseUnicodeToMultiByteN", "RtlUpperChar",  // 313
		"RtlUpperString", "RtlUshortByteSwap", "RtlWalkFrameChain", "RtlZeroMemory",  // 317
		"XboxEEPROMKey", "XboxHardwareInfo", "XboxHDKey", "XboxKrnlVersion",  // 321
		"XboxSignatureKey", "XeImageFileName", "XeLoadSection", "XeUnloadSection",  // 325
		"READ_PORT_BUFFER_UCHAR", "READ_PORT_BUFFER_USHORT", "READ_PORT_BUFFER_ULONG", "WRITE_PORT_BUFFER_UCHAR",  // 329
		"WRITE_PORT_BUFFER_USHORT", "WRITE_PORT_BUFFER_ULONG", "XcSHAInit", "XcSHAUpdate",  // 333
		"XcSHAFinal", "XcRC4Key", "XcRC4Crypt", "XcHMAC",  // 337
		"XcPKEncPublic", "XcPKDecPrivate", "XcPKGetKeyLen", "XcVerifyPKCS1Signature",  // 341
		"XcModExp", "XcDESKeyParity", "XcKeyTable", "XcBlockCrypt",  // 345
		"XcBlockCryptCBC", "XcCryptService", "XcUpdateCrypto", "RtlRip",  // 349
		"XboxLANKey", "XboxAlternateSignatureKeys", "XePublicKeyData", "HalBootSMCVideoMode",  // 353
		"IdexChannelObject", "HalIsResetOrShutdownPending", "IoMarkIrpMustComplete", "HalInitiateShutdown",  // 357
		"RtlSnprintf", "RtlSprintf", "RtlVsnprintf", "RtlVsprintf",  // 361
		"HalEnableSecureTrayEject", "HalWriteSMCScratchRegister",  // 365
	};

	/** Exports that are variables (object types, counters, version blocks), not functions. */
	public static final Set<String> DATA = Set.of(
		"ExEventObjectType",
		"ExMutantObjectType",
		"ExSemaphoreObjectType",
		"ExTimerObjectType",
		"HalBootSMCVideoMode",
		"HalDiskCachePartitionCount",
		"HalDiskModelNumber",
		"HalDiskSerialNumber",
		"IdexChannelObject",
		"IoCompletionObjectType",
		"IoDeviceObjectType",
		"IoFileObjectType",
		"KdDebuggerEnabled",
		"KdDebuggerNotPresent",
		"KeInterruptTime",
		"KeSystemTime",
		"KeTickCount",
		"KeTimeIncrement",
		"KiBugCheckData",
		"LaunchDataPage",
		"MmGlobalData",
		"ObDirectoryObjectType",
		"ObSymbolicLinkObjectType",
		"ObpObjectHandleTable",
		"PsThreadObjectType",
		"XboxAlternateSignatureKeys",
		"XboxEEPROMKey",
		"XboxHDKey",
		"XboxHardwareInfo",
		"XboxKrnlVersion",
		"XboxLANKey",
		"XboxSignatureKey",
		"XeImageFileName",
		"XePublicKeyData");

	/** {@return the export name for an ordinal, or "Ordinal_N" when unknown} */
	public static String name(int ordinal) {
		if (ordinal >= 1 && ordinal <= NAMES.length) {
			return NAMES[ordinal - 1];
		}
		switch (ordinal) {
			case 374:
				return "MmDbgAllocateMemory";
			case 375:
				return "MmDbgFreeMemory";
			case 376:
				return "MmDbgQueryAvailablePages";
			case 377:
				return "MmDbgReleaseAddress";
			case 378:
				return "MmDbgWriteCheck";
			default:
				return "Ordinal_" + ordinal;
		}
	}
}
