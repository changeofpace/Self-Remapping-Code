#pragma once

#include <Windows.h>

typedef long NTSTATUS;

#pragma region macros

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

// NTSTATUS codes
#define STATUS_INVALID_PAGE_PROTECTION   ((NTSTATUS)0xC0000045L)
#define STATUS_PROCEDURE_NOT_FOUND       ((NTSTATUS)0xC000007AL)

// Flags
#define SEC_NO_CHANGE 0x00400000

// Page utils
#define PAGE_SIZE               0x1000
#define PAGE_ALIGN(Va)          ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))
#define ROUND_TO_PAGES(Size)    (((ULONG_PTR)(Size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

#pragma endregion macros


#pragma region types

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

#pragma endregion types


#pragma region prototypes

EXTERN_C
NTSTATUS
NTAPI
NtCreateSection(
    _Out_    PHANDLE            SectionHandle,
    _In_     ACCESS_MASK        DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER     MaximumSize,
    _In_     ULONG              SectionPageProtection,
    _In_     ULONG              AllocationAttributes,
    _In_opt_ HANDLE             FileHandle
);

EXTERN_C
NTSTATUS
NTAPI
NtMapViewOfSection(
    _In_        HANDLE          SectionHandle,
    _In_        HANDLE          ProcessHandle,
    _Inout_     PVOID           *BaseAddress,
    _In_        ULONG_PTR       ZeroBits,
    _In_        SIZE_T          CommitSize,
    _Inout_opt_ PLARGE_INTEGER  SectionOffset,
    _Inout_     PSIZE_T         ViewSize,
    _In_        SECTION_INHERIT InheritDisposition,
    _In_        ULONG           AllocationType,
    _In_        ULONG           Win32Protect
);

EXTERN_C
NTSTATUS
NTAPI
NtUnmapViewOfSection(
    _In_        HANDLE  ProcessHandle,
    _In_opt_    PVOID   BaseAddress
);

EXTERN_C
NTSTATUS
NTAPI
NtProtectVirtualMemory(
    _In_    HANDLE  ProcessHandle,
    _Inout_ PVOID*  BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_    ULONG   NewProtection,
    _Out_   PULONG  OldProtection
);

#pragma endregion prototypes
