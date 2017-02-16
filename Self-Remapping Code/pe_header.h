#pragma once

#include <Windows.h>

#include <array>
#include <vector>

#define PAGE_SIZE               0x1000
#define PAGE_ALIGN(Va)          ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))
#define ROUND_TO_PAGES(Size)    (((ULONG_PTR)(Size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

#define PE_HEADER_SIZE          0x1000

////////////////////////////////////////////////////////////////////////////////
// types

struct PE_HEADER
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_FILE_HEADER fileHeader;
    PIMAGE_OPTIONAL_HEADER optionalHeader;
    std::array<PIMAGE_DATA_DIRECTORY, IMAGE_NUMBEROF_DIRECTORY_ENTRIES> dataDirectory;
    std::vector<PIMAGE_SECTION_HEADER> sectionHeaders;
};

struct REMOTE_PE_HEADER : PE_HEADER
{
    ULONG_PTR remoteBaseAddress;
    BYTE rawData[PE_HEADER_SIZE];
};

////////////////////////////////////////////////////////////////////////////////
// ctors

bool FillPEHeader(ULONG_PTR BaseAddress, OUT PE_HEADER& PEHeader);
bool FillRemotePEHeader(HANDLE ProcessHandle, ULONG_PTR BaseAddress, OUT REMOTE_PE_HEADER& PEHeader);

////////////////////////////////////////////////////////////////////////////////
// utils

bool IsValidPEHeader(ULONG_PTR BaseAddress);
const PIMAGE_SECTION_HEADER GetPeSectionByName(const PE_HEADER& HeaderData, const char* SectionName);
DWORD GetSizeOfImage(PVOID BaseAddress);