#include "remap.h"

#include <stdio.h>

#include "pe_header.h"
#include "ntapi.h"

#define NtCurrentProcess		((HANDLE)(LONG_PTR)-1)

void remap::RemapSelfImage(const PVOID RegionBase)
{
    PE_HEADER pe;
    if (!FillPEHeader(SIZE_T(RegionBase), pe))
        return;

    // Create a section to store the remapped image.
    HANDLE hRemapSection = NULL;
    LARGE_INTEGER sectionMaxSize = {};
    sectionMaxSize.QuadPart = pe.optionalHeader->SizeOfImage;
    ntapi::NTSTATUS status = ntapi::NtCreateSection(&hRemapSection,
                                                    SECTION_ALL_ACCESS,
                                                    NULL,
                                                    &sectionMaxSize,
                                                    PAGE_EXECUTE_READWRITE,
                                                    SEC_COMMIT | ntapi::SEC_NO_CHANGE,
                                                    NULL);
    if (status != ntapi::STATUS_SUCCESS)
    {
        printf("NtCreateSection failed:  0x%08X.\n", status);
        return;
    }

    // Map an image-sized view of the remap section with write protection.
    PVOID copyViewBase = NULL;
    LARGE_INTEGER copySectionOffset = {};
    SIZE_T copyViewSize = 0;
    status = ntapi::NtMapViewOfSection(hRemapSection,
                                       NtCurrentProcess,
                                       &copyViewBase,
                                       0,
                                       pe.optionalHeader->SizeOfImage,
                                       &copySectionOffset,
                                       &copyViewSize,
                                       ntapi::ViewUnmap,
                                       0,
                                       PAGE_READWRITE);
    if (status != ntapi::STATUS_SUCCESS)
    {
        printf("NtMapViewOfSection failed for copy view:  0x%08X.\n", status);
        return;
    }

    // Write the image to the physical memory represented by the remap section.
    memcpy(copyViewBase, PVOID(pe.optionalHeader->ImageBase), pe.optionalHeader->SizeOfImage);

    const PIMAGE_SECTION_HEADER text = GetPeSectionByName(pe, ".text");
    const PIMAGE_SECTION_HEADER rdata = GetPeSectionByName(pe, ".rdata");
    const PIMAGE_SECTION_HEADER data = GetPeSectionByName(pe, ".data");
    if (!(text && text < rdata && rdata < data))
        return;

    // Prepare functions before unmapping otherwise it breaks on 32-bit because of non RIP-relative instructions like in 64-bit.
    HMODULE hmNtdll = GetModuleHandleA("ntdll.dll");
    ntapi::NtUnmapViewOfSection_t unmapFn = ntapi::NtUnmapViewOfSection_t(GetProcAddress(hmNtdll, "NtUnmapViewOfSection"));
    ntapi::NtMapViewOfSection_t mapFn = ntapi::NtMapViewOfSection_t(GetProcAddress(hmNtdll, "NtMapViewOfSection"));
    void *closeHandleFn = &CloseHandle;

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    // Unmap the image.
    status = unmapFn(NtCurrentProcess, PVOID(pe.optionalHeader->ImageBase));
    if (status != ntapi::STATUS_SUCCESS)
    {
        printf("NtUnmapViewOfSection failed for image:  0x%08X.\n", status);
        return;
    }

    // Reconstruct the image by mapping aligned views of the remap section for the image's PE Sections.
    // Each view represents one or more PE Sections (including the PE Header).
    // ntapi::SEC_NO_CHANGE causes future attempts to change the protection of pages in these views to 
    // fail with status code STATUS_INVALID_PAGE_PROTECTION.

    // Mapped views for the PE Sections, if they are aligned.
    // ========================================================================
    // Address Range (RVA)      Content                         Protection
    // ------------------------------------------------------------------------
    // 0x000000 - 0x0FFFFF      PE Header, .text.               PAGE_EXECUTE_READ
    // 0x100000 - 0x2FFFFF      .rdata                          PAGE_READONLY
    // 0x200000 - 0x203FFF      .data, .pdata, .rsrc, .reloc    PAGE_READWRITE
    // ------------------------------------------------------------------------
    PVOID viewBase = PVOID(pe.optionalHeader->ImageBase);
    LARGE_INTEGER sectionOffset = {};
    sectionOffset.QuadPart = 0;
    SIZE_T viewSize = rdata->VirtualAddress;
    while (viewSize % si.dwAllocationGranularity != 0) {
        viewSize++;
    }
    status = mapFn(hRemapSection, NtCurrentProcess, &viewBase, 0, 0, &sectionOffset, &viewSize, ntapi::ViewUnmap, ntapi::SEC_NO_CHANGE, PAGE_EXECUTE_READ);
    PVOID initialBase = viewBase;

    viewBase = PVOID((UINT_PTR)viewBase + viewSize);
    sectionOffset.QuadPart += viewSize;
    viewSize = data->VirtualAddress - viewSize;
    while (viewSize % si.dwAllocationGranularity != 0) {
        viewSize--;
    }
    status = mapFn(hRemapSection, NtCurrentProcess, &viewBase, 0, 0, &sectionOffset, &viewSize, ntapi::ViewUnmap, ntapi::SEC_NO_CHANGE, PAGE_READONLY);

    viewBase = PVOID((UINT_PTR)viewBase + viewSize);
    sectionOffset.QuadPart += viewSize;
    viewSize = 0;
    status = mapFn(hRemapSection, NtCurrentProcess, &viewBase, 0, 0, &sectionOffset, &viewSize, ntapi::ViewUnmap, ntapi::SEC_NO_CHANGE, PAGE_READWRITE);

    // Unmap the copy view.
    status = unmapFn(NtCurrentProcess, copyViewBase);
    if (status != ntapi::STATUS_SUCCESS)
    {
        printf("NtUnmapViewOfSection failed 0x%08X.\n", status);
        return;
    }

    // Might need to call GetProcAddress for this one as well.
    if (!reinterpret_cast<BOOL(WINAPI*)(HANDLE)>(closeHandleFn)(hRemapSection))
        printf("CloseHandle failed %d.\n", GetLastError());
}