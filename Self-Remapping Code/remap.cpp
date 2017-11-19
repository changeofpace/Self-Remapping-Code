#include "remap.h"

#include <stdio.h>

#include "ntdll.h"
#include "pe_header.h"

void remap::RemapSelfImage(const PVOID RegionBase)
{
    PE_HEADER pe;
    if (!FillPEHeader(SIZE_T(RegionBase), pe))
        return;

    // Create a section to store the remapped image.
    HANDLE hRemapSection = NULL;
    LARGE_INTEGER sectionMaxSize = {};
    sectionMaxSize.QuadPart = pe.optionalHeader->SizeOfImage;
    NTSTATUS status = NtCreateSection(&hRemapSection,
                                      SECTION_ALL_ACCESS,
                                      NULL,
                                      &sectionMaxSize,
                                      PAGE_EXECUTE_READWRITE,
                                      SEC_COMMIT | SEC_NO_CHANGE,
                                      NULL);
    if (!NT_SUCCESS(status))
    {
        printf("NtCreateSection failed:  0x%08X.\n", status);
        return;
    }

    // Map an image-sized view of the remap section with write protection.
    PVOID copyViewBase = NULL;
    LARGE_INTEGER copySectionOffset = {};
    SIZE_T copyViewSize = 0;
    status = NtMapViewOfSection(hRemapSection,
                                GetCurrentProcess(),
                                &copyViewBase,
                                0,
                                pe.optionalHeader->SizeOfImage,
                                &copySectionOffset,
                                &copyViewSize,
                                ViewUnmap,
                                0,
                                PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        printf("NtMapViewOfSection failed for copy view:  0x%08X.\n", status);
        return;
    }

    // Write the image to the physical memory represented by the remap section.
    memcpy(copyViewBase, PVOID(pe.optionalHeader->ImageBase), pe.optionalHeader->SizeOfImage);

    // Unmap the image.
    status = NtUnmapViewOfSection(GetCurrentProcess(), PVOID(pe.optionalHeader->ImageBase));
    if (!NT_SUCCESS(status))
    {
        printf("NtUnmapViewOfSection failed for image:  0x%08X.\n", status);
        return;
    }

    // Reconstruct the image by mapping aligned views of the remap section for the image's PE Sections.
    // Each view represents one or more PE Sections (including the PE Header).
    // SEC_NO_CHANGE causes future attempts to change the protection of pages in these views to
    // fail with status code STATUS_INVALID_PAGE_PROTECTION.
    auto mapPeSection = [&hRemapSection](SIZE_T BaseAddress,
                                         SIZE_T RegionSize,
                                         SIZE_T RegionOffset,
                                         DWORD Protection)
    {
        PVOID viewBase = PVOID(BaseAddress);
        LARGE_INTEGER sectionOffset = {};
        sectionOffset.QuadPart = RegionOffset;
        SIZE_T viewSize = RegionSize;
        NTSTATUS status = NtMapViewOfSection(hRemapSection,
                                             GetCurrentProcess(),
                                             &viewBase,
                                             0,
                                             viewSize,
                                             &sectionOffset,
                                             &viewSize,
                                             ViewUnmap,
                                             SEC_NO_CHANGE,
                                             Protection);
        if (!NT_SUCCESS(status))
            printf("NtMapViewOfSection failed for view at base %p:  0x%08X.\n", BaseAddress, status);
        else
            printf("remapped \t %IX \t %IX \t %llX\n", viewBase, viewSize, sectionOffset.QuadPart);
    };

    const PIMAGE_SECTION_HEADER text = GetPeSectionByName(pe, ".text");
    const PIMAGE_SECTION_HEADER rdata = GetPeSectionByName(pe, ".rdata");
    const PIMAGE_SECTION_HEADER data = GetPeSectionByName(pe, ".data");
    if (!(text && text < rdata && rdata < data))
        return;

    // Mapped views for the PE Sections.
    // ========================================================================
    // Address Range (RVA)      Content                         Protection
    // ------------------------------------------------------------------------
    // 0x000000 - 0x0FFFFF      PE Header, .text.               PAGE_EXECUTE_READ
    // 0x100000 - 0x2FFFFF      .rdata                          PAGE_READONLY
    // 0x200000 - 0x203FFF      .data, .pdata, .rsrc, .reloc    PAGE_READWRITE
    // ------------------------------------------------------------------------
    mapPeSection(pe.optionalHeader->ImageBase,
                 PE_HEADER_SIZE + text->Misc.VirtualSize,
                 0,
                 PAGE_EXECUTE_READ);

    mapPeSection(pe.optionalHeader->ImageBase + rdata->VirtualAddress,
                 rdata->Misc.VirtualSize,
                 rdata->VirtualAddress,
                 PAGE_READONLY);

    mapPeSection(pe.optionalHeader->ImageBase + data->VirtualAddress,
                 0,
                 data->VirtualAddress,
                 PAGE_READWRITE);

    // Unmap the copy view.
    status = NtUnmapViewOfSection(GetCurrentProcess(), copyViewBase);
    if (!NT_SUCCESS(status))
    {
        printf("NtUnmapViewOfSection failed 0x%08X.\n", status);
        return;
    }

    if (!CloseHandle(hRemapSection))
        printf("CloseHandle failed %d.\n", GetLastError());
}
