#include <Windows.h>

#include <stdio.h>
#include <array>

#include "filler.h"
#include "ntdll.h"
#include "pe_header.h"
#include "remap.h"

// Verify that .rdata and .data's base addresses are a multiple of the system 
// allocation granularity.
static bool ValidateSectionAlignment(const PVOID ImageBase)
{
    PE_HEADER pe;
    if (!FillPEHeader(SIZE_T(ImageBase), pe))
        return false;

    const PIMAGE_SECTION_HEADER text = GetPeSectionByName(pe, ".text");
    const PIMAGE_SECTION_HEADER rdata = GetPeSectionByName(pe, ".rdata");
    const PIMAGE_SECTION_HEADER data = GetPeSectionByName(pe, ".data");
    if (!(text && text < rdata && rdata < data))
        return false;

    auto printSectionSummary = [&ImageBase](const PIMAGE_SECTION_HEADER Section)
    {
        printf("%-8.8s \t %IX \t %X \t %X\n",
               Section->Name,
               SIZE_T(ImageBase) + Section->VirtualAddress,
               Section->Misc.VirtualSize,
               Section->VirtualAddress);
    };

    printf("=================================================================\n");
    printf("Section       Base Address       Size    Rva\n");
    printf("-----------------------------------------------------------------\n");
    printSectionSummary(text);
    printSectionSummary(rdata);
    printSectionSummary(data);
    printf("=================================================================\n");

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    auto isAligned = [&si](const PIMAGE_SECTION_HEADER Section)
    {
        return Section->VirtualAddress % si.dwAllocationGranularity == 0;
    };

    return isAligned(rdata) && isAligned(data);
}

// Verify that we're unable set .text or .rdata's page protection via NtProtectVirtualMemory.
// e.g., changing .text from PAGE_EXECUTE_READ to PAGE_EXECUTE_READWRITE should
// fail after remap::RemapSelfImage returns.
static void TestVirtualProtect(const PVOID ImageBase)
{
    PE_HEADER pe;
    if (!FillPEHeader(SIZE_T(ImageBase), pe))
        return;

    const PIMAGE_SECTION_HEADER text = GetPeSectionByName(pe, ".text");
    const PIMAGE_SECTION_HEADER rdata = GetPeSectionByName(pe, ".rdata");
    if (!(text && text < rdata))
        return;

    auto testVirtualProtect = [](SIZE_T BaseAddress, SIZE_T RegionSize, DWORD NewProtection)
    {
        PVOID regionBase = PVOID(BaseAddress);
        SIZE_T regionSize = RegionSize;
        DWORD oldProtection = 0;
        NTSTATUS status = NtProtectVirtualMemory(GetCurrentProcess(),
                                                 &regionBase,
                                                 &regionSize,
                                                 NewProtection,
                                                 &oldProtection);
        if (status != STATUS_INVALID_PAGE_PROTECTION &&
            NewProtection != oldProtection)
        {
            printf("Unexpected NtProtectVirtualMemory status for %p (%X):  0x%08X\n",
                   BaseAddress, NewProtection, status);
        }
    };

    const std::array<DWORD, 12> protectionValues =
    {
        PAGE_NOACCESS,
        PAGE_READONLY,
        PAGE_READWRITE,
        PAGE_WRITECOPY,
        PAGE_EXECUTE,
        PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY,
        PAGE_GUARD,
        PAGE_NOCACHE,
        PAGE_WRITECOMBINE,
        PAGE_REVERT_TO_FILE_MAP
    };

    for (auto protection : protectionValues)
    {
        // .text
        testVirtualProtect(pe.optionalHeader->ImageBase,
                           PE_HEADER_SIZE + text->Misc.VirtualSize,
                           protection);

        // .rdata
        testVirtualProtect(pe.optionalHeader->ImageBase + rdata->VirtualAddress,
                           rdata->Misc.VirtualSize,
                           protection);
    }
}

int main(int argc, char* argv[])
{
    const PVOID imagebase = GetModuleHandleA(NULL);
    if (ValidateSectionAlignment(imagebase))
    {
        const DWORD imageSize = GetSizeOfImage(imagebase);

        // Allocate an executable / writable memory region where the remapping code will execute.
        if (PVOID remapperRegion = VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
        {
            // Copy SelfRemappingCode.exe's image to this region.
            memcpy(remapperRegion, imagebase, imageSize);

            // Calculate remap::RemapSelfImage's VA in this region.
            typedef void(*Remap_t)(PVOID);
            Remap_t Remap = Remap_t(SIZE_T(remapperRegion) + SIZE_T(remap::RemapSelfImage) - SIZE_T(imagebase));

            // Process execution continues in the new region.
            Remap(remapperRegion);
            // Process execution returns to the original (remapped) region.

            VirtualFree(remapperRegion, 0, MEM_RELEASE);

            TestVirtualProtect(imagebase);

            for (;;)
            {
                printf("Zzz...\n");
                Sleep(3000);
            }
        }
        else
        {
            printf("VirtualAlloc failed for remapper region:  %d.\n", GetLastError());
        }
    }
    else
    {
        printf("Error: .rdata or .data are not aligned to system allocation granularity.\n");
    }

    // Force-include filler code / data.
    if (SIZE_T(imagebase) == 1) { filler::text(); const double zxcv = filler::rdata[3]; }

    getchar();
    return 0;
}
