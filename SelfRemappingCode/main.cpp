#include <Windows.h>

#include "log.h"
#include "remap.h"


//
// This linker option forces every pe section to be loaded at an address which
//  is aligned to the system allocation granularity. At runtime, each section
//  is padded with pages of reserved memory.
//
// NOTE This option does not affect file size.
//
#pragma comment(linker, "/ALIGN:0x10000")


//
// main
//
int
main(
    int argc,
    char* argv[]
)
{
    ULONG_PTR ImageBase = 0;
    int mainstatus = EXIT_SUCCESS;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    ImageBase = (ULONG_PTR)GetModuleHandleW(NULL);
    if (!ImageBase)
    {
        ERR_PRINT("GetModuleHandleW failed: %u\n", GetLastError());
        mainstatus = EXIT_FAILURE;
        goto exit;
    }

    if (!RmpRemapImage(ImageBase))
    {
        ERR_PRINT("RmpRemapImage failed.\n");
        mainstatus = EXIT_FAILURE;
        goto exit;
    }

exit:
    return mainstatus;
}
