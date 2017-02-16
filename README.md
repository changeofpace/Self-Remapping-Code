# Self-Remapping Code

## Summary

This program remaps its image to prevent its .text and .rdata PE sections from being made writable via NtProtectVirtualMemory.

## Motivation

Processes can utilize this technique as an anti-debugging / anti-hacking mechanism to prevent third-party processes and injected code from patching the image.

## Implementation

Image, in this context, refers to the memory mapped view of the image section for the executing process:

<pre>
Address           Size               Info                                    Content                      Type   Protect  Initial
000000013FD90000  0000000000001000   selfremappingcode.exe                                                IMG    -R---    ERWC-
000000013FD91000  000000000000F000    ".text"                                Executable code              IMG    ER---    ERWC-
000000013FDA0000  0000000000010000    ".rdata"                               Read-only initialized data   IMG    -R---    ERWC-
000000013FDB0000  0000000000001000    ".data"                                Initialized data             IMG    -RW--    ERWC-
000000013FDB1000  0000000000003000    ".pdata", ".rsrc", ".reloc"            Exception information        IMG    -R---    ERWC-
</pre>

The process begins by copying its image to a dynamically allocated memory region with PAGE\_EXECUTE\_READWRITE protection. The address of the remapping function, RemapSelfImage, is located in the copied image region then executed. RemapSelfImage creates a page-file-backed section to store the remapped view. A full view of this section is mapped with PAGE\_READWRITE protection. The image is written to physical memory by copying the original image to this view. The original image is unmapped and reconstructed by mapping aligned views of the section for the image's PE Sections. Each of these views is mapped with the undocumented allocation type: **SEC\_NO\_CHANGE** (0x00400000). This value causes future attempts to change the protection of pages in these views to fail with status code **STATUS\_INVALID\_PAGE\_PROTECTION** (0xC0000045). Finally, the copy view is unmapped and execution continues in the remapped image's memory region.

The remapped image's layout:

<pre>
Address           Size               Info                                    Content                      Type   Protect  Initial
000000013FD90000  0000000000010000    ".text"                                Executable code              MAP    ER---    ER---
000000013FDA0000  0000000000010000    ".rdata"                               Read-only initialized data   MAP    -R---    -R---
000000013FDB0000  0000000000004000    ".data", ".pdata", ".rsrc", ".reloc"   Initialized data             MAP    -RW--    -RW--
</pre>

## Defeating This Protection

How to patch memory using this protection:

1. Pause all threads in the target process.
2. Allocate a memory buffer large enough to contain the view you want to patch.
3. Copy the target view's content to this buffer.
4. Create a page-file-backed section using the target view's size as the maximum size.
5. Unmap the target view.
6. Map a view of this section with base address set to the target view's base address, size set to target view's size, and protection set to the desired protection (PAGE\_EXECUTE\_READWRITE).
7. Patch.
8. Resume all threads in the target process.
9. OPTIONAL: Repeat the above steps using the original protection value when mapping the view.

The target process can detect this method by querying the view's MEMORY\_BASIC\_INFORMATION and comparing the view's AllocationProtect against the expected protection value. The attacker can easily overcome this check by repeating the steps above using the view's original protection when mapping the view.

## Issues

- Each view must be aligned to the system allocation granularity (64kB / 0x10000 bytes on Windows 7). This program overcomes this issue by padding .text and .rdata with filler code / constant data.

## Notes

- Developed / tested on Windows 7 SP1 x64.
- Code optimization is disabled to force filler code to be included.
