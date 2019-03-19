# Self-Remapping Code

## Summary

This program remaps its image to prevent the page protection of pages contained in the image from being modified via NtProtectVirtualMemory.

## Motivation

This technique can be utilized as an anti-debugging and anti-dumping mechanism.

## Implementation

The remapping technique uses the following strategy:

1. The image is copied to an executable buffer referred to as the 'remap
    region'.

2. The remap routine inside the remap region is located and invoked.

3. The remap routine creates a page-file-backed section to store the
    remapped image.

4. The remap routine maps a view of the entire section and copies the
    contents of the image to the view. This view is then unmapped.

5. The remap routine maps a view for each pe section in the image using the
    relative virtual address of the pe section as the section offset for
    the view. Each view is mapped using the 'SEC_NO_CHANGE' allocation
    type to prevent page protection changes.

6. The remap routine completes and execution returns to the remapped image.

The following tables are examples of the memory layout of an image before and after it has been remapped using this technique:

##### Before

<pre>
Address          Size             Info                          Type   Protect  Initial
=======================================================================================
0000000140000000 0000000000001000 selfremappingcode.exe         IMG    -R---    ERWC-
0000000140001000 000000000000F000 Reserved (0000000140000000)   IMG             ERWC-
0000000140010000 0000000000002000  ".text"                      IMG    ER---    ERWC-
0000000140012000 000000000000E000 Reserved (0000000140000000)   IMG             ERWC-
0000000140020000 0000000000002000  ".rdata"                     IMG    -R---    ERWC-
0000000140022000 000000000000E000 Reserved (0000000140000000)   IMG             ERWC-
0000000140030000 0000000000001000  ".data"                      IMG    -RW--    ERWC-
0000000140031000 000000000000F000 Reserved (0000000140000000)   IMG             ERWC-
0000000140040000 0000000000001000  ".pdata"                     IMG    -R---    ERWC-
0000000140041000 000000000000F000 Reserved (0000000140000000)   IMG             ERWC-
0000000140050000 0000000000001000  ".rsrc"                      IMG    -R---    ERWC-
0000000140051000 000000000000F000 Reserved (0000000140000000)   IMG             ERWC-
</pre>

##### After

<pre>
Address          Size             Info                          Type   Protect  Initial
=======================================================================================
0000000140000000 0000000000001000                               MAP    -R---    -R---
0000000140010000 0000000000002000                               MAP    ER---    ER---
0000000140020000 0000000000002000                               MAP    -R---    -R---
0000000140030000 0000000000001000                               MAP    -RW--    -RW--
0000000140040000 0000000000001000                               MAP    -R---    -R---
0000000140050000 0000000000001000                               MAP    -R---    -R---
</pre>

## Requirements

- Each pe section in the image must be aligned to the system allocation granularity. This program uses the `/ALIGN` linker option to achieve this alignment.
