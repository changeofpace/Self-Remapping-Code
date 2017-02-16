#pragma once

#include <Windows.h>

namespace remap {

// Remap the currently executing process's image as a series of
// memory mapped views. This function should execute in a dynamically
// allocated memory region containing a copy of the image.
void RemapSelfImage(const PVOID RegionBase);

} // namespace remap