#pragma once

#include <Windows.h>

//=============================================================================
// Public Interface
//=============================================================================
_Check_return_
BOOL
RmpRemapImage(
    _In_ ULONG_PTR ImageBase
);
