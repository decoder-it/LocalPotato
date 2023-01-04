#define SECURITY_WIN32 

#pragma once
#include "Windows.h"

#define NTLM_RESERVED_OFFSET 32

void HookSSPIForDCOMReflection();
