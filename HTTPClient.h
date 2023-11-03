#pragma once
#include "Windows.h"

#define SEC_SUCCESS(Status) ((Status) >= 0)
#define DEFAULT_BUFLEN 16192
#define MessageAttribute ISC_REQ_NO_INTEGRITY 

void HTTPAuthenticatedGET();