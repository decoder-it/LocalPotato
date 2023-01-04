#define SECURITY_WIN32 

#pragma once
#include "Windows.h"

#define SEC_SUCCESS(Status) ((Status) >= 0)
#define DEFAULT_BUFLEN 8192
#define MessageAttribute ISC_REQ_NO_INTEGRITY 
#define TargetNameSpn L"cifs/127.0.0.1"

typedef union usmb2_header {
    struct
    {
        BYTE ProtocolID[4];
        BYTE StructureSize[2];
        BYTE CreditCharge[2];
        BYTE ChannelSequence[2];
        BYTE Reserved[2];
        BYTE Command[2];
        BYTE CreditRequest[2];
        BYTE Flags[4];
        BYTE NextCommand[4];
        BYTE MessageID[8];
        BYTE ProcessID[4];
        BYTE TreeID[4];
        BYTE SessionID[8];
        BYTE Signature[16];
    } smb2_header;
    BYTE buffer[64];
};

typedef union usmb2_data {

    struct {
        BYTE StructureSize[2];
        BYTE Flags[1];
        BYTE SecurityMode[1];
        BYTE Capabilities[4];
        BYTE Channel[4];
        BYTE SecurityBufferOffset[2];
        BYTE SecurityBufferLength[2];
        BYTE PreviousSessionID[8];
    } smb2_data;
    BYTE buffer[24];
};

union myint {
    unsigned int i;
    char buffer[4];
};
union myshort {
    unsigned short int i;
    char buffer[2];
};
union mydw {
    DWORD i;
    char buffer[8];
};

void SMBAuthenticatedFileWrite();