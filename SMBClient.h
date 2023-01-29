#define SECURITY_WIN32 

#pragma once
#include "Windows.h"

#define SEC_SUCCESS(Status) ((Status) >= 0)
#define DEFAULT_BUFLEN 8192
#define MessageAttribute ISC_REQ_INTEGRITY
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
        long long MessageID;
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

typedef struct {
    short structured_size;;
    short flags;
    short path_offset;
    short path_len;
} tree_connect_request_header;

typedef union {
    tree_connect_request_header trh;
    char buffer[sizeof(trh)];
} u_tree_connect_request_header;

typedef struct {
    short StructuredSize;
    byte SecurityFlags;
    byte RequestedOplockLevel;
    int ImpersonationLevel;
    char SmbCreateFlags[8];
    char Reserved[8];
    char DesiredAccess[4];
    char FileAttribute[4];
    char ShareAccess[4];
    char CreateDisposition[4];
    char CreateOptions[4];
    short NameOffset;
    short NameLength;
    int CreateContextsOffset;
    int CreateContextsLength;
} create_request;

typedef union
{
    create_request cr;
    char buffer[sizeof(cr)];
} u_create_request;

typedef struct {
    short StructureSize;
    short DataOffset;
    int WriteLen;
    long long FileOffset;
    char fileid[16];
    int RemainingBytes;
    char filler[8];
} write_request;

typedef union {
    write_request wr;
    char buffer[sizeof(wr)];
} u_write_request;

void SMBAuthenticatedFileWrite();

