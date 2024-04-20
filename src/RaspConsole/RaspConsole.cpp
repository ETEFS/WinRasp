#include <windows.h>
#include <stdio.h>
#include <time.h>
#include "..\FileEvent\FileEvent.h"
#include "..\RaspApi\raspapi.h"

#ifdef _DEBUG
	#ifdef _M_IX86
		#pragma  comment(lib, "../../bin/Win32/debug/lib/FileEvent.lib")
		#pragma  comment(lib, "../../bin/Win32/debug/lib/RaspApi.lib")
	#elif defined _M_X64
		#pragma  comment(lib, "../../bin/x64/debug/lib/FileEvent.lib")
		#pragma  comment(lib, "../../bin/x64/debug/lib/RaspApi.lib")
	#endif
#else
	#ifdef _M_IX86
		#pragma  comment(lib, "../../bin/Win32/release/lib/FileEvent.lib")
		#pragma  comment(lib, "../../bin/Win32/release/lib/RaspApi.lib")
	#elif defined _M_X64
		#pragma  comment(lib, "../../bin/x64/release/lib/FileEvent.lib")
		#pragma  comment(lib, "../../bin/x64/release/lib/RaspApi.lib")
	#endif
#endif

void ShowUsage()
{
	printf("*** RaspConsole - Tools for WinRasp ***\n");
	printf("*** Copyright AT etefs.com          ***\n");
	printf("*** etefs@etefs.com                 ***\n\n");

	printf("File Security:\n");
	printf("    List opened file handle   ----   RaspConsole /list_file_handle   c:\\file.txt\n");
	printf("    Close opened file handle  ----   RaspConsole /close_file_handle  pid  handle\n");
	printf("    Add a protected dir       ----   RaspConsole /add_protected_dir  c:\\testdir\\*  dispo\n");
	printf("    List protected dir        ----   RaspConsole /list_protected_dir \n");
	printf("    Remove a protected dir    ----   RaspConsole /rm_protected_dir dir/file \n");
	printf("    Add a hiding dir          ----   RaspConsole /add_hide_dir  c:\\hide_dir\n");
	printf("    Remove a hiding dir       ----   RaspConsole /rm_hide_dir  c:\\hide_dir\n");
	printf("    List hiding dirs          ----   RaspConsole /list_hide_dir   \n");
	printf("    Direct Read/Write File    ----   RaspConsole /direct_rw_file c:\\test.txt  \n");
	printf("\n");

	printf("Process Security:\n");
	printf("    Add proc create mon dir   ----   RaspConsole /add_proc_create_mon_dir  c:\\testexe\\*  dispo\n");
	printf("    Rm proc create mon dir    ----   RaspConsole /rm_proc_create_mon_dir  c:\\testexe\\*  \n");
	printf("    List proc create mon dir  ----   RaspConsole /list_proc_create_mon_dir   \n");
	printf("    Add Dll Load  mon         ----   RaspConsole /add_dll_load_mon  c:\\testexe\\*  c:\\testdll\\* dispo\n");
	printf("    Rm Dll Load  mon          ----   RaspConsole /rm_dll_load_mon  c:\\testexe\\*  \n");
	printf("    List Dll Load mon         ----   RaspConsole /list_dll_load_mon   \n");
	printf("    Inject Dll to Proc        ----   RaspConsole /inject_dll PID  x86_dll x64_dll \n");
	printf("    Kill process              ----   RaspConsole /kill_process PID  Flag\n");
	printf("    Read process mem          ----   RaspConsole /read_proc_mem PID address Len\n");
	printf("    Write process mem         ----   RaspConsole /write_proc_mem PID address Len\n");
	printf("    List process              ----   RaspConsole /list_process\n");
	printf("    Add proc protect          ----   RaspConsole /add_proc_protect  PID dispo\n");
	printf("    Rm proc protect           ----   RaspConsole /rm_proc_protect  PID  \n");
	printf("    List proc protect         ----   RaspConsole /list_proc_protect \n");
	printf("\n");

	printf("Registry Security:\n");
	printf("    Add Reg Protect           ----   RaspConsole /add_reg_protect   dispo bHide\n");
	printf("    Rm Reg Protect            ----   RaspConsole /rm_reg_protect    \n");
	printf("    List Reg Protect          ----   RaspConsole /list_reg_protect   \n");
	printf("    Direct access key         ----   RaspConsole /direct_access_key   \n");
	printf("\n");

	printf("Misc Security:\n");
	printf("    Debug check               ----   RaspConsole /dbg_check   PID\n");
	printf("    Direct Network IO         ----   RaspConsole /direct_net_io \n");
	printf("    List Driver               ----   RaspConsole /list_driver\n");
	printf("    List Callback             ----   RaspConsole /list_callback\n");
	printf("    Remove Callback           ----   RaspConsole /remove_callback type addr cookie/handle\n");
	printf("\n");


	system("pause");
}

class CEventHandler: public IEventReceiver
{
public:
	DWORD  OnFileEvent(PFILE_EVENT_PACKET  pFileEventPacket) ;
};

CEventHandler EventHandler;

//
//File/Directory Security
//
void ListFileHandle(int argc, char* argv[]);
void CloseFileHandle(int argc, char* argv[]);
void AddProtectedDir(int argc, char* argv[]);
void ListProtectedDir(int argc, char* argv[]);
void RmProtectedDir(int argc, char* argv[]);
void AddHideDir(int argc, char* argv[]);
void RmHideDir(int argc, char* argv[]);
void ListHideDir(int argc, char* argv[]);
void DirectReadWriteFile(int argc, char* argv[]);

//
//Process Security
//
void AddProcCreationMon(int argc, char* argv[]);
void RmProcCreationMon(int argc, char* argv[]);
void ListProcCreationMon(int argc, char* argv[]);
void AddDllLoadMon(int argc, char* argv[]);
void RmDllLoadMon(int argc, char* argv[]);
void ListDllLoadMon(int argc, char* argv[]);
void InjectDll(int argc, char* argv[]);
void KillProcess(int argc, char* argv[]);
void ReadWriteProcessMemory(int argc, char* argv[]);
void ListProcess(int argc, char* argv[]);
void AddProcProtect(int argc, char* argv[]);
void RmProcProtect(int argc, char* argv[]);
void ListProcProtect(int argc, char* argv[]);

//
//Registry Security
//
void AddRegProtect(int argc, char* argv[]);
void RmRegProtect(int argc, char* argv[]);
void ListRegProtect(int argc, char* argv[]);
void DirectAccessKey(int argc, char* argv[]);

//
//Misc Security
//
void DbgCheck(int argc, char* argv[]);
void DirectNetworkIO(int argc, char* argv[]);
void ListDriver();
void ListCallback();
void RemoveCallback(int argc, char* argv[]);


void DumpBin(const unsigned char* buf, int size);

int main(int argc, char* argv[])
{
	int ret = 0;
	if(argc == 1 )
	{
		ShowUsage();
		return 0;
	}

	printf("*** RaspConsole - Tools for WinRasp ***\n");

	ret = OpenRaspDriver();
	if(ret != 0 )
	{
		printf("OpenRaspDriver failed. err:%d\n", ret);
		return ret;
	}

	printf("OpenRaspDriver TEST OK.\n");

	//File Security
	if(_stricmp(argv[1], "/list_file_handle") == 0 )
	{
		ListFileHandle(argc, argv);
	}
	else if(_stricmp(argv[1], "/close_file_handle") == 0 )
	{
		CloseFileHandle(argc, argv);
	}
	else if(_stricmp(argv[1], "/add_protected_dir") == 0 )
	{
		AddProtectedDir(argc, argv);
	}
	else if(_stricmp(argv[1], "/list_protected_dir") == 0 )
	{
		ListProtectedDir(argc, argv);
	}
	else if(_stricmp(argv[1], "/rm_protected_dir") == 0 )
	{
		RmProtectedDir(argc, argv);
	}
	else if( _stricmp(argv[1], "/add_hide_dir") == 0 )
	{
		AddHideDir(argc, argv);
	}
	else if( _stricmp(argv[1], "/rm_hide_dir") == 0 )
	{
		RmHideDir(argc, argv);
	}
	else if( _stricmp(argv[1], "/list_hide_dir") == 0 )
	{
		ListHideDir(argc, argv);
	}
	else if( _stricmp(argv[1], "/direct_rw_file") == 0 )
	{
		DirectReadWriteFile(argc, argv);
	}

	//Process Security
	else if(_stricmp(argv[1], "/add_proc_create_mon_dir") == 0 )
	{
		AddProcCreationMon(argc, argv);
	}
	else if(_stricmp(argv[1], "/rm_proc_create_mon_dir") == 0 )
	{
		RmProcCreationMon(argc, argv);
	}
	else if(_stricmp(argv[1], "/list_proc_create_mon_dir") == 0 )
	{
		ListProcCreationMon(argc, argv);
	}
	else if(_stricmp(argv[1], "/add_dll_load_mon") == 0)
	{
		AddDllLoadMon(argc, argv);
	}
	else if(_stricmp(argv[1], "/rm_dll_load_mon") == 0)
	{
		RmDllLoadMon(argc, argv);
	}
	else if(_stricmp(argv[1], "/list_dll_load_mon") == 0)
	{
		ListDllLoadMon(argc, argv);
	}
	else if(_stricmp(argv[1], "/inject_dll") == 0  )
	{
		InjectDll(argc, argv);
	}
	else if(_stricmp(argv[1], "/kill_process") == 0  )
	{
		KillProcess(argc, argv);
	}
	else if(_stricmp(argv[1], "/read_proc_mem") == 0  )
	{
		ReadWriteProcessMemory(argc,  argv);
	}
	else if(_stricmp(argv[1], "/write_proc_mem") == 0  )
	{
		ReadWriteProcessMemory(argc,  argv);
	}
	else if(_stricmp(argv[1], "/list_process") == 0)
	{
		ListProcess(argc, argv);
	}
	else if(_stricmp(argv[1], "/add_proc_protect") == 0)
	{
		AddProcProtect(argc, argv);
	}
	else if(_stricmp(argv[1], "/rm_proc_protect") == 0)
	{
		RmProcProtect(argc, argv);
	}
	else if(_stricmp(argv[1], "/list_proc_protect") == 0)
	{
		ListProcProtect(argc, argv);
	}

	//Registry Security
	else if(_stricmp(argv[1], "/add_reg_protect") == 0)
	{
		AddRegProtect(argc, argv);
	}
	else if(_stricmp(argv[1], "/rm_reg_protect") == 0)
	{
		RmRegProtect(argc, argv);
	}
	else if(_stricmp(argv[1], "/list_reg_protect") == 0)
	{
		ListRegProtect(argc, argv);
	}
	else if(_stricmp(argv[1], "/direct_access_key") == 0)
	{
		DirectAccessKey(argc, argv);
	}
	//Misc Security

	else if(_stricmp(argv[1], "/dbg_check") == 0)
	{
		DbgCheck(argc, argv);
	}
	else if(_stricmp(argv[1], "/direct_net_io") == 0 )
	{
		DirectNetworkIO(argc, argv);
	}
	else if(_stricmp(argv[1], "/list_driver") == 0 )
	{
		ListDriver();
	}
	else if (_stricmp(argv[1], "/list_callback") == 0 )
	{
		ListCallback();
	}
	else if(_stricmp(argv[1], "/remove_callback") == 0  )
	{
		RemoveCallback(argc, argv);
	}
	else  
	{
		ShowUsage();
	}

	return ret;
}

void ListFileHandle(int argc, char* argv[])
{
	DWORD dwRet;
	int count = 0;
	int i;
	char* szFileName = argv[2];
	HANDLE_INFO handls[32]={0};
	WCHAR wszFileName[512] = { 0 };

	MultiByteToWideChar(CP_ACP, 0, szFileName, strlen(szFileName),wszFileName, 512);

	dwRet = GetFileHandleInfo(wszFileName, handls, &count);
	if(dwRet != 0 )
	{
		printf("GetFileHandleInfo failed. err:%d\n", dwRet);
		return;
	}

	for( i = 0; i < count; i++)
	{
		printf("pid:%8d, handle:0x%08X\n", handls[i].ProcessId, handls[i].HandleValue);
	}
}

void CloseFileHandle(int argc, char* argv[])
{
	HANDLE_INFO handleInfo;
	DWORD dwRet;

	handleInfo.ProcessId = atoi(argv[2]);
	handleInfo.HandleValue = (PVOID64) strtol(argv[3], NULL, 16);
	dwRet = ForceCloseHandle(&handleInfo);

	printf("ForceCloseHandle %s code:%d, pid:%8d, handle:0x%08X\n",
		dwRet == 0 ? "OK" :"Failed",
		dwRet,
		handleInfo.ProcessId,
		handleInfo.HandleValue
		);
}


BOOL WINAPI AddProtectedDir_HandlerRoutine(DWORD dwCtrlType);
DIR_CONFIG g_dirConfig;

void AddProtectedDir(int argc, char* argv[])
{
	DWORD dwRet = 0;
	int nDispo = atoi(argv[3]);

	if( nDispo == DISP_REPORT_SYNC || nDispo == DISP_BLOCK_REPORT_ASYNC )
	{
		IFileEventServer*   m_FileEventServer = NULL;
		int nTimeOut = 20;//in seconds
		dwRet = SetEventReportAttribute( L"RASP_EVENT_SERVER",nTimeOut);

		dwRet = CreateFileEventServer(&m_FileEventServer, L"RASP_EVENT_SERVER");
		if(dwRet != 0 )
		{
			printf("CreateFileEventServer failed. err:%d\n", dwRet);
			return;
		}
		dwRet = m_FileEventServer->Startup( &EventHandler);
	}

	ZeroMemory(&g_dirConfig, sizeof(DIR_CONFIG));
	g_dirConfig.Dispostion = nDispo;
	srand(time(0));
	g_dirConfig.nRuleId = rand() % 60000; //allocate a random rule id.
	MultiByteToWideChar(CP_ACP, 0, argv[2], strlen(argv[2]), g_dirConfig.wszDir, MAX_PATH);

	dwRet = AddProtectedDir(&g_dirConfig);

	printf("AddProtectedDir %s code:%d, RuleID:%d, wszDir:%s, Dispostion:%d\n",
		dwRet == 0 ? "OK" :"Failed",
		dwRet,
		g_dirConfig.nRuleId,
		argv[2],
		g_dirConfig.Dispostion
		);

	if(dwRet != 0)
	{
		return;
	}

	if( nDispo == DISP_REPORT_SYNC || nDispo == DISP_BLOCK_REPORT_ASYNC )
	{
		SetConsoleCtrlHandler(AddProtectedDir_HandlerRoutine, TRUE);
		HANDLE hEvent = CreateEvent(NULL, TRUE,  FALSE, NULL);
		printf("Wait for event, Press Ctrl+C to interrupt\n");
		WaitForSingleObject(hEvent, INFINITE );
		CloseHandle(hEvent);
	}
}

BOOL WINAPI AddProtectedDir_HandlerRoutine(DWORD dwCtrlType)
{
	DWORD dwRet = RemoveProtectedDir(g_dirConfig.wszDir);

	printf("RemoveProtectedDir %s code:%d, RuleID:%d, wszDir:%ws, Dispostion:%d\n",
		dwRet == 0 ? "OK" :"Failed",
		dwRet,
		g_dirConfig.nRuleId,
		g_dirConfig.wszDir,
		g_dirConfig.Dispostion
		);
	ExitProcess(0);
	return TRUE;
}

void ListProtectedDir(int argc, char* argv[])
{
	int i, count = 0;
	DIR_CONFIG DirConfig;

	GetProtectedDirCount(&count);

	for(i = 0; i < count; i++)
	{
		ZeroMemory(&DirConfig, sizeof(DirConfig));
		if( GetProtectedDir(i, &DirConfig) == ERROR_SUCCESS )
		{
			printf("RuleId:%d, Dispostion:0x%08X, Dir:%ws\n", 
				DirConfig.nRuleId, 
				DirConfig.Dispostion,
				DirConfig.wszDir
				);
		}
	}
}

//RaspConsole /rm_protected_dir dir/file 
void RmProtectedDir(int argc, char* argv[])
{
	DWORD dwRet;
	WCHAR wszFileName[512] = { 0 };

	MultiByteToWideChar(CP_ACP, 0, argv[2], strlen(argv[2]),wszFileName, 512);

	dwRet = RemoveProtectedDir(wszFileName);

	printf("RemoveProtectedDir %s code:%d, wszFileName:%ws\n",
		dwRet == 0 ? "OK" :"Failed",
		dwRet,
		wszFileName
		);
}

//RaspConsole /add_hide_dir  c:\\hide_dir
void AddHideDir(int argc, char* argv[])
{
	DWORD dwRet;
	WCHAR wszFileName[512] = { 0 };
	DIR_CONFIG DirConfig;

	MultiByteToWideChar(CP_ACP, 0, argv[2], strlen(argv[2]),wszFileName, 512);

	ZeroMemory(&DirConfig, sizeof(DirConfig));
	wcscpy(DirConfig.wszDir, wszFileName);
	dwRet = AddHidingDir(&DirConfig);

	printf("AddHidingDir %s code:%d, wszFileName:%ws\n",
		dwRet == 0 ? "OK" :"Failed",
		dwRet,
		wszFileName
		);
}

//RaspConsole /rm_hide_dir  c:\\hide_dir
void RmHideDir(int argc, char* argv[])
{
	DWORD dwRet;
	WCHAR wszFileName[512] = { 0 };

	MultiByteToWideChar(CP_ACP, 0, argv[2], strlen(argv[2]),wszFileName, 512);

	dwRet = RemoveHidingDir(wszFileName);

	printf("RemoveHidingDir %s code:%d, wszFileName:%ws\n",
		dwRet == 0 ? "OK" :"Failed",
		dwRet,
		wszFileName
		);
}

//
//RaspConsole /list_hide_dir 
//
void ListHideDir(int argc, char* argv[])
{
	int i ,count;
	WCHAR wszDir[MAX_PATH];
	DWORD dwRet;

	count = 0;
	GetHidingDirCount(&count);
	for( i= 0; i < count; i++)
	{
		ZeroMemory(wszDir, sizeof(wszDir));
		dwRet = GetHidingDir(i, wszDir, sizeof(wszDir));
		printf("GetHidingDir %s code:%d, wszDir:%ws\n",
			dwRet == 0 ? "OK" :"Failed",
			dwRet,
			wszDir
			);
	}
}

//
//RaspConsole /direct_rw_file c:\\test.txt  
//
void DirectReadWriteFile(int argc, char* argv[])
{
	PVOID64 hFile = NULL;
	WCHAR wszFileName[512] = { 0 };

	MultiByteToWideChar(CP_ACP, 0, argv[2], strlen(argv[2]),wszFileName, 512);

	NTSTATUS Status = DirectCreateFile(&hFile, wszFileName,
		FILE_READ_DATA | FILE_WRITE_DATA,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_SUPERSEDE,
		FILE_NON_DIRECTORY_FILE);

	if (Status == STATUS_SUCCESS)
	{
		printf("DirectCreateFile ok\r\n");
		LARGE_INTEGER off;
		off.QuadPart = 0;
		ULONG writeSize = 0;
		char buffer[64]={0};
		ULONG rwSize= 0;

		Status = DirectWriteFile(hFile, "test", 4, off, &writeSize);
		if (Status == STATUS_SUCCESS)
		{
			printf("DirectWriteFile ok, writeSize=%u\r\n", writeSize);
		}
		else
		{
			printf("DirectWriteFile error:ret=0x%x, path=%S\r\n", Status, wszFileName);
		}

		Status = DirectReadFile(hFile, buffer, 4, off, &rwSize);
		if (Status == STATUS_SUCCESS)
		{
			printf("DirectReadFile ok, rwSize=%u, data:%s\n", rwSize, buffer);
		}
		else
		{
			printf("DirectReadFile error:ret=0x%x, path=%S\n", Status, wszFileName);
		}
		DirectCloseHandle(hFile);

	}
	else
		printf("DirectCreateFile error:ret=0x%x, path=%S\r\n", Status, wszFileName);

}

BOOL WINAPI AddProcessCreationMonDir_HandlerRoutine(DWORD dwCtrlType);

//
//RaspConsole /add_proc_create_mon_dir  c:\\testexe\\*  dispo
//
void AddProcCreationMon(int argc, char* argv[])
{
	DWORD dwRet = 0;
	int nDispo = atoi(argv[3]);

	if( nDispo == DISP_REPORT_SYNC || nDispo == DISP_BLOCK_REPORT_ASYNC )
	{
		IFileEventServer*   m_FileEventServer = NULL;
		int nTimeOut = 20;//in seconds
		dwRet = SetEventReportAttribute( L"RASP_EVENT_SERVER",nTimeOut);

		dwRet = CreateFileEventServer(&m_FileEventServer, L"RASP_EVENT_SERVER");
		if(dwRet != 0 )
		{
			printf("CreateFileEventServer failed. err:%d\n", dwRet);
			return;
		}
		dwRet = m_FileEventServer->Startup( &EventHandler);
	}

	ZeroMemory(&g_dirConfig, sizeof(DIR_CONFIG));
	g_dirConfig.Dispostion = nDispo;
	srand(time(0));
	g_dirConfig.nRuleId = rand() % 60000; //allocate a random rule id.
	MultiByteToWideChar(CP_ACP, 0, argv[2], strlen(argv[2]), g_dirConfig.wszDir, MAX_PATH);

	dwRet = AddProcessCreationMonDir(&g_dirConfig);

	printf("AddProcessCreationMonDir %s code:%d, RuleID:%d, wszDir:%ws, Dispostion:%d\n",
		dwRet == 0 ? "OK" :"Failed",
		dwRet,
		g_dirConfig.nRuleId,
		g_dirConfig.wszDir,
		g_dirConfig.Dispostion
		);

	if(dwRet != 0)
	{
		return;
	}

	if( nDispo == DISP_REPORT_SYNC || nDispo == DISP_BLOCK_REPORT_ASYNC )
	{
		SetConsoleCtrlHandler(AddProcessCreationMonDir_HandlerRoutine, TRUE);
		HANDLE hEvent = CreateEvent(NULL, TRUE,  FALSE, NULL);
		printf("Wait for event, Press Ctrl+C to interrupt\n");
		WaitForSingleObject(hEvent, INFINITE );
		CloseHandle(hEvent);
	}
}

BOOL WINAPI AddProcessCreationMonDir_HandlerRoutine(DWORD dwCtrlType)
{
	DWORD dwRet = RemoveProcessCreationMonDir(g_dirConfig.wszDir);

	printf("RemoveProcessCreationMonDir %s code:%d, RuleID:%d, wszDir:%ws, Dispostion:%d\n",
		dwRet == 0 ? "OK" :"Failed",
		dwRet,
		g_dirConfig.nRuleId,
		g_dirConfig.wszDir,
		g_dirConfig.Dispostion
		);
	ExitProcess(0);
	return TRUE;
}

//RaspConsole /rm_proc_create_mon_dir c:\testexe\*
void RmProcCreationMon(int argc, char* argv[])
{
	DWORD dwRet;
	WCHAR wszFileName[512] = { 0 };

	MultiByteToWideChar(CP_ACP, 0, argv[2], strlen(argv[2]),wszFileName, 512);

	dwRet = RemoveProcessCreationMonDir(wszFileName);

	printf("RemoveProcessCreationMonDir %s code:%d, wszFileName:%ws\n",
		dwRet == 0 ? "OK" :"Failed",
		dwRet,
		wszFileName
		);
}

void ListProcCreationMon(int argc, char* argv[])
{
	int i, count = 0;
	DIR_CONFIG DirConfig;
	DWORD dwRet;

	GetProcessCreationMonDirCount(&count);

	for(i = 0; i < count; i++)
	{
		ZeroMemory(&DirConfig, sizeof(DIR_CONFIG));
		dwRet = GetProcessCreationMonDir(i, &DirConfig);

		if( dwRet == ERROR_SUCCESS )
		{
			printf("nRuleId:%d, Disposition:%d, wszDir:%ws\n",
				(INT)DirConfig.nRuleId, 
				(INT)DirConfig.Dispostion,
				DirConfig.wszDir
				);
		}
	}
}

DIR_CONFIG g_DllLoadMonDirConfig[2];


BOOL WINAPI AddProcessDllLoadMonDir_HandlerRoutine(DWORD dwCtrlType)
{
	DWORD dwRet = RemoveDllLoadMonDir(g_DllLoadMonDirConfig[0].wszDir);

	printf("RemoveDllLoadMonDir %s code:%d, RuleID:%d,  Dispostion:%d, wszDir:%ws\n",
		dwRet == 0 ? "OK" :"Failed",
		dwRet,
		g_DllLoadMonDirConfig[0].nRuleId,
		g_DllLoadMonDirConfig[0].Dispostion,
		g_DllLoadMonDirConfig[0].wszDir
		);
	ExitProcess(0);
	return TRUE;
}

void AddDllLoadMon(int argc, char* argv[])
{
	DWORD dwRet = 0;
	int nDispo = atoi(argv[4]);
	WCHAR wszProcPath[MAX_PATH]={0};
	WCHAR wszDllPath[MAX_PATH]={0};

	if( nDispo == DISP_REPORT_SYNC || nDispo == DISP_BLOCK_REPORT_ASYNC )
	{
		IFileEventServer*   m_FileEventServer = NULL;
		int nTimeOut = 20;//in seconds
		dwRet = SetEventReportAttribute( L"RASP_EVENT_SERVER",nTimeOut);

		dwRet = CreateFileEventServer(&m_FileEventServer, L"RASP_EVENT_SERVER");
		if(dwRet != 0 )
		{
			printf("CreateFileEventServer failed. err:%d\n", dwRet);
			return;
		}
		dwRet = m_FileEventServer->Startup( &EventHandler);
	}

	ZeroMemory(&g_DllLoadMonDirConfig, sizeof(DIR_CONFIG)*2);
	
	srand(time(0));

	g_DllLoadMonDirConfig[0].nRuleId = rand() % 60000;
	g_DllLoadMonDirConfig[0].Dispostion = nDispo;

	MultiByteToWideChar(CP_ACP, 0, argv[2], strlen(argv[2]), wszProcPath, MAX_PATH);
	MultiByteToWideChar(CP_ACP, 0, argv[3], strlen(argv[3]), wszDllPath, MAX_PATH);

	wcscpy(g_DllLoadMonDirConfig[0].wszDir, wszProcPath);
	wcscpy(g_DllLoadMonDirConfig[1].wszDir, wszDllPath);

	dwRet = AddDllLoadMonDir(g_DllLoadMonDirConfig);

	printf("AddDllLoadMonDir %s code:%d, RuleID:%d,  Dispostion:%d, wszDir:%ws, wszDllPath:%ws\n",
		dwRet == 0 ? "OK" :"Failed",
		dwRet,
		g_DllLoadMonDirConfig[0].nRuleId,
		g_DllLoadMonDirConfig[0].Dispostion,
		g_DllLoadMonDirConfig[0].wszDir,
		g_DllLoadMonDirConfig[1].wszDir
		);

	if(dwRet != 0)
	{
		return;
	}

	if( nDispo == DISP_REPORT_SYNC || nDispo == DISP_BLOCK_REPORT_ASYNC )
	{
		SetConsoleCtrlHandler(AddProcessDllLoadMonDir_HandlerRoutine, TRUE);
		HANDLE hEvent = CreateEvent(NULL, TRUE,  FALSE, NULL);
		printf("Wait for event, Press Ctrl+C to interrupt\n");
		WaitForSingleObject(hEvent, INFINITE );
		CloseHandle(hEvent);
	}
}

void RmDllLoadMon(int argc, char* argv[])
{
	DWORD dwRet;
	WCHAR wszFileName[512] = { 0 };

	MultiByteToWideChar(CP_ACP, 0, argv[2], strlen(argv[2]),wszFileName, 512);

	dwRet = RemoveDllLoadMonDir(wszFileName);

	printf("RemoveDllLoadMonDir %s code:%d, wszFileName:%ws\n",
		dwRet == 0 ? "OK" :"Failed",
		dwRet,
		wszFileName
		);
}

void ListDllLoadMon(int argc, char* argv[])
{
	int i, count = 0;
	DIR_CONFIG DirConfig[2];

	GetDllLoadMonDirCount(&count);

	for(i = 0; i < count; i++)
	{
		ZeroMemory(&DirConfig, sizeof(DirConfig));
		if( GetDllLoadMonDir(i, DirConfig) == ERROR_SUCCESS )
		{
			printf("nRuleId:%d, Disposition:%d, wszExePath:%ws, wszDllPath:%ws\n",
				DirConfig[0].nRuleId, 
				DirConfig[0].Dispostion,
				DirConfig[0].wszDir,
				DirConfig[1].wszDir
				);
		}
	}
}

void InjectDll(int argc, char* argv[])
{
	WCHAR dllX86[512] = { 0 };
	WCHAR dllX64[512] = { 0 };
	DWORD pid = atoi(argv[2]);
	DWORD dwRet;

	if (pid == 0)
	{
		printf("invalid pid");
		return ;
	}

	MultiByteToWideChar(CP_ACP, 0, argv[3], strlen(argv[3]), dllX86, 512);
	MultiByteToWideChar(CP_ACP, 0, argv[4], strlen(argv[4]), dllX64, 512);

	INJECT_DLL_REQUEST  injectDll;

	injectDll.nProcessID = pid;
	injectDll.wszDllPathName32 = dllX86;
	injectDll.wszDllPathName64 = dllX64;

	dwRet = DriverInjectDll(&injectDll);

	printf("DriverInjectDll dwRet:%d, pid=%u, x86dll=%S, x64dll=%S\r\n", 
		dwRet,pid,  dllX86, dllX64
		);
}

void KillProcess(int argc, char* argv[])
{
	DWORD pid = atoi(argv[2]);
	DWORD Flag = atoi(argv[3]);
	DWORD dwRet;

	if (pid == 0)
	{
		printf("invalid pid");
		return ;
	}

	KILL_PROC killProc;

	killProc.nPID = pid;
	killProc.Flags = Flag;
	dwRet = KillProcess(&killProc);

	printf("KillProcess dwRet:%d, pid:%u, Flag:%X\n", dwRet,pid, Flag);
}

//EXE read_proc_mem PID address len
void ReadWriteProcessMemory(int argc, char* argv[])
{
	char bRead;
	DWORD pid = atoi(argv[2]);
	PVOID64 address = 0;
	DWORD len = atoi(argv[4]);
	char* buf = new char[len];
	DWORD dwRet;

	ZeroMemory(buf, len);
	if(_stricmp(argv[1], "read_proc_mem") == 0 )
	{
		bRead = TRUE;
	}
	else if(_stricmp(argv[1], "write_proc_mem") == 0 )
	{
		bRead = FALSE;
	}
	sscanf_s(argv[3],"%I64X", &address);

	if(bRead)
	{
		dwRet = DirectReadProcessMemory(pid, address, len, buf);
		printf("DirectReadProcessMemory! dwRet:%d, address:0x%I64X, len:%d\n", pid, address, len);
		DumpBin((unsigned char*)buf, len);
	}
	else
	{
		dwRet = DirectWriteProcessMemory(pid, address, len, buf);
		printf("DirectWriteProcessMemory! dwRet:%d, address:0x%I64X, len:%d\n", pid, address, len);
		DumpBin((unsigned char*)buf, len);
	}

	delete[] buf;
}

void ListProcess(int argc, char* argv[])
{
	PROC_INFO ProcInfo[400]={0};
	int size = 400;
	DWORD dwRet;
	int i;

	dwRet = GetProcessInfoArrary(ProcInfo, &size);
	if( dwRet == 0 )
	{
		for( i = 0; i < size ; i++)
		{
			printf("index:%d, pid:%d, Name:%ws\n", i, ProcInfo[i].nPID, ProcInfo[i].wszImageName);
		}
	}
}

PID_PROTECT g_pidProtect;
BOOL WINAPI AddProcessProtect_HandlerRoutine(DWORD dwCtrlType);

void AddProcProtect(int argc, char* argv[])
{
	DWORD dwRet;

	srand(time(0));

	g_pidProtect.nRuleID =  rand() % 60000;
	g_pidProtect.nPID =  atoi(argv[2]);
	g_pidProtect.Disposition = atoi(argv[3]);

	dwRet = AddProcessProtect(&g_pidProtect);

	if( g_pidProtect.Disposition == DISP_REPORT_SYNC || g_pidProtect.Disposition == DISP_BLOCK_REPORT_ASYNC )
	{
		IFileEventServer*   m_FileEventServer = NULL;
		int nTimeOut = 20;//in seconds
		dwRet = SetEventReportAttribute( L"RASP_EVENT_SERVER",nTimeOut);

		dwRet = CreateFileEventServer(&m_FileEventServer, L"RASP_EVENT_SERVER");
		if(dwRet != 0 )
		{
			printf("CreateFileEventServer failed. err:%d\n", dwRet);
			return;
		}
		dwRet = m_FileEventServer->Startup( &EventHandler);
	}


	dwRet = AddProcessProtect(&g_pidProtect);

	printf("AddProcessProtect %s code:%d, RuleID:%d, PID:%d, Dispostion:%d\n",
		dwRet == 0 ? "OK" :"Failed",
		dwRet,
		g_pidProtect.nRuleID,
		g_pidProtect.nPID,
		g_pidProtect.Disposition
		);

	if(dwRet != 0)
	{
		return;
	}

	if( g_pidProtect.Disposition == DISP_REPORT_SYNC || g_pidProtect.Disposition == DISP_BLOCK_REPORT_ASYNC )
	{
		SetConsoleCtrlHandler(AddProcessProtect_HandlerRoutine, TRUE);
		HANDLE hEvent = CreateEvent(NULL, TRUE,  FALSE, NULL);
		printf("Wait for event, Press Ctrl+C to interrupt\n");
		WaitForSingleObject(hEvent, INFINITE );
		CloseHandle(hEvent);
	}
	
}


BOOL WINAPI AddProcessProtect_HandlerRoutine(DWORD dwCtrlType)
{
	DWORD dwRet = RemoveProcessProtect(g_pidProtect.nPID);

	printf("RemoveProcessProtect %s code:%d, RuleID:%d, PID:%d, Dispostion:%d\n",
		dwRet == 0 ? "OK" :"Failed",
		dwRet,
		g_pidProtect.nRuleID,
		g_pidProtect.nPID,
		g_pidProtect.Disposition
		);

	ExitProcess(0);
	return TRUE;
}

void RmProcProtect(int argc, char* argv[])
{
	DWORD dwRet = RemoveProcessProtect( atoi(argv[2]));

	printf("RemoveProcessProtect %s code:%d,  PID:%d\n",
		dwRet == 0 ? "OK" :"Failed",
		dwRet,
		g_pidProtect.nPID
		);
}

void ListProcProtect(int argc, char* argv[])
{
	int i, count = 0;
	PID_PROTECT pidProtect;

	GetProcessProtectCount(&count);

	for(i = 0; i < count; i++)
	{
		if( GetProcessProtectItem(i, &pidProtect) == ERROR_SUCCESS )
		{
			printf("GetProcessProtectItem OK, index:%d, RuleID:%d, PID:%d, Dispostion:%d\n",
				i,
				pidProtect.nRuleID,
				pidProtect.nPID,
				pidProtect.Disposition
				);
		}
	}
}


BOOL WINAPI AddRegProtect_HandlerRoutine(DWORD dwCtrlType);

REG_KEY_CONFIG KeyConfig;

void AddRegProtect(int argc, char* argv[])
{
	DWORD dwRet;

	srand(time(0));
	
	KeyConfig.nRuleId =  rand() % 60000;
	KeyConfig.Disposition =  atoi(argv[2]);
	if(atoi(argv[3]))
	{
		KeyConfig.Flags = REG_KEY_HIDE;
	}

	wcscpy_s(KeyConfig.wszRegKey, MAX_PATH, L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\test");


	if( KeyConfig.Disposition == DISP_REPORT_SYNC || KeyConfig.Disposition == DISP_BLOCK_REPORT_ASYNC )
	{
		IFileEventServer*   m_FileEventServer = NULL;
		int nTimeOut = 20;//in seconds
		dwRet = SetEventReportAttribute( L"RASP_EVENT_SERVER",nTimeOut);

		dwRet = CreateFileEventServer(&m_FileEventServer, L"RASP_EVENT_SERVER");
		if(dwRet != 0 )
		{
			printf("CreateFileEventServer failed. err:%d\n", dwRet);
			return;
		}
		dwRet = m_FileEventServer->Startup( &EventHandler);
	}


	dwRet = AddProtectedRegKey(&KeyConfig);

	printf("AddProtectedRegKey %s code:%d, RuleID:%d, Dispostion:%d, key:%ws\n",
		dwRet == 0 ? "OK" :"Failed",
		dwRet,
		KeyConfig.nRuleId,
		KeyConfig.Disposition,
		KeyConfig.wszRegKey
		);

	if(dwRet != 0)
	{
		return;
	}

	if( KeyConfig.Disposition == DISP_REPORT_SYNC || KeyConfig.Disposition == DISP_BLOCK_REPORT_ASYNC )
	{
		SetConsoleCtrlHandler(AddRegProtect_HandlerRoutine, TRUE);
		HANDLE hEvent = CreateEvent(NULL, TRUE,  FALSE, NULL);
		printf("Wait for event, Press Ctrl+C to interrupt\n");
		WaitForSingleObject(hEvent, INFINITE );
		CloseHandle(hEvent);
	}
}

BOOL WINAPI AddRegProtect_HandlerRoutine(DWORD dwCtrlType)
{
	DWORD dwRet = RemoveProtectedRegKey(KeyConfig.wszRegKey);

	printf("RemoveProtectedRegKey %s code:%d, RuleID:%d, wszRegKey:%ws, Dispostion:%d\n",
		dwRet == 0 ? "OK" :"Failed",
		dwRet,
		KeyConfig.nRuleId,
		KeyConfig.wszRegKey,
		KeyConfig.Disposition
		);

	ExitProcess(0);
	return TRUE;
}


void RmRegProtect(int argc, char* argv[])
{
	DWORD dwRet = RemoveProtectedRegKey(L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\test");

	printf("RemoveProtectedRegKey %s code:%d, RuleID:%d, wszRegKey:%ws, Dispostion:%d\n",
		dwRet == 0 ? "OK" :"Failed",
		dwRet,
		KeyConfig.nRuleId,
		KeyConfig.wszRegKey,
		KeyConfig.Disposition
		);
}

void ListRegProtect(int argc, char* argv[])
{
	int i, count;
	REG_KEY_CONFIG RegKeyConfig;

	GetProtectedRegKeyCount(&count);

	for(i = 0; i < count; i++)
	{
		ZeroMemory(&RegKeyConfig, sizeof(REG_KEY_CONFIG));
		if( GetProtectedRegKey(i, &RegKeyConfig) == ERROR_SUCCESS )
		{
			printf("GetProtectedRegKey OK. index:%d, nRuleId:%d, Dispo:%d, Key:%ws\n",
				i, 
				RegKeyConfig.nRuleId,
				RegKeyConfig.Disposition,
				RegKeyConfig.wszRegKey
				);
		}
	}
}

void DirectAccessKey(int argc, char* argv[])
{
	printf("please check the sample code in the source file.\n");
	
	//
	//Sample code
	//

	/*
	CHAR Buffer[1024];
	PKEY_VALUE_FULL_INFORMATION pInfo = (PKEY_VALUE_FULL_INFORMATION) Buffer;
	ULONG ResultLength;

	NTSTATUS Status;

	Status = DirectQueryValueKey( L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\services\\test",
		L"Start", 
		KeyValueFullInformation,
		(PKEY_VALUE_FULL_INFORMATION)Buffer,
		1024,
		&ResultLength
		);

	ULONG Start = 4;
	Status = DirectSetValueKey(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\services\\test",
		L"Start",
		REG_DWORD,
		&Start, 
		sizeof(Start));
	*/
}

void DbgCheck(int argc, char* argv[])
{
	int pid =  atoi(argv[2]);

	DWORD dwRet = IsProcessBeingDebugged(pid);
	printf("GetProtectedRegKey dwRet:%d %s, PID:%d\n",dwRet, dwRet == 0 ? "YES":"NO", pid);
}

void DirectNetworkIO(int argc, char* argv[])
{
	printf("please check the sample code in the source file.\n");

	//Sample code
	/*
	CHAR sendBuffer[]="1test";
	char recvBuffer[1024];

	int nRecvSize = 1024;
	DWORD dwRet;


	dwRet = TcpSendRecv("192.168.1.102", 6000, sendBuffer, strlen(sendBuffer), recvBuffer, &nRecvSize);
	*/
}

void ListDriver()
{
	DWORD    dwRet;
	HDRVLIST hDrvList = NULL;
	PDRV_MOUDLE_ENTRY drvModule =(PDRV_MOUDLE_ENTRY) malloc(4096);
	int i = 0;

	if( drvModule == NULL )
	{
		goto EXIT;
	}

	dwRet = DrvListCreate(&hDrvList);
	if( dwRet != ERROR_SUCCESS )
	{
		goto EXIT;
	}

	ZeroMemory(drvModule, 4096);
	dwRet = DrvListFirst(hDrvList,drvModule, 4096);
	if( dwRet != ERROR_SUCCESS )
	{
		goto EXIT;
	}
	i+=1;
	WCHAR wszBuffer[256] = {0};

	ZeroMemory(wszBuffer, sizeof(wszBuffer));
	RtlCopyMemory(wszBuffer, drvModule->PathName, drvModule->PathNameSize);

	printf("i:%d, Base:0x%I64X, Entry:0x%I64X, Size:0x%08X, Name:%ws\n",
		i++,
		drvModule->DllBase,
		drvModule->EntryPoint,
		drvModule->SizeOfImage,
		wszBuffer
		);

	for(; ;)
	{
		ZeroMemory(drvModule, 4096);
		dwRet = DrvListNext(hDrvList,drvModule, 4096);
		if(dwRet != ERROR_SUCCESS)
		{
			break;
		}
		ZeroMemory(wszBuffer, sizeof(wszBuffer));
		RtlCopyMemory(wszBuffer, drvModule->PathName, drvModule->PathNameSize);

		printf("i:%d, Base:0x%I64X, Entry:0x%I64X, Size:0x%08X, Name:%ws\n",
			i++,
			drvModule->DllBase,
			drvModule->EntryPoint,
			drvModule->SizeOfImage,
			wszBuffer
			);
	}

EXIT:
	if( hDrvList )
	{
		DrvListClose(hDrvList);
	}

	if( drvModule )
	{
		free(drvModule);
	}
}

void PrintCallackItem(WCHAR* wszType, PVOID64 address)
{
	if( _wcsicmp(wszType, L"Registry") == 0 )
	{
		PREG_CALLBACK RegCallback = (PREG_CALLBACK)address;

		printf("Type:Registry,           Function:0x%I64X, Cookie:0x%I64X\n", 
			RegCallback->Function,
			RegCallback->Cookie.QuadPart
			);
	}
	else if( _wcsicmp(wszType, L"ObCallback_Process") == 0 )
	{
		POB_CALLBACK ObCallback = (POB_CALLBACK)address;

		printf("Type:ObCallback_Process, Function:0x%I64X, Handle:0x%I64X\n", 
			ObCallback->Function,
			ObCallback->Handle
			);
	}
	else if( _wcsicmp(wszType, L"Registry") == 0 )
	{
		printf("Type:LoadImage,          Function:0x%I64X\n",address);
	}
	else if( _wcsicmp(wszType, L"CreateProcess") == 0 )
	{
		printf("Type:CreateProcess,      Function:0x%I64X\n",address);
	}
	else if( _wcsicmp(wszType, L"LoadImage") == 0 )
	{
		printf("Type:LoadImage,          Function:0x%I64X\n",address);
	}
}

void ListCallback( )
{
	DWORD dwRet;
	INT size = 64;
	int i;
	PVOID64  NotifyRoutine[64]={0};

	dwRet = GetLoadImageCallbackFunctions(NotifyRoutine, &size);
	if( dwRet == ERROR_SUCCESS )
	{
		for(i = 0; i < size; i++)
		{
			PrintCallackItem(L"LoadImage", NotifyRoutine[i]);
		}
	}

	size = 64;
	ZeroMemory(NotifyRoutine, sizeof(NotifyRoutine));
	dwRet = GetCreateProcessCallbackFunctions(NotifyRoutine, &size);
	if( dwRet == ERROR_SUCCESS )
	{
		for(i = 0; i < size; i++)
		{
			PrintCallackItem(L"CreateProcess", NotifyRoutine[i]);
		}
	}

	REG_CALLBACK RegCallbacks[100];
	size = 100;
	ZeroMemory(RegCallbacks, sizeof(RegCallbacks));
	dwRet = GetRegCallbackFunctions(RegCallbacks, &size);

	if( dwRet == ERROR_SUCCESS )
	{
		for(i = 0; i < size; i++)
		{
			PrintCallackItem(L"Registry", &RegCallbacks[i]);
		}
	}


	OB_CALLBACK ObCallbacks[100];
	size = 100;
	ZeroMemory(ObCallbacks, sizeof(ObCallbacks));
	dwRet = GetObCallbackFunctions(ObCallbacks, &size);

	if( dwRet == ERROR_SUCCESS )
	{
		for(i = 0; i < size; i++)
		{
			PrintCallackItem(L"ObCallback_Process", &ObCallbacks[i]);
		}
	}
}

//RaspConsole /remove_callback type addr cookie/handle
void RemoveCallback(int argc, char* argv[])
{
	char* szType = argv[2];
	DWORD dwRet;
	PVOID64 fun;

	if(_stricmp(szType, "LoadImage") == 0 )
	{
		sscanf_s(argv[3],"%I64X", &fun);

		dwRet = RemoveLoadImageCallbackFunction(fun);
		printf("RemoveLoadImageCallbackFunction! dwRet:%d, Function:0x%I64x\n", dwRet, fun);
	}
	else if(_stricmp(szType, "CreateProcess") == 0 )
	{
		sscanf_s(argv[3],"%I64X", &fun);

		dwRet = RemoveCreateProcessCallbackFunction(fun);
		printf("RemoveCreateProcessCallbackFunction! dwRet:%d, Function:0x%I64x\n", dwRet, fun);
	}
	else if(_stricmp(szType, "Registry") == 0 )
	{
		REG_CALLBACK regCallback;

		sscanf_s(argv[3],"%I64X", &regCallback.Function);
		sscanf_s(argv[4],"%I64X", &regCallback.Cookie.QuadPart);

		dwRet = RemoveRegCallbackFunction(regCallback.Cookie);
		printf("RemoveRegCallbackFunction! dwRet:%d, Function:0x%I64X, Cookie:0x%I64X\n", 
			dwRet, 
			regCallback.Function,
			regCallback.Cookie.QuadPart
			);
	}
	else if(_stricmp(szType, "ObCallback_Process") == 0 )
	{
		OB_CALLBACK obCallback;

		sscanf_s(argv[3],"%I64X", &obCallback.Function);
		sscanf_s(argv[4],"%I64X", &obCallback.Handle);

		dwRet = RemoveObCallbackFunction(obCallback.Handle);
		printf("RemoveObCallbackFunction! dwRet:%d, Function:0x%I64X, Handle:0x%I64X\n", 
			dwRet, 
			obCallback.Function,
			obCallback.Handle
			);
	}
}

DWORD CEventHandler::OnFileEvent(PFILE_EVENT_PACKET  pFileEventPacket) 
{
	DWORD dwRet = 0;

	switch(pFileEventPacket->dwEventID )
	{
	case EVENT_ID_FILE_MODIFY_DETECTED:
		{
			if(pFileEventPacket->nDisposition == DISP_REPORT_SYNC)
			{
				pFileEventPacket->dwStatusCode = FE_NOT_ALLOWED;// not allow to modify the dir
				//pFileEventPacket->dwStatusCode == FE_SUCCESS//  allow to modify the dir
				printf("File modify detected. RuleID:%d, Action:%ws, Name:%ws\n",
					pFileEventPacket->nRuleId,
					pFileEventPacket->dwStatusCode == FE_NOT_ALLOWED ? L"Denied" :L"Allow",
					pFileEventPacket->FileModify.wszFileName );
			}
			else
			{
				printf("File modify detected. RuleID:%d, Action:%ws, Name:%ws\n",
					pFileEventPacket->nRuleId,
					L"Denied",
					pFileEventPacket->FileModify.wszFileName );
			}
		}
		break;

	case EVENT_ID_PROC_START:
		{
			if(pFileEventPacket->nDisposition == DISP_REPORT_SYNC)
			{
				pFileEventPacket->dwStatusCode = FE_NOT_ALLOWED;// not allow to start the process.
				//pFileEventPacket->dwStatusCode == FE_SUCCESS//  allow to start the process.

				printf("Proc Start detected. RuleID:%d, PID:%d, Parent PID:%d, Action:%ws, Name:%ws\n",
					pFileEventPacket->nRuleId,
					pFileEventPacket->ProcStart.dwPID,
					pFileEventPacket->ProcStart.dwParentID,
					pFileEventPacket->dwStatusCode == FE_NOT_ALLOWED ? L"Denied" :L"Allow",
					pFileEventPacket->ProcStart.wszFileName );
			}
			else
			{
				printf("Proc Start detected. RuleID:%d, PID:%d, Parent PID:%d, Action:Denied, Name:%ws\n",
					pFileEventPacket->nRuleId,
					pFileEventPacket->ProcStart.dwPID,
					pFileEventPacket->ProcStart.dwParentID,
					pFileEventPacket->ProcStart.wszFileName );
			}

		}
		break;

	case EVENT_ID_PROC_EXIT:
		{
			printf("PID Exit. dwPID:%d, wszFileName:%ws\n",
				pFileEventPacket->ProcStart.dwPID,
				pFileEventPacket->ProcStart.wszFileName
				);
		}
		break;

	case EVENT_ID_DLL_LOAD:
		{
			if(pFileEventPacket->nDisposition == DISP_REPORT_SYNC)
			{
				pFileEventPacket->dwStatusCode = FE_NOT_ALLOWED;// not allow to start the process.
				//pFileEventPacket->dwStatusCode == FE_SUCCESS//  allow to start the process.

				printf("Dll Load detected. Action:%ws, nRuleID:%d, PID:%d, Proc:%ws, Dll:%ws\n",
					pFileEventPacket->dwStatusCode == FE_NOT_ALLOWED ? L"Denied" :L"Allow",
					pFileEventPacket->nRuleId,
					pFileEventPacket->DllLoad.dwPID,
					pFileEventPacket->DllLoad.wszProcName,
					pFileEventPacket->DllLoad.wszDllName);
			}
			else
			{
				printf( "Dll Load detected. Action:%ws, nRuleID:%d, PID:%d, Proc:%ws, Dll:%ws\n",
					L"Denied",
					pFileEventPacket->nRuleId,
					pFileEventPacket->DllLoad.dwPID,
					pFileEventPacket->DllLoad.wszProcName,
					pFileEventPacket->DllLoad.wszDllName);
			}
		}
		break;

	case EVENT_ID_KEY_MODIFY:
		{
			if(pFileEventPacket->nDisposition == DISP_REPORT_SYNC)
			{
				pFileEventPacket->dwStatusCode = FE_NOT_ALLOWED;// not allow to start the process.
				//pFileEventPacket->dwStatusCode == FE_SUCCESS//  allow to start the process.

				printf("Key modify detected. Action:%ws, nRuleID:%d, PID:%d, Key:%ws\n",
					pFileEventPacket->dwStatusCode == FE_NOT_ALLOWED ? L"Denied" :L"Allow",
					pFileEventPacket->nRuleId,
					pFileEventPacket->KeyModify.dwPID,
					pFileEventPacket->KeyModify.wszFileName 
					);
			}
			else
			{
				printf("Key modify detected. Action:%ws, nRuleID:%d, PID:%d, Key:%ws\n",
					L"Denied",
					pFileEventPacket->nRuleId,
					pFileEventPacket->KeyModify.dwPID,
					pFileEventPacket->KeyModify.wszFileName 
					);
			}
		}
		break;

	case EVENT_ID_PID_ACCESS:
		{
			if(pFileEventPacket->nDisposition == DISP_REPORT_SYNC)
			{
				pFileEventPacket->dwStatusCode = FE_NOT_ALLOWED;// not allow to start the process.
				//pFileEventPacket->dwStatusCode == FE_SUCCESS//  allow to start the process.

				printf("Pid access detected. Action:%ws, nRuleID:%d, PID:%d, TargetPID:%d, DesiredAccess:0x%08X\n",
					pFileEventPacket->dwStatusCode == FE_NOT_ALLOWED ? L"Denied" :L"Allow",
					pFileEventPacket->nRuleId,
					pFileEventPacket->PidAccess.dwPID,
					pFileEventPacket->PidAccess.dwTargetPID,
					pFileEventPacket->PidAccess.DesiredAccess
					);
			}
			else
			{
				printf("Pid access detected. Action:%ws, nRuleID:%d, PID:%d, TargetPID:%d, DesiredAccess:0x%08X\n",
					L"Denied",
					pFileEventPacket->nRuleId,
					pFileEventPacket->PidAccess.dwPID,
					pFileEventPacket->PidAccess.dwTargetPID,
					pFileEventPacket->PidAccess.DesiredAccess
					);
			}
		}
	}
	return dwRet;
}


void DumpBin(const unsigned char* buf, int size)
{
	for (int i = 0; i < size; i++)
	{
		printf("%02x ", buf[i]);
		if (i != 0 && (i+1) % 16 == 0)
			printf("\r\n");
	}
	printf("\r\n");
}
