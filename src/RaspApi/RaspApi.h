#ifndef _RASP_API_H_
#define _RASP_API_H_

#ifdef __cplusplus
extern "C"
{
#endif

typedef PVOID64 HDRVLIST;

typedef short CSHORT;

typedef struct _DRV_MOUDLE_ENTRY {
	PVOID64 DllBase;
	PVOID64 EntryPoint;
	ULONG SizeOfImage;
	ULONG PathNameSize;
	WCHAR PathName[1];
}DRV_MOUDLE_ENTRY,*PDRV_MOUDLE_ENTRY;


/*++
Name:
	OpenRaspDriver

Description:
    This function try to open the rasp driver.

Arguments:
	None

Return Value:
    If the function succeeds, the return value is 0, which mean the driver is running;
	otherwise returns an error code which equal to the return value of call GetLastError 
--*/

DWORD OpenRaspDriver( );


/*++
Name:
	DrvListCreate

Description:
    Create a loaded driver module list snapshot.

Arguments:
	hDrvList - a pointer to receive the handle of driver list.

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD DrvListCreate(HDRVLIST* hDrvList);

/*++
Name:
	DrvListFirst

Description:
    Create the first driver info

Arguments:
	hDrvList - the handle of drive list
	drvModule - receive the drive info

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD DrvListFirst(HDRVLIST  hDrvList,PDRV_MOUDLE_ENTRY drvModule, int nBufSize);

/*++
Name:
	DrvListNext

Description:
    Create the net driver info

Arguments:
	hDrvList - the handle of drive list
	drvModule - receive the drive info

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD DrvListNext(HDRVLIST  hDrvList,PDRV_MOUDLE_ENTRY drvModule, int nBufSize);

/*++
Name:
	DrvListClose

Description:
    Close the   driver list snap shot

Arguments:
	hDrvList - the handle of drive list
	drvModule - receive the drive info

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD DrvListClose(HDRVLIST  hDrvList);

/*++
Name:
	GetLoadImageCallbackFunctions

Description:
    Get the load image callback functions

Arguments:
	fun - the array  to receive the function list
	size - the size of the fun array. If operation succeeded, it is the valid fun pointer count in the fun array.

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD GetLoadImageCallbackFunctions(PVOID64* fun, int* size);


/*++
Name:
	RemoveLoadImageCallbackFunction

Description:
    Remove  a load image callback function

Arguments:
	fun - function pointer

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD RemoveLoadImageCallbackFunction(PVOID64 fun);


DWORD GetCreateProcessCallbackFunctions(PVOID64* fun, int* size);


DWORD RemoveCreateProcessCallbackFunction(PVOID64 fun);

typedef struct _REG_CALLBACK
{
	PVOID64          Function; 
	LARGE_INTEGER  Cookie;    
}REG_CALLBACK,*PREG_CALLBACK;


DWORD GetRegCallbackFunctions(PREG_CALLBACK RegCallback, int* size);

DWORD RemoveRegCallbackFunction(LARGE_INTEGER Cookie);

typedef struct _OB_CALLBACK
{
	PVOID64          Function;
	PVOID64          Handle;     
}OB_CALLBACK,*POB_CALLBACK;


DWORD GetObCallbackFunctions(POB_CALLBACK ObCallbacks, int* size);

DWORD RemoveObCallbackFunction(PVOID64 Handle);

typedef struct _PROC_INFO
{
	INT    nPID;

	WCHAR  wszImageName[64];

}PROC_INFO,*PPROC_INFO;

/*++
Name:GetProcessInfoArrary

Description:
    get process list.

Arguments:
	pProcInfo - receive the list
	size - the size of the list

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD GetProcessInfoArrary(PPROC_INFO pProcInfo, int* size);

#define  KILL_PROC_FLAG_FORCE   0x00000001

typedef struct _KILL_PROC
{
	ULONG64    nPID;

	ULONG64  Flags;
}KILL_PROC,*PKILL_PROC;

/*++
Name:KillProcess

Description:
    Kill Process

Arguments:
	killProc - process info to terminate

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD KillProcess(PKILL_PROC killProc);

typedef struct _HANDLE_INFO
{
	ULONG64   ProcessId;

	PVOID64  HandleValue;

}HANDLE_INFO,*PHANDLE_INFO;


/*++
Name:
	GetFileHandleInfo

Description:
    Retrieve all handle information for the specified target file.

Arguments:
	in wszFileName - specifics the target file name.
	in_out handelInfo - the array to receive the handle info
	in_out size - the array handleInfo space size. If function succeeds, the real opened handle size. 

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD  GetFileHandleInfo(WCHAR* wszFileName, PHANDLE_INFO  handelInfo, INT* size);

/*++
Name:
	GetKeyHandleInfo

Description:
    Retrieve all handle information for the specified target registry key.

Arguments:
	in wszKey - specifics the target registry key.
	in_out handelInfo - the array to receive the handle info
	in_out size - the array handleInfo space size. If function succeeds, the real opened handle size. 

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD  GetKeyHandleInfo(WCHAR* wszKey, PHANDLE_INFO  handelInfo, INT* size);

/*++
Name:
	KillFileHandle

Description:
    Kill the opened file or registry key handle.

Arguments:
	in handleInfo - specifics the process id and file handle value.

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD  ForceCloseHandle(HANDLE_INFO* handleInfo);

typedef struct _INJECT_DLL_REQUEST
{
	ULONG64  nProcessID;
		
	PVOID64  wszDllPathName32;

	PVOID64  wszDllPathName64;
}INJECT_DLL_REQUEST,*PINJECT_DLL_REQUEST;

/*++
Name:
	DriverInjectDll

Description:
    Inject DLL to a process.
	If the target process is 32 bit, the wszDllPathName32 must be valid.
	If the target process is 64 bit, the wszDllPathName64 must be valid.

Arguments:
	in InjectDll - ProcessID and dll path.

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD DriverInjectDll(PINJECT_DLL_REQUEST InjectDll);


#define DISP_BLOCK                  0x00000001
#define DISP_REPORT                 0x00000002
#define DISP_REPORT_SYNC            0x00000002
#define DISP_BLOCK_REPORT_ASYNC     0x00000004

typedef struct _PATH_CONFIG
{
	//
	//Specific the path.
	//Support wild char *
	//
	WCHAR       wszPath[MAX_PATH];
	
	//Field not used
	WCHAR       wszFilter[128]; 
	
	//Field not used
	ULONG64     Flags; 	

	//
	//DISP_BLOCK
	//DISP_REPORT
	//DISP_BLOCK_REPORT_ASYNC
	//
	ULONG64     Dispostion;

	ULONG64     nRuleId;

}PATH_CONFIG,*PPATH_CONFIG;

#define WHITE_ITEM_TYPE_PID          1
#define WHITE_ITEM_TYPE_PROC_NAME    2

typedef struct _WHITE_ITEM
{
	INT         nItemType;

	union
	{
		INT         nPID;

		WCHAR       wszName[128];
	};
}WHITE_ITEM, *PWHITE_ITEM;

/*++
Name:
	AddProtectedPath

Description:
    Add a protected directory config

Arguments:
	in PathConfig - specifics the target dir name.

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD AddProtectedPath(PPATH_CONFIG PathConfig);

/*++
Name:
	RemoveProtectedPath

Description:
    remove a protected directory config

Arguments:
	in wszDir - specifics the target dir name.

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD RemoveProtectedPath(WCHAR* wszPath);

/*++
Name:GetProtectedPathCount

Description:
    get the protected file/dir count

Arguments:
	nCount - receive the protected file/dir count

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD GetProtectedPathCount(INT* nCount);

/*++
Name:GetProtectedPath

Description:
    get the protected file/dir details

Arguments:
	nIndex - the index of item
	DirConfig - receive the protected file/dir 

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD GetProtectedPath(INT nIndex, PATH_CONFIG* DirConfig);

/*++
Name:GetProtectedPathWhiteItemCount

Description:
    get the protected file/dir white item count

Arguments:
	wszPath - receive the protected file/dir path
	count -  receive the white item  count

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD GetProtectedPathWhiteItemCount(WCHAR* wszPath, int* count);

/*++
Name:GetProtectedPathWhiteItem

Description:
    get the protected file/dir white item

Arguments:
	wszPath - receive the protected file/dir path
	nIndex - the index of item
	whiteItem - receive the white item details

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD GetProtectedPathWhiteItem(WCHAR* wszPath, int index, PWHITE_ITEM whiteItem);

/*++
Name:AddProtectedPathWhiteItem

Description:
    add the protected file/dir white item

Arguments:
	wszPath - set the protected file/dir path
	whiteItem - set the white item details

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD AddProtectedPathWhiteItem(WCHAR* wszPath, PWHITE_ITEM whiteItem);

/*++
Name:RemoveProtectedPathWhiteItem

Description:
    remove the protected file/dir white item

Arguments:
	wszPath - set the protected file/dir path
	whiteItem - set the white item details

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD RemoveProtectedPathWhiteItem(WCHAR* wszPath, PWHITE_ITEM whiteItem);

/*++
Name:AddProcessCreationMonDir

Description:
    Add the dir for process creation monitor

Arguments:
	DirConfig - set the monitor  path and disposition.

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD AddProcessCreationMonDir(PPATH_CONFIG DirConfig);


/*++
Name:RemoveProcessCreationMonDir

Description:
    Remove the dir for process creation monitor

Arguments:
	wszDir - set the monitor  path

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD RemoveProcessCreationMonDir(WCHAR* wszDir);

/*++
Name:GetProcessCreationMonDirCount

Description:
    get the count of  process creation monitor directory

Arguments:
	nCount - receive the count

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD GetProcessCreationMonDirCount(INT* nCount);

/*++
Name:GetProcessCreationMonDir

Description:
    get the details of  process creation monitor directory

Arguments:
	nIndex - index of the node. 0 based;
	DirConfig - receive the the monitor  path and disposition.

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD GetProcessCreationMonDir(INT nIndex, PATH_CONFIG* DirConfig);

/*++
Name:AddDllLoadMonDir

Description:
    add a  dll load monitor directory

Arguments:
	DirConfig - set the the monitor  path and disposition.

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD AddDllLoadMonDir(PATH_CONFIG* DirConfigs);

/*++
Name:RemoveDllLoadMonDir

Description:
    remove a  dll load monitor directory

Arguments:
	wszDir - the dll load monitor path

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD RemoveDllLoadMonDir(WCHAR* wszDir);


/*++
Name:GetDllLoadMonDirCount

Description:
    get the  dll load monitor directory count

Arguments:
	nCount - receive the count

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD GetDllLoadMonDirCount(INT* nCount);

/*++
Name:GetDllLoadMonDir

Description:
    get the  dll load monitor directory details

Arguments:
	nIndex - index of the node. 0 based;
	DirConfigs - receive the the monitor  path and disposition.

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD GetDllLoadMonDir(INT nIndex, PATH_CONFIG* DirConfigs);

#define  REG_KEY_HIDE            0x00000002

typedef struct _REG_KEY_CONFIG
{
	WCHAR     wszRegKey[MAX_PATH];

	ULONG     Flags;

	ULONG     Disposition;

	ULONG       nRuleId;

}REG_KEY_CONFIG,*PREG_KEY_CONFIG;

/*++
Name:AddProtectedRegKey

Description:
    Add a protected reg key

Arguments:
	pRegKey - specific the key parameters

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD AddProtectedRegKey(PREG_KEY_CONFIG pRegKey);

/*++
Name:RemoveProtectedRegKey

Description:
    Remove a protected reg key

Arguments:
	wszRegKey - specific the key

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD RemoveProtectedRegKey(WCHAR* wszRegKey);


/*++
Name:GetProtectedRegKeyCount

Description:
    Get Protected Reg Key Count 

Arguments:
	nCount

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD GetProtectedRegKeyCount(INT* nCount);

/*++
Name:GetProtectedRegKey

Description:
    GetProtectedRegKey 

Arguments:
	nIndex - the index of item
	RegKeyConfig - protected reg key details

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD GetProtectedRegKey(INT nIndex, PREG_KEY_CONFIG RegKeyConfig);

/*++
Name:GetProtectedRegKeyWhiteItemCount

Description:
    Get Protected RegKey White Item Count 

Arguments:
	wszRegKey - specifics the protected key
	count - receive the white item count

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD GetProtectedRegKeyWhiteItemCount(WCHAR* wszRegKey, int* count);

/*++
Name:GetProtectedRegKeyWhiteItem

Description:
    Get Protected RegKey White Item 

Arguments:
	wszRegKey - specifics the protected key
	index -  index value. 0 based.
	whiteItem - the white item information

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD GetProtectedRegKeyWhiteItem(WCHAR* wszRegKey, int index, PWHITE_ITEM whiteItem);

/*++
Name:AddProtectedRegKeyWhiteItem

Description:
    Add Protected RegKey White Item 

Arguments:
	wszRegKey - specifics the protected key
	whiteItem - the white item information

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD AddProtectedRegKeyWhiteItem(WCHAR* wszRegKey, PWHITE_ITEM whiteItem);

/*++
Name: RemoveProtectedRegKeyWhiteItem

Description:
    Remove Protected RegKey White Item 

Arguments:
	wszRegKey - specifics the protected key
	whiteItem - the white item information

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD RemoveProtectedRegKeyWhiteItem(WCHAR* wszRegKey, PWHITE_ITEM whiteItem);

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
#define STATUS_NOT_IMPLEMENTED           ((NTSTATUS)0xC0000002L)
#define STATUS_PROFILING_NOT_STARTED     ((NTSTATUS)0xC00000B7L)

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_REMOTE_INSTANCE               0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000

#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FILE_OPEN_REQUIRING_OPLOCK              0x00010000
#define FILE_DISALLOW_EXCLUSIVE                 0x00020000
#endif /* NTDDI_VERSION >= NTDDI_WIN7 */

#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000


#define FILE_VALID_OPTION_FLAGS                 0x00ffffff
#define FILE_VALID_PIPE_OPTION_FLAGS            0x00000032
#define FILE_VALID_MAILSLOT_OPTION_FLAGS        0x00000032
#define FILE_VALID_SET_FLAGS                    0x00000036

#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005


/*++
Name: DirectCreateFile

Description:
    Open file handle in kernel mode.

Arguments:
	please reference the parameter in MSDN of ZwCreateFile

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD 
DirectCreateFile(
	__out PVOID64* FileHandle,
	__in WCHAR* wszFileName,
	__in ACCESS_MASK DesiredAccess,
	__in ULONG FileAttributes,
	__in ULONG ShareAccess,
	__in ULONG CreateDisposition,
	__in ULONG CreateOptions
	);

/*++
Name: DirectReadFile

Description:
    Read file handle in kernel mode.

Arguments:
	please reference the parameter in MSDN of ZwReadFile

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD 
DirectReadFile(
	PVOID64           FileHandle,
	PVOID            Buffer,
	ULONG            Length,
	LARGE_INTEGER    ByteOffset,
	ULONG*           ReadLength
	);

/*++
Name: DirectWriteFile

Description:
    Read file handle in kernel mode.

Arguments:
	please reference the parameter in MSDN of ZwWriteFile

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD 
DirectWriteFile(
	PVOID64           FileHandle,
	PVOID            Buffer,
	ULONG            Length,
	LARGE_INTEGER    ByteOffset,
	ULONG*           WriteLength
	);

/*++
Name: DirectCloseHandle

Description:
    Close file handle

Arguments:
	FileHandle - the file handle

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD 
DirectCloseHandle(
	PVOID64 FileHandle
	);


typedef struct _KEY_VALUE_BASIC_INFORMATION {
	ULONG   TitleIndex;
	ULONG   Type;
	ULONG   NameLength;
	WCHAR   Name[1];            // Variable size
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION {
	ULONG   TitleIndex;
	ULONG   Type;
	ULONG   DataOffset;
	ULONG   DataLength;
	ULONG   NameLength;
	WCHAR   Name[1];            // Variable size
	//          Data[1];            // Variable size data not declared
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
	ULONG   TitleIndex;
	ULONG   Type;
	ULONG   DataLength;
	UCHAR   Data[1];            // Variable size
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 {
	ULONG   Type;
	ULONG   DataLength;
	UCHAR   Data[1];            // Variable size
} KEY_VALUE_PARTIAL_INFORMATION_ALIGN64, *PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	MaxKeyValueInfoClass  // MaxKeyValueInfoClass should always be the last enum
} KEY_VALUE_INFORMATION_CLASS;

/*++
Name: DirectQueryValueKey

Description:
    Query Registry Key

Arguments:
	please reference the parameter in MSDN of ZwOpenKey and ZwReadKey

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD 
DirectQueryValueKey(
	WCHAR* wszKeyPath,
	WCHAR* wszValueName, 
	KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	PVOID KeyValueInformation,
	ULONG Length,
	PULONG ResultLength
	);


/*++
Name: DirectSetValueKey

Description:
    Query Registry Key

Arguments:
	please reference the parameter in MSDN of ZwOpenKey and ZwWwriteKey

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD
DirectSetValueKey(
	WCHAR* wszKeyPath,
	WCHAR* wszValueName,
	ULONG Type,
	PVOID Data,
	ULONG DataSize
	);


/*++
Name: DirectReadProcessMemory

Description:
    Read process memory in kernel mode

Arguments:
	processId - the process id of target process. 0 represents kernel memory space.

Return Value:
    If the function succeeds, the return value is 0, otherwise returns a error code equal to GetLastError
--*/

DWORD
DirectReadProcessMemory(
	ULONG  processId,
	PVOID64  Address,
	ULONG  Length,
	PVOID64  OutputBuffer
	);

/*++
Name: DirectWriteProcessMemory

Description:
    Write process memory in kernel mode

Arguments:
	processId - the process id of target process. 0 represents kernel memory space.

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD
DirectWriteProcessMemory(
	ULONG  processId,
	PVOID64  Address,
	ULONG  Length,
	PVOID64  InputBuffer
	);


typedef struct _PID_PROTECT
{
	ULONG         nRuleID;
	ULONG         nPID;
	ULONG         Disposition;
}PID_PROTECT,*PPID_PROTECT;

/*++
Name: AddProcessProtect

Description:
    Add a process protection

Arguments:
	PidProtect -  PID protect information

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD  AddProcessProtect(PPID_PROTECT PidProtect);

/*++
Name: RemoveProcessProtect

Description:
    remove a process protection

Arguments:
	nPID -  the process id

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD  RemoveProcessProtect(int nPID);

DWORD  GetProcessProtectCount(INT* nCount);

DWORD  GetProcessProtectItem(INT index, PID_PROTECT* PidProtect);


/*++
Name: TcpSendRecv

Description:
    send and receive data in kernel mode

Arguments:
	szIp - server ip address
	port - server port address
	szSendBuffer - send buffer
	nSendSize - buffer size of send buffer
	szRecvBuffer - recv buffer
	nRecvSize - buffer size of recv buffer


Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD  TcpSendRecv(char* szIp, short port, char* szSendBuffer, int nSendSize, char* szRecvBuffer, int* nRecvSize);


/*++
Name: IsProcessBeingDebugged

Description:
    check the process or OS is in debug mode

Arguments:
	nProcessID -  the id of process. 0 represent the OS kernel mode.

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD  IsProcessBeingDebugged(INT nProcessID);


/*++
Name:AddHiddingDir

Description:
    Add a file or dir to hiding list.

Arguments:
	DirConfig - specifics the file path information

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD AddHidingDir(PPATH_CONFIG DirConfig);


/*++
Name:RemoveHiddingDir

Description:
    remove a file/dir from hiding list.

Arguments:
	wszDir - specifics the file path 

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD RemoveHidingDir(WCHAR* wszDir);

/*++
Name:GetHidingDirCount

Description:
    get the hiding file/dir count

Arguments:
	nCount - receive the hiding file/dir count

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD GetHidingDirCount(INT* nCount);

/*++
Name:GetHidingDir

Description:
    get the hiding file/dir details

Arguments:
	nIndex - the index of item
	wszDir - receive the hiding file/dir 
	size - the size of wszDir in bytes

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD GetHidingDir(INT nIndex, WCHAR* wszDir, INT size);


#define MODULE_ID_DIR_PROTECT    1   
#define MODULE_ID_DLL_LOAD_MON   2 
#define MODULE_ID_PROC_MON       3 
#define MODULE_ID_PID_PROTECT    4  
#define MODULE_ID_REG_MON        5 
#define MODULE_ID_HIDING_DIR     6  


/*++
Name:SetEventReportAttribute

Description:
    SetEventReportAttribute

Arguments:
	wszName - set the event server name
	nTimeout - set the io time out

Return Value:
    If the function succeeds, the return value is 0, otherwise returns an error code equal to GetLastError
--*/

DWORD SetEventReportAttribute(WCHAR* wszName, int nTimeout);

#ifdef __cplusplus
}
#endif


#endif
