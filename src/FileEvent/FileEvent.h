
#ifndef _FILE_EVENT_H_
#define _FILE_EVNET_H_

#define  FE_SUCCESS                0
#define  FE_START_SERVER_FAILED    1
#define  FE_START_CLIENT_FAILED    2
#define  FE_SEND_DATA_FAILED       3
#define  FE_RECV_DATA_FAILED       4
#define  FE_CREATE_OBJECTF_FAILED  5
#define  FE_NOT_ALLOWED            6
#define  FE_OBJECT_NOT_FOUND       7
#define  FE_NO_PRIVILEGE           8
#define  FE_OP_FAILED              9
#define  FE_CONNECT_PORT_FAILED    10


#pragma pack(1)

#define EVENT_ID_FILE_MODIFY_DETECTED   1
#define EVENT_ID_PROC_START             2
#define EVENT_ID_DLL_LOAD               3
#define EVENT_ID_KEY_MODIFY             4
#define EVENT_ID_PID_ACCESS             5
#define EVENT_ID_PROC_EXIT              6

typedef struct _FILE_EVENT_PACKET
{
	DWORD   dwEventID;
	DWORD   dwStatusCode;
	INT     nRuleId;
	INT     nDisposition;

	union
	{
		struct  
		{ 
			DWORD            dwPID;
			WCHAR            wszFileName[MAX_PATH];

		}FileModify;

		struct  
		{ 
			DWORD            dwPID;
			DWORD            dwParentID; 
			WCHAR            wszFileName[MAX_PATH];
		}ProcStart;

		struct  
		{ 
			DWORD            dwPID;
			WCHAR            wszProcName[MAX_PATH];
			WCHAR            wszDllName[MAX_PATH];
		}DllLoad;

		struct  
		{ 
			DWORD            dwPID;
			WCHAR            wszFileName[MAX_PATH];
		}KeyModify;

		struct  
		{ 
			DWORD            dwPID;
			DWORD            dwTargetPID;
			ACCESS_MASK      DesiredAccess;            
		}PidAccess;
	};

}FILE_EVENT_PACKET,*PFILE_EVENT_PACKET;


#pragma pack( )
class IEventReceiver
{
public:
	~IEventReceiver(){};

	friend class CFileEventServer;
	friend class CFltPortEventServer;
protected:
	virtual DWORD  OnFileEvent(PFILE_EVENT_PACKET  pFileEventPacket) = 0;

};

class IFileEventServer
{
public:
	virtual ~IFileEventServer(    ){};
	virtual DWORD Startup( IEventReceiver*  receiver) = 0;
};

EXTERN_C DWORD  CreateFileEventServer(IFileEventServer**  EventReportServer, WCHAR* wszName);
EXTERN_C DWORD  DeleteFileEventServer(IFileEventServer*  EventReportServer);


class  IFileEventClient
{
public:
	virtual ~IFileEventClient(    ){};
	virtual DWORD   Connect( )= 0;
	virtual DWORD   ReportFileEvent(PFILE_EVENT_PACKET  pFileEventPacket)=0;
	virtual VOID    DisConnect( ) = 0;
};

EXTERN_C DWORD  CreateFileEventClient(IFileEventClient**  FileEventClient);
EXTERN_C DWORD  DeleteFileEventClient(IFileEventClient*   FileEventClient);

#endif

