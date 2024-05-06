# WinRasp
WinRasp is a RASP (Runtime Application Self Protection) solution for Windows. It can help customer to detect and remove the threats while the target application is at runtime. It can be used to protect registry, file, and process object.

## File/Directory Security
### File Unlock
Identify the target file is in using by which process. Provide the interface to close the file handle by force. 
### Directory Protection
Prevent directory or file from data modifying, create new file and delete existing file. Support regular expression filter. User can set a white PID or process name to permit it can access the protected directory. Support receive directory and file modify event. Support Event Hanlder. 
### File/Directory Hiding
Hiding File or Directory from user mode application.
### Direct File Access
Provides a set of function call to support create, read and write file in kernel mode. To direct access file can avoid the user mode apihook module to interfere the real file data and information.
## Process Security
### Process Creation Monitor
Monitor the process creation and exit event in the OS. Support regular expression filter. Support receive the process started and exit event. It can also block the unwanted process creation. Support Event Hanlder. 
### DLL Image Load Monitor
Monitor DLL image load event in the whole operating system. Prevent the suspicious DLL from being load. Support regular expression filter. Support receive and disposition of DLL Image load event.Support Event Hanlder. 
### DLL Injection
Support Inject DLL in kernel mode. Both support dll injection to 32 and 64 bit process. 
### Kill Process
Support kill process in kernel mode. The caller can choose to kill the process normally or by force.
### Process memory Read/Write
Support to read/write process memory in kernel mode. Also support read/write kernel address space memory in kernel mode.
### Process List
Retrive a process list from kernel mode.
### Process Object Protection
Capture the process object access event, filter and prevent the write request to the target process object. Support receive the event handler processing. Support Event Hanlder .
## Registry Security
### Registry Key Protection
Prevent registry key from file data modifying, create new key and delete existing key. Support regular expression filter. User can set a white PID or process name to permit it   can access the protected registry key. Support receive registry key modify event. Support Event Hanlder.
### Direct Registry Access
Provides a set of function call to support create, read and write registry key in kernel mode. To direct access registry key can avoid the user mode apihook module to interfere the real registry key data and information.
### Registry Key Hiding
Hiding Registry key from user mode application.
## Misc Security
### Debugging state checking
Checking the target application is being debug. Checking OS Kernel is being debug.
### Callback Management
To enumerate the all kernel callback object include process creation callback, DLL image load callback, object access callback and registry operation callback. 
Support remove the callback object in the system. 
### Direct network access
Provides a set of function call to support send and receive data in kernel mode. To direct access network can avoid the user mode apihook module to interfere the real network data and information.
### Loaded kernel module list 
Get a loaded kernel module list, including image name, image base address, entry point, image size.
