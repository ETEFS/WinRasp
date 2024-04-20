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
Monitor DLL image load event in the whole operating system. Prevent the suspicious DLL from being load. Support regular expression filter. Support receive and disposition of DLL Image load event.Support Event Hanlder 
