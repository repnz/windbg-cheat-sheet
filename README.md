# windbg-cheat-sheet

My personal cheat sheet for using WinDbg for kernel debugging. 
This cheat sheet / mini guide will be updated as I do new stuff with WinDbg.

## WinDbg Setup

- Install [Windows Debugging Tools](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/)
- use vmware workstation with windows machine installed. 
- Turn on test signing by running "bcdedit /set testsigning on"
- Install [VirtualKd](http://sysprogs.com/legacy/virtualkd/)
  - Run the "target" executable on the guest
  - Run vmmon64.exe / vmmon.exe on the host
  - Configure windbg.exe path in vmmmon
- To enable "DbgPrint" output inside WinDbg, set the "Debug Print Filter" value under "HKLM\SYSTEM\CurrentControlSet\Control\Session
Manager" to 8. 
- Configure VM for debugging: (Verify this is the correct debug port in the settings)
  - bcdedit /debug on
  - bcdedit /dbgsettings serial debugport:1 baudrate:115200
- Restart VM. click F8 and choose "Disable Device Signing Enforcement" - that will allow your driver to be load.
- At that point the VM will stuck. It will try to connect to the debugger. Click "Run Debugger" in vmmon to connect
- The debugger will break. 
- Configure WinDbg Symbols: (File->Symbol File Path) <code>SRV*c:\Symbols*http://msdl.microsoft.com/download/symbols</code>
  - (Symbols of drivers you develop will be loaded automatically from the same folder of the driver. Copy .pdb to the guest..)
- Click F5 to continue the OS load or do any command you like.
  
## Installing and Loading Device Drivers

You can either:

- Use [Osr Loader](https://www.osronline.com/article.cfm%5Earticle=157.htm) - This works on win 7-10
- Use builtin SC tool (only win10)
  - Use "sc service <REG_KEY_NAME> type= kernel binPath= <FULL_PATH>" to install the driver as a server
  - Use "sc <REG_KEY_NAME> start" to start the service

If there the DriverEntry function returns an error status, it will be returned to "sc" / OsrLoader and the driver will be unloaded without
calling DriverUnload.

