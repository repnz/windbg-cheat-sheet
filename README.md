# Kernel Debugging & WinDbg Cheat Sheet

My personal cheat sheet for using WinDbg for kernel debugging. 
This cheat sheet / mini guide will be updated as I do new stuff with WinDbg.

## Kernel Debugging Setup - Vmware, Windbg, VirtualKd 

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

Installing a driver is done by registering it in the registry under the services key. Loading the driver is done by calling the 
NtLoadDriver syscall.

You can either:

- Use [Osr Loader](https://www.osronline.com/article.cfm%5Earticle=157.htm) - This works on win 7-10
- Use builtin SC tool (only win10)
  - Use "sc service <REG_KEY_NAME> type= kernel binPath= <FULL_PATH>" to install the driver 
  - Use "sc <REG_KEY_NAME> start" to load the driver

If there the DriverEntry function returns an error status, it will be returned to "sc" / OsrLoader and the driver will be unloaded without
calling DriverUnload.

To debug your own driver, move it into the virtual machine and install it. Then you are welcome to put a breakpoint on the DriverEntry
by using "bu DriverName!DriverEntry" and then start the driver. If you want to update the code (say you found a bug..) then you can 
stop the driver, recompile, move the files into the VM, and start the driver again. 

## Exploring Modules And Symbols

- lm -> Prints list of loaded modules
- x -> Prints loaded symbols - x <module_name>!<symbol_name> - you can use wildcard on both sides

## Breakpoints

- bp - normal breakpoint
- Breakpoint On DriverEntry - Because the DriverEntry is not loaded yet you cannot use "bp MyDriver!DriverEntry" because this symbol
is not known yet. You can use the "bu" command, this allows to put a breakpoint on the driver entry because those breakpoints are calculated when a driver is loaded.

  
## Analyzing BugChecks

- analyze -v: Shows detailed information about the exception

## Processes

### Listing processes

.tlist - <process_id>:<process_name>

```
0n17636 chrome.exe
0n17744 chrome.exe
0n13076 chrome.exe
0n17148 chrome.exe
0n17516 chrome.exe
0n10776 chrome.exe
0n13176 cmd.exe
```

!process 0 0 

```

PROCESS ffff89062943c080
    SessionId: 1  Cid: 09e0    Peb: 9780215000  ParentCid: 03ac
    DirBase: 6ce90002  ObjectTable: ffffb088f57cad80  HandleCount: 309.
    Image: RuntimeBroker.exe

PROCESS ffff8906297ce080
    SessionId: 1  Cid: 06f8    Peb: 3877758000  ParentCid: 122c
    DirBase: 77800002  ObjectTable: ffffb088f3ac8880  HandleCount:  33.
    Image: WindowsInspector.Controller.exe

```

!process <process_name>

```
kd> !process "WindowsInspector.Controller.exe"
PROCESS ffff8906297ce080
    SessionId: 1  Cid: 06f8    Peb: 3877758000  ParentCid: 122c
    DirBase: 77800002  ObjectTable: ffffb088f3ac8880  HandleCount:  33.
    Image: WindowsInspector.Controller.exe
    VadRoot ffff890629929300 Vads 22 Clone 0 Private 353. Modified 0. Locked 257.
    DeviceMap ffffb088f43ed730
    Token                             ffffb088f6f88060
    ElapsedTime                       00:53:33.825
    UserTime                          00:00:00.000
    KernelTime                        00:00:00.000
    QuotaPoolUsage[PagedPool]         24560
    QuotaPoolUsage[NonPagedPool]      3256
    Working Set Sizes (now,min,max)  (846, 50, 345) (3384KB, 200KB, 1380KB)
    PeakWorkingSetSize                814
    VirtualSize                       4143 Mb
    PeakVirtualSize                   4143 Mb
    PageFaultCount                    849
    MemoryPriority                    BACKGROUND
    BasePriority                      8
    CommitCharge                      540

        THREAD ffff890629432080  Cid 06f8.0c6c  Teb: 0000003877759000 Win32Thread: 0000000000000000 RUNNING on processor 0
```

### Searching for processes

- Use the "!process" command with wildcards: <code>!process "Windows*"</code>

### Moving to the context of a certain process

Moving between process contexts allows placing breakpoints on the process (in user mode), seeing the state of the process, 
searching symbols (because the symbols are loaded)
  
- Get process id : <code>!process 0 0 myproc.exe</code>
- Use procID to switch context: <code>.process /i <process_id></code>
- Continue until the scheduler switches to the desired process context: <code>g</code>


