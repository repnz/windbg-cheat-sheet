# Kernel Debugging & WinDbg Cheat Sheet

My personal cheat sheet for using WinDbg for kernel debugging. 
This cheat sheet / mini guide will be updated as I do new stuff with WinDbg. 

## TODO

- dps
- .reload /f
- kdfiles: drvmap
- kdinit
- disassembly: u, uf, uf /c
- breaking on nt!IopLoadDriver
- !pte
- .formats
- dv
- !thread 
- !handle <handle>
- fix escaping
- error <ntstatus>
- !devobj
- !drvobj
- !object
- !error <win32_error>
- !error <ntstatus> nt
- !devnode 0 1
- ?? (_EPROCESS*)@@masm(nt!PsInitialSystemProcess)
- .reload -user	
- dd, dq, dds, dqs dps
.shell
- .kdfiles -m \??\c:\dev\file.sys c:\hostdir\file.sys << instead of creating a drv map file
- dt poi(nt!PsLoadedModuleList) nt!_LDR_DATA_TABLE_ENTRY -l InLoadOrderLinks.Flink BaseDllName EntryPoint
- dt <list head address> <data structure> -l <flink path> <variables to print> - if you are mistaken in the name of the flink member,
	it will show you only the first element in the list.
- dt nt!_LDR_DATA_TABLE_ENTRY poi(nt!PsLoadedModuleList)
- !poolfind
- !kp, !kc
- .frame <id>
- !ioctldecoder
- %...%\WindowsApps\Microsoft.WinDbg_8wekyb3d8bbwe\WinDbgX.exe -k com:pipe,resets=0,reconnect,port=$(pipename) -c "$$< c:\tools\virtualkd\kdinit"
- CTRL-ALT-K - Enable boot breakpoint - remember to use "Restart Guest" and not simply a reset to keep the same windbg process
- For vmware 15: https://github.com/4d61726b/VirtualKD-Redux
- Use DbgKit for object exploration: http://www.andreybazhan.com/dbgkit.html
- Use "dx" to explore processes, threads, ..
- Use "bp /w" to set smart conditional breakpoints
- Jump to address: r rip = fffff802`64c763f0 
- Change the value of register: r <reg_name> = <reg_value>
- .pagein
- Breakpoint in process by name after DLLs are loaded: 
```
	bp /w "@$curprocess.Name.ToLower() == \"apcinjector.exe\"" nt!NtTestAlert ".reload;bp /t 1 apcinjector!main;g"
```
- Wow64 Debugging: https://docs.microsoft.com/en-us/windows/win32/winprog64/debugging-wow64
- .thread <address> - set register context
	
Books:

- [Windows Internals](https://www.amazon.com/Windows-Internals-Part-architecture-management/dp/0735684189)
- [Windows Kernel Programming](https://www.amazon.com/Windows-Kernel-Programming-Pavel-Yosifovich/dp/1977593372) 

## Disable Windows Defender

- First, turn it off from it's settings: Virus & Threat protection, Real-time protection, turn off
- gpedit.msc is disabled in Windows Home. Download and run [GPEdit Enabler](https://www.itechtics.com/?dl_id=43). Run as admin and it 
requires an internet connection..
- "gpedit.msc" -> Computer Configuration > Administrative Templates > Windows Components > Windows Defender -> Turn Off Windows Defender -> Enabled

## Kernel Debugging Setup - Vmware, Windbg, VirtualKd 

- Install [Windows Debugging Tools](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/)
- use vmware workstation with windows machine installed. 
- Turn on test signing by running "bcdedit /set testsigning on"
- Install [VirtualKd](http://sysprogs.com/legacy/virtualkd/)
  - Put virtualkd in the host in any location you like (I like c:\tools\virtualkd)
  - Run the "target" executable on the guest
  - Run vmmon64.exe / vmmon.exe on the host
  - Configure Windbg Preview this way:
- To enable "DbgPrint" output inside WinDbg, set the "IHVDRIVER" value under "HKLM\SYSTEM\CurrentControlSet\Control\Session
Manager\Debug Print Filter" to DWORD 0xf (This is what I use in my drivers..)
- Configure VM for debugging: (Verify this is the correct debug port in the settings)
  - bcdedit /debug on
  - bcdedit /dbgsettings serial debugport:1 baudrate:115200
- Restart VM. click F8 and choose "Disable Device Signing Enforcement" - that will allow your driver to be load.
- At that point the VM will stuck. It will try to connect to the debugger. Click "Run Debugger" in vmmon to connect
- The debugger will break. 
- Configure WinDbg Symbols: (File->Symbol File Path) <code>cache\*c:\symbols;srv\*https://msdl.microsoft.com/download/symbols</code>
- Click F5 to continue the OS load or do any command you like.
- If the debugger crashes / closes, you can just open a new debugger by clicking the "run debugger" button

## Settings Workspace

Remember to set the workspace by clicking "Save Workspace" after arranging the windows in the way you like, so next time
you open WinDbg it will save this arrangement.


## Initialization Commands

- !sym noisy - this will allow you to understand better why the debugger is stuck:)
- .kdfiles <map file> - this will save you some time by automatically loading the .sys file from the host machine,
	this way you won't need to copy the .sys file. The downside is that it doesn't work with user mode executables,
	so you need to find another method for them (copy pasting or using some kind of share)
- .reload - this will referesh 


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

## General WinDbg

.<command> - run a command. This command is built-into the debugger
!<command> - run an extension. Some extensions arrive by default, like "!process"
Control-Break - Abort Long Running Operation / Debug Break


## Symbols

- .reload to reload symbols of loaded modules. Typically used to load symbols of modules that weren't loaded before
- You may want to use <code>!sym noisy</code> to diagnose symbol loading errors.
- .reload /u - unload symbols. This is used to release the .pdb file of compiled code.
  - Sometimes it's needed to forcefully close handles to PDB files because WinDbg does not close them.
  (using process explorer or process hacker..)

## Exploring Modules And Symbols

- lm (List Modules): Prints list of loaded modules
- x (Examine): Prints loaded symbols - x <module_name>!<symbol_name> - you can use wildcard on both sides
    - Search for modules: x Ori*!

## Source Navigation

- .open -a <symbol> - open the source file with this symbol
	
## Breakpoints

- bp - normal breakpoint
- Breakpoint On DriverEntry - If your driver is not loaded yet, you cannot use "bp MyDriver!DriverEntry" because this symbol
is not known yet. You can use the "bu" command, this allows to put a breakpoint on the driver entry because those breakpoints are calculated when a driver is loaded.
- bl - list breakpoints
- bc * / bc <breakpoint_id> - clear breakpoint
- bp /1 <location> - temporary breakpoint (break 1 time..)
- Breaking on source lines - 
	- Old Method: Find the source line using the status bar and run <code>bp `<sourcefile>:<line>`</code>
	- Sometimes this method is too slow because it cannot know which module you are trying to break on, so it'll
	start downloading symbols of other modules....
	- bp `module_name!file.cpp:206` is better - specifies the name of the module
	- You can also use F9 while placing the cursor on a specific line of code.

- bp /p <EPROCESS address> <breakpoint address> - Break on a specific process - 
	say you want your breakpoint to be on only for a specific process, you can use /p to do it
  
- bp <options> "<command"> - this will run a windbg command after breaking. You can combine multipile commands using ';' for example:

This command will break at line 385 in the ProcessProtector.c file in the ProcessProtector module and it will print 
basic process information, a stack trace, and it will continue on.
Limit the number of times the breakpoint hits to prevent floods:

```
bp /5 `ProcessProtector!ProcessProtector.c:385` "!process -1 0; k; g"
```

Break right before the process entry point in kernel debugging:
```
bp ntdll!LdrpInitializeProcess "bp /1 KERNEL32!BaseThreadInitThunk; g"
```

## Analyzing BugChecks

- <code>analyze -v</code>: Shows detailed information about the exception

## Tracing and Stepping

- (F5) g : (go) continue
- (F10) : step over
- (F11) : step into
- tt - Trace until next return

## Analyzing Program State

- Use memory window to see raw memory
- use "dt" to see observe data structures
- use "??" to evaluate C++ Expressions
- k - stack trace

## Processes

- cid - CID in the windows structures means client id. Most of the time it refers to a ProcessId or a ThreadId but 
sometimes it's both in the same struct. (The struct CLIENT_ID contains UniqueProcessId and UniqueThreadId)

### Current Process

- <code>!process</code> - Dump current process information
```
kd> !process
PROCESS ffff8906293a1080
    SessionId: 1  Cid: 0f3c    Peb: 2063b93000  ParentCid: 122c
    DirBase: 72810002  ObjectTable: ffffb088f57cedc0  HandleCount:  33.
    Image: WindowsInspector.Controller.exe
    VadRoot ffff89062992fac0 Vads 22 Clone 0 Private 354. Modified 0. Locked 0.
    DeviceMap ffffb088f43ed730
    Token                             ffffb088f745d060
    ElapsedTime                       00:00:00.233
    UserTime                          00:00:00.000
    KernelTime                        00:00:00.000
    QuotaPoolUsage[PagedPool]         24560
    QuotaPoolUsage[NonPagedPool]      3256
    Working Set Sizes (now,min,max)  (847, 50, 345) (3388KB, 200KB, 1380KB)
    PeakWorkingSetSize                814
    VirtualSize                       4143 Mb
    PeakVirtualSize                   4143 Mb
    PageFaultCount                    849
    MemoryPriority                    BACKGROUND
    BasePriority                      8
    CommitCharge                      540

        THREAD ffff890628533080  Cid 0f3c.0de0  Teb: 0000002063b94000 Win32Thread: 0000000000000000 RUNNING on processor 0

```


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
/
```

!process 0 0 <process_name>

```
kd> !process 0 0 WindowsInspector.Controller.exe
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

This is how to show a little bit information about the current process:

```
kd> !process -1 0
PROCESS ffff8e8aa3781080
    SessionId: 1  Cid: 0a20    Peb: 62982f2000  ParentCid: 13ec
    DirBase: 6b280002  ObjectTable: ffffc68158f6da00  HandleCount: 486.
    Image: PROCEXP64.exe
```

### Searching for processes

- Use the "!process" command with wildcards: <code>!process "Windows*"</code>

### Moving to the context of a certain process

Moving between process contexts allows placing breakpoints on the process (in user mode), seeing the state of the process, 
searching symbols (because the symbols are loaded)
  
- Get process id : <code>!process 0 0 myproc.exe</code>
- Use procID to switch context: <code>.process /i <EPROCESS address></code>
- Continue until the scheduler switches to the desired process context: <code>g</code>

```
kd> .process /i ffff998ba6f6e280
You need to continue execution (press 'g' <enter>) for the context
to be switched. When the debugger breaks in again, you will be in
the new process context.
kd> g
Invalid parameter passed to C runtime function.
Break instruction exception - code 80000003 (first chance)
rax=0000000000000000 rbx=00000000000000bd rcx=0000000000000007
rdx=0000000000000000 rsi=0000000000000000 rdi=ffff998ba6f6e280
rip=fffff8041be59240 rsp=ffff840136f67a58 rbp=ffff998ba6f6e280
 r8=ffff998ba557b0e8  r9=7ffff8041c60c600 r10=ffff840136f67a90
r11=0000000000000000 r12=0000000000000700 r13=0000000000000000
r14=0000000000000000 r15=fffff8041c1fb200
iopl=0         nv up ei ng nz na pe nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00000282
nt!DbgBreakPointWithStatus:
fffff804`1be59240 cc              int     3
kd> !process
PROCESS ffff998ba6f6e280
    SessionId: 0  Cid: 08e4    Peb: 00684000  ParentCid: 032c
    DirBase: 5e3d0002  ObjectTable: ffffbf8f1ddf8740  HandleCount: 397.
    Image: vmtoolsd.exe
    VadRoot ffff998ba57e97a0 Vads 176 Clone 0 Private 1675. Modified 7635. Locked 0.
    DeviceMap ffffbf8f19413600
    Token                             ffffbf8f1d65c060
    ElapsedTime                       02:23:51.459
    UserTime                          00:00:00.015
    KernelTime                        00:00:00.031
    QuotaPoolUsage[PagedPool]         205840
    QuotaPoolUsage[NonPagedPool]      24888
    Working Set Sizes (now,min,max)  (1560, 50, 345) (6240KB, 200KB, 1380KB)
    PeakWorkingSetSize                5419
    VirtualSize                       4236 Mb
    PeakVirtualSize                   4245 Mb
    PageFaultCount                    22400
    MemoryPriority                    BACKGROUND
    BasePriority                      13
    CommitCharge                      2308
```

That allows us to put breakpoints in the context of this process.

### Debugging User Mode Code From a Kernel Debugging Session

Note that the Timestamp and Checksum of the image must be valid. If the image doesn't have a valid checksum/timestamp, windbg will not
be able to load the symbols. Compiling the executable with vs2019 results in an invalid checksum by default (on debug builds) because
of a feature called "incremental build". It's best to debug the process with release builds or disable incremental builds.

Add the .pdb path of your user mode application into the source file path. Without doing so, WinDbg might get stuck if you use reload /f
while trying to get the symbols (https://stackoverflow.com/questions/38062216/windbg-cant-find-microsoft-symbols).
After that, perform <code>.reload</code> to reload symbols (in the context of this process). Then, "lm" should show the user mode
image that you are debugging.

That will allow to put breakpoints by using symbols from this image. :)

## Debugging RPC 

- Set a breakpoint on RPC method invocation: ```bp RPCRT4!Invoke```

To get the THREAD id, use the following structures:

```C

PTHREAD ThreadPtr = Teb->ReservedForNtRpc ^ 0x0ABABABABDEDEDEDE;

class THREAD { 
	ULONGLONG ThreadId; // 0x10
	RpcCallState* RpcMessage; // 0x20
}


class RpcCallState { 
	RpcConnectionInformation* RpcConnectionInfo; // 0x130
	PPORT_MESSAGE PortMessage; // 0x1b8
}

class RpcConnectionInformation { 
	AlpcConnectionInformation* AlpcConnectionInformation; // 0x38
}

class AlpcConnectionInformation { 
	HANDLE PortHandle; // 0xd0
}
```


## Threads

!thread


## Pool Allocation Breakpoint

This trick is very useful - it can be used to break when a certain tag is used in an allocation.

dd nt!PoolHitTag L1 << read the current pool tag hit
ed nt!PoolHitTag 'eliF' << set the current pool tag hit to 'File'. Each time a file will be allocated, we'll break


## Windbg Scripting

