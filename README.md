# Kernel Debugging & WinDbg Cheat Sheet

My personal cheat sheet for using WinDbg for kernel debugging.
This cheat sheet / mini guide will be updated as I do new stuff with WinDbg.

## Kernel Debugging Setup

### Installing the debugging tools

- To use windbg, you have to install the [Windows Debugging Tools](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/).
- I recommend to install Windbg Preview from the Windows Store.

### Setting a VM

Create a VM in Vmware Workstation and install Windows from ISO.

### Disable Windows Defender

When setting up a VM for debugging, it's useful to disable Windows Defender. It's recommended
for a couple of reasons:

- To save resources in the VM
- In case you want to execute malicious software, you don't want defender to prevent it's execution.

Follow these steps:

1. Turn it off from it's settings: Virus & Threat protection, Real-time protection, turn off.
Windows defender will start again in case you reboot, so we need to perform additional steps.
2. We can disable Windows Defender using gpedit.msc. In case your setup is Windows Home, gpedit
is disabled, so you need to download and run [GPEdit Enabler](https://www.itechtics.com/?dl_id=43). Run as admin and make sure you have an internet connection.
3. Run "gpedit.msc" -> Computer Configuration > Administrative Templates > Windows Components > Windows Defender -> Turn Off Windows Defender -> Enabled

### Install VirtualKd

VirtualKd enables you to debug a VM by connecting over a named pipe.

- Download [VirtualKd Redux](https://github.com/4d61726b/VirtualKD-Redux/releases)
- The redux version is a newer version that supports Vmware 15 and has a few bugfixes.
- Extract VirtualKd in the host in any location you like (I like c:\tools\virtualkd)
- Run the "target" executable inside the guest
- Run vmmon64.exe / vmmon.exe on the host (According to the host's architecture)
- Configure the path of Windbg / Windbg Preview in vmmon.
- Make sure "Start Debugger Automatically" is not marked.

### Configure VM for debugging

Run the following commands in an admin command line.

- ```bcdedit /set testsigning on```
- ```bcdedit /debug on```
- ```bcdedit /dbgsettings serial debugport:1 baudrate:115200```

### Connecting to the debugger

After these preparations, we can connect to the debugger by doing these steps:

1. Restart VM. click F8 and choose "Disable Device Signing Enforcement" - that will allow your driver to be load.  
2. At that point the VM will stuck. It will wait for the debugger to connect. Click "Run Debugger" in VMMON to connect

### Configuring Windbg

Now, the debugger should be connected to the VM. We need to setup some configurations in the
debugger:

- Setup symbols server: There are 2 ways to setup symbols path:
  - Environment Variable: This is the easier way I typically use. Set a new environment variable named _NT_SYMBOL_PATH with the
    following value: ```srv*c:\symbols\sym*http://msdl.microsoft.com/download/symbols"```
  - You can also configure the symbols using a debugger command like this: ```.sympath srv*c:\symbols\sym*http://msdl.microsoft.com/download/symbols"```

- If the debugger crashes / closes, you can just open a new debugger by clicking the "run debugger" button
- Arrange the windows / font however you like.

If you use the old Windbg, you should use "Save Workspace" after arranging the windows in the way you like, so next time you open WinDbg it will save this arrangement. It will also restore the symbol path.

### Configuring DbgPrint output

When debugging a driver, It's useful to be able to call [DbgPrintEx](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgprintex) and see messages in the debugger
window. By default, all DbgPrint calls are filtered out. There are 3 ways to enable debugger messages:

1. In windbg, run ```ed nt!Kd_DEFAULT_MASK 0xF```. Kd_DEFAULT_MASK is a global variable inside 
ntoskrnl that is checked before printing messages to the debugger. If you write 0xF to this variable it means you want to get all messages. You will need to do this every time the machine reboots.
2. If you don't want to edit this variable every time the machine reboots, you can configure this
via registry. Run the following command (THIS REQUIRES A REBOOT.)

```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter" /ve /t REG_DWORD /d 15
```

Because we use the "default mask" here you'll start to see every DbgPrint from all drivers so it can become pretty noisy. The other option is to filter by ComponentId. When you call DbgPrintEx, the first argument is a component id. Instead of setting the Kd_DEFAULT_MASK variable, you can
set a component-specific mask. For example:

1. Make sure that when you call DbgPrintEx, you specify the ```DPFLTR_IHVDRIVER_ID``` component.
2. Run the following command, to edit this component's mask:  ```ed nt!Kd_IHVDRIVER_Mask 0xf```
3. You can do it in the registry too, run the following command:

```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter" /v IHVDRIVER /t REG_DWORD /d 15
``` 

## Initialization Commands

- !sym noisy - this will allow you to understand better why the debugger is stuck:)
- .kdfiles <map file> - this will save you some time by automatically loading the .sys file from the host machine,
	this way you won't need to copy the .sys file. The downside is that it doesn't work with user mode executables,
	so you need to find another method for them (copy pasting or using some kind of share)
- .reload - this will referesh the symbols.


## Installing and Loading Device Drivers

Installing a driver is done by registering it in the registry under the services key. Loading the driver is done by calling the 
NtLoadDriver syscall.

You can either:

- Use [Osr Loader](https://www.osronline.com/article.cfm%5Earticle=157.htm) - This works on win 7-10
- Use builtin SC tool (only win10)
  - Use "sc create <REG_KEY_NAME> type= kernel binPath= <FULL_PATH>" to install the driver 
  - Use "sc start <REG_KEY_NAME>" to load the driver

If there the DriverEntry function returns an error status, it will be returned to "sc" / OsrLoader and the driver will be unloaded without
calling DriverUnload.

To debug your own driver, move it into the virtual machine and install it. Then you are welcome to put a breakpoint on the DriverEntry
by using "bu DriverName!DriverEntry" and then start the driver. If you want to update the code (say you found a bug..) then you can 
stop the driver, recompile, move the files into the VM, and start the driver again. 

## General WinDbg

- ```.<command>``` - run a command. This command is built-into the debugger
- ```!<command>``` - run an extension. Some extensions arrive by default, like "!process"
- Control-Break - Abort Long Running Operation / Debug Break

## Exploring Modules And Symbols

Symbols are important when examining modules. When examining a certain module we always need to verify it's symbols
are loaded. We can use the ```lm``` command to see which modules are loaded right now - for each module we can see the
status of the symbols. Basically information about loaded modules is not 'updated' unless ```.reload``` is used before.
use .reload when changing the process context or when you're missing a specific modules in the list.

- ```.reload``` to reload symbols of loaded modules. Typically used to load symbols of modules that weren't loaded before
- You may want to use <code>!sym noisy</code> to diagnose symbol loading errors.
- ```.reload /u``` - unload symbols. This is used to release the .pdb file of compiled code.
  - Sometimes it's needed to forcefully close handles to PDB files because WinDbg does not close them.
  (using process explorer or process hacker..)
- ```lm``` (List Modules): Prints list of loaded modules
- ```x``` (Examine): Prints loaded symbols - ```x <module_name>!<symbol_name>``` - you can use wildcard on both sides
    - Search for a function by name: ```x MyDllName!FunctionName```
    - Search for a function with wildcards ```x MyDllName!*Func``` (ends with Func)

## Source Navigation

- ```.open -a <symbol>``` - open the source file with this symbol
	
## Breakpoints

These are the commands for int3 breakpoints.
- bp - normal breakpoint
- Breakpoint On DriverEntry - If your driver is not loaded yet, you cannot use "bp MyDriver!DriverEntry" because this symbol
is not known yet. You can use the "bu" command, this allows to put a breakpoint on the driver entry because those breakpoints are calculated when a driver is loaded. Another trick to break at the load of drivers (Useful in case you don't have symbols) is breaking
in ntoskrnl.exe where DriverEntry is called. (For example, IopLoadDriver)
- ```bl``` - list breakpoints
- ```bc *``` / ```bc <breakpoint_id>``` - clear breakpoint
- ```bp /1 <location>``` - temporary breakpoint (break 1 time..)
- Breaking on source lines - 
	- You can use F9 while placing the cursor on a specific line of code.
	- Old Method: Find the source line using the status bar and run <code>bp `<sourcefile>:<line>`</code>
	- Sometimes this method is too slow because it cannot know which module you are trying to break on, so it'll
	start downloading symbols of other modules....
	- ```bp `module_name!file.cpp:206` ``` is better - specifies the name of the module

- ```bp /p <EPROCESS address> <breakpoint address>``` - Break on a specific process - 
	say you want your breakpoint to be on only for a specific process, you can use /p to do it
  
- ```bp /t <ETHREAD address> <breakpoint address>``` - same as above, for threads.

- ```bp <options> "<command">``` - this will run a windbg command after breaking. You can combine multipile commands using ';' for example:

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

### Conditional breakpoints

Conditional breakpoints allows you to break if a some DX expression evaluates to true.

## Analyzing BugChecks

- <code>analyze -v</code>: Shows detailed information about the exception

## Tracing and Stepping

- (F5) ```g``` : (go) continue
- (F10) : step over
- (F11) : step into
- ```tt``` - Trace until next return

## Analyzing Program State

- Use memory window to see raw memory
- use "dt" to see observe data structures
- use "dx" to evaluate C++ Expressions
- ```k``` - stack trace
- ```!stacks``` - Inspect the stacks of all of the running threads.
    - ```!stacks 1 <filter_string>``` can be used to filter based on some string in the stack

#### Function arguments

When debugging, it's useful to see the function arguments.

The first 4 arguments are in: rcx, rdx, r8, r9. Also, the caller allocates a shadow space for them, but the caller does not 
store the arguments in this space (it's reserved for the callee)


```
kd> dq /c1 rsp
fffffd08`ee125dc8  fffff801`71222935 --> the return address. only relevant inside the function
fffffd08`ee125dd0  00000025`196fdb50 --> arg1 shadow
fffffd08`ee125dd8  00000000`00000000 --> arg2 shadow
fffffd08`ee125de0  00000000`00000000 --> arg3 shadow
fffffd08`ee125de8  00000000`00000000 --> arg4 shadow
fffffd08`ee125df0  00007fff`00000002 --> arg5
fffffd08`ee125df8  00000025`196fda48 --> arg6
fffffd08`ee125e00  ffffb484`5254e080 --> arg7
fffffd08`ee125e08  fffff801`71449ebf --> ar8
fffffd08`ee125e10  00000000`00000000 -->....
fffffd08`ee125e18  00000000`00000000
```


It's also useful to be able to extract function arguments of previous calls in the callstack. In 32 bit, windbg supports reading function
arguments from the stack using the 'kv' command. Say we are debugging this code:

```C
#include <stdio.h>

typedef struct OBJ {
    int a;
    int b;
    int c;
} OBJ, *POBJ;

int AddValues1(int a, int b)
{
    return a + b;
}

int AddValues2(int a, int b)
{
    return AddValues1(a, b);
}

OBJ AddObjects(POBJ Obj1, POBJ Obj2)
{
    OBJ Obj3 = { 0 };
    Obj3.a = AddValues2(Obj1->a, Obj2->a);
    return Obj3;
}

int main()
{
    OBJ Obj1 = { 0 };
    OBJ Obj2 = { 0 };

    Obj1.a = 1;
    Obj1.b = 2;
    Obj1.c = 3;
    Obj2.a = 4;
    Obj2.b = 5;
    Obj2.c = 6;

    printf("Obj1 Address: 0x%p\n", &Obj1);
    printf("Obj2 Address: 0x%p\n", &Obj2);

    AddObjects(&Obj1, &Obj2);

    return 0;
}
```

The following example will show how to extract the 32 bit arguments:

```
0:000> bp AddValues1
0:000> g
Breakpoint 0 hit
eax=00000004 ebx=01059000 ecx=00000001 edx=00000001 esi=00891a40 edi=0133fc58
eip=008910c0 esp=0133fb80 ebp=0133fc58 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
Project1!AddValues1:
008910c0 55              push    ebp
0:000> kv
 # ChildEBP RetAddr  Args to Child              
00 0133fb7c 00891145 00000001 00000004 0133fd4c Project1!AddValues1 (FPO: [Non-Fpo]) (CONV: cdecl)
01 0133fc58 0089104e 00000001 00000004 0133fe80 Project1!AddValues2+0x35 (FPO: [Non-Fpo]) (CONV: cdecl)
02 0133fd4c 008912d8 0133fd70 0133fe6c 0133fe58 Project1!AddObjects+0x4e (FPO: [Non-Fpo]) (CONV: cdecl)
03 0133fe80 008919e3 00000001 015f5db8 015fb990 Project1!main+0xa8 (FPO: [Non-Fpo]) (CONV: cdecl)
04 0133fea0 008918b7 fdf471b3 00891a40 00891a40 Project1!invoke_main+0x33 (FPO: [Non-Fpo]) (CONV: cdecl)
05 0133fefc 0089175d 0133ff0c 00891a48 0133ff1c Project1!__scrt_common_main_seh+0x157 (FPO: [Non-Fpo]) (CONV: cdecl) [d:\agent\_work\3\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 288] 
06 0133ff04 00891a48 0133ff1c 768f6359 01059000 Project1!__scrt_common_main+0xd (FPO: [Non-Fpo]) (CONV: cdecl) [d:\agent\_work\3\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 331] 
07 0133ff0c 768f6359 01059000 768f6340 0133ff78 Project1!mainCRTStartup+0x8 (FPO: [Non-Fpo]) (CONV: cdecl) [d:\agent\_work\3\s\src\vctools\crt\vcstartup\src\startup\exe_main.cpp @ 17] 
08 0133ff1c 77738964 01059000 5f9cd80a 00000000 KERNEL32!BaseThreadInitThunk+0x19 (FPO: [Non-Fpo])
09 0133ff78 77738934 ffffffff 7775a0de 00000000 ntdll!__RtlUserThreadStart+0x2f (FPO: [SEH])
0a 0133ff88 00000000 00891a40 01059000 00000000 ntdll!_RtlUserThreadStart+0x1b (FPO: [Non-Fpo])
0:000> dx (OBJ*)0x0133fd70 <<<<<< This is the "hidden" return value argument, as expected it has garbage
(OBJ*)0x0133fd70                 : 0x133fd70 [Type: OBJ *]
    [+0x000] a                : -858993460 [Type: int]
    [+0x004] b                : -858993460 [Type: int]
    [+0x008] c                : -858993460 [Type: int]
0:000> dx (OBJ*)0x0133fe6c  <<<<<< This is arg1 from the call to AddObjects
(OBJ*)0x0133fe6c                  : 0x133fe6c [Type: OBJ *]
    [+0x000] a                : 1 [Type: int]
    [+0x004] b                : 2 [Type: int]
    [+0x008] c                : 3 [Type: int]
0:000> dx (OBJ*)0x0133fe58  <<<<<< This is arg2
(OBJ*)0x0133fe58                   : 0x133fe58 [Type: OBJ *]
    [+0x000] a                : 4 [Type: int]
    [+0x004] b                : 5 [Type: int]
    [+0x008] c                : 6 [Type: int]

```

In 64 bit things are a bit more complicated because the calling conventions do not pass the 4 first arguments on the stack, but on registers.
The KV command still tries to read the arguments from the stack, from the shadow space of passed arguments. So, if the file is compiled
in debug mode, it can have valid arguments when using KV. In case the arguments are not saved in the shadow space, we can still try to extract
them by tracing the flow of register usage and seeing whether the value is saved in the stack somewhere. In some cases the parameter is lost because
it's not saved anywhere on the stack. If we are lucky the parameter is saved somewhere and we can read it.

The way I typically do this is to disassemble the function from the callstack, and see if the arguments are saved in the shadow space. If they are I use
the KV command to extract the arguments, or use the Child SP value with ```dq /c1 @rsp```



## Locks

Inspecting the usage of locks is typically useful when debugging deadlock

- !cs: ("Critical Sections")

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

```.tlist``` - <process_id>:<process_name>

```
0n17636 chrome.exe
0n17744 chrome.exe
0n13076 chrome.exe
0n17148 chrome.exe
0n17516 chrome.exe
0n10776 chrome.exe
0n13176 cmd.exe
```

```!process 0 0```

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

```!process 0 0 <process_name>```

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
  
- Get the EPROCESS address : <code>!process 0 0 myproc.exe</code>
- Use the address to switch context: <code>.process /i <EPROCESS address></code>
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

```!thread```


## Pool Allocation Breakpoint

This trick is very useful - it can be used to break when a certain tag is used in an allocation.

```dd nt!PoolHitTag L1``` - read the current pool tag hit
```ed nt!PoolHitTag 'eliF'``` - set the current pool tag hit to 'File'. Each time a file will be allocated, we'll break


## Debugger Expressions

the ```dx``` command is one of the most useful commands of windbg. It can be used to evaluate a C++ like expressions in the debugger.
The reason it's so powerfull is that it let's you access symbol information and javascript windbg scripts.

Some simple examples (More examples later)


## Windbg Scripting
..
..
..

## Dotnet Debugging

- .NET Internals: https://docs.microsoft.com/en-us/archive/msdn-magazine/2005/may/net-framework-internals-how-the-clr-creates-runtime-objects


The SOS (Son Of Strike) Windbg extension can be used to debug .NET processes.

### Origin of the name

*The original name of the CLR team (chosen by team founder and former Microsoft Distinguished Engineer Mike Toutonghi) was "Lighting". Larry Sullivan's dev team created an ntsd extension dll to help facilitate the bootstrapping of v1.0. We called it strike.dll (get it? "Lightning Strike"? yeah, I know, ba'dump bum). PSS really needed this in order to give us information back to the team when it was time to debug nasty stress failures, which are almost always done with the Windows debugger stack. But we didn't want to hand out our full strike.dll, because it contained some "dangerous" commands that if you really didn't have our source code could cause you confusion and pain (even to other Microsoft teams). So I pushed the team to create "Son of Strike" (Simon from our dev takes credit/blame for this), and we shipped it with the product starting with Everett (aka V1.1).*



### Loading the SOS plugin

The SOS windbg extension is loaded from the .NET runtime DLL. First we have to make sure mscorlib is loaded into the process. if not (or, it's a dump) We first put a breakpoint on the MSCORLIB DLL (A .NET DLL that provides the .NET standard libraries)

```
> sxe ld:mscorlib
> g
```

For example:

```
ntdll!RtlUserThreadStart:
00007ffb`0290ce30 4883ec78        sub     rsp,78h
0:007> sxe ld:mscorlib
0:007> g
...
...
ModLoad: 00007ffa`d3500000 00007ffa`d43e4000   C:\windows\assembly\NativeImages_v2.0.50727_64\mscorlib\712d042affe876859328e2d4029c7297\mscorlib.ni.dll
ntdll!NtMapViewOfSection+0x14:
00007ffb`0293c574 c3              ret
```
After that, we can run a command to load the SOS plugin from the runtime DLL. the name of the runtime DLL was changed in .NET 4, so we have to specify a different name. 
This command means: Load the "sos" plugin from a loaded DLL.

To determine the version of .NET, you can run 'lm' and see which DLL is loaded:

- mscorwks: .NET 2
- clr: .NET 4

##### .NET 2

```
.loadby sos mscorwks
```

##### .NET 4+

```
.loadby sos clr
```

#### Load SOS in a dump file

In dump files you get from other computers, you need to load dll using an absolute path. So first, you need to find the .net directory that matches the .NET version that you debug (2 vs 4) - then, you need to load sos.dll from this path. For example:

```
.load C:\Windows\Microsoft.NET\Framework64\v4.0.30319\sos.dll
```

### Loading into a Wow64 dump

There's a bug in sos.dll that it cannot load correctly into a wow64 dump because it "thinks" the target architecture is incorrect.
To solve this, you can use this Windbg plugin: https://github.com/poizan42/soswow64

1. Load the dump into a Windbg x86 debugger. (It sometimes works with Windbgx64 debuggers too)
2. load sos.dll
3. load soswow64.dll
4. switch to wow64 (wow64exts.sw)
5. have fun!

example:

```
0:000> .load C:\Windows\Microsoft.NET\Framework\v2.0.50727\SOS.dll
0:000> .load C:\Tools\soswow64\soswow64.dll
Successfully hooked IDebugControl::GetExecutingProcessorType.
Successfully patched DbgEng!X86MachineInfo::ConvertCanonContextToTarget.
0:000> !wow64exts.sw
Switched to Guest (WoW) mode
0:000:x86> !clrstack
OS Thread Id: 0x1b20 (0)
ESP       EIP     
0010fd70 0000002b [InlinedCallFrame: 0010fd70] System.Windows.Forms.UnsafeNativeMethods.WaitMessage()
0010fd6c 6e5a8e08 System.Windows.Forms.Application+ComponentManager.System.Windows.Forms.UnsafeNativeMethods.IMsoComponentManager.FPushMessageLoop(Int32, Int32, Int32)
0010fe08 6e5a88f7 System.Windows.Forms.Application+ThreadContext.RunMessageLoopInner(Int32, System.Windows.Forms.ApplicationContext)
0010fe5c 6e5a8741 System.Windows.Forms.Application+ThreadContext.RunMessageLoop(Int32, System.Windows.Forms.ApplicationContext)
0010fe8c 6eabe7f2 System.Windows.Forms.Application.Run()
.......
.......
```

### Finding information about a method/type

- ```!dumpdomain``` - List all application domains.
- ```!name2ee * <full method/type/assembly name>``` can be used to find methods/types/assemblies
  - Sometimes classes are missing when using !name2ee. Not sure why.
- ```!dumpmt -md <method_table_address>``` - List all the methods in a method table. Each object has a method table
- ```!DumpMD /d <method_descriptor_address>``` - Show information about a method descriptor.
- ```!ip2md <address>``` - get method descriptor by address. 
- ```!dumpil <descriptor>``` - output IL disassembly of a method
- ```!clrstack``` - show stack trace for CLR ONLY.
- ```!dumpstack``` - show combined stack trace for CLR and native code.
  - This command is not so reliable - it can sometimes show unrelated functions 
- ```!do <object_address>``` - Dump a managed object
- ```!dso``` - Dump the objects on the stack
- ```!threads``` - list the managed threads and can be used to change context to a different thread
- ```!dumpmodule -mt <module>``` - List method tables in a module

### Managed breakpoints

There are 2 ways to put a breakpoint on a managed method:

1. Find the address of jitted code using ```!dumpmd``` and use the regular ```bp``` command.
2. If the method is not jitted yet, you can use the ```!bpmd``` command.


## Minifilter Debugging

....


## TODO

- dps
- .reload /f
- kdfiles: drvmap
- kdinit
- disassembly: u, uf, uf /c
- !pte
- .formats
- dv
- .f+ / .f- (Or Ctrl Up/Down)
- !thread
- !handle <handle>
- error <ntstatus>
- !devobj
- !drvobj
- !object
- !error <win32_error>
- !error <ntstatus> nt
- !devnode 0 1
- lmu
- ?? (_EPROCESS*)@@masm(nt!PsInitialSystemProcess)
- .reload -user	
- dd, dq, dds, dqs dps
.shell
- .kdfiles -m file c:\\hostdir\\file.sys << instead of creating a drv map file
- dt poi(nt!PsLoadedModuleList) nt!_LDR_DATA_TABLE_ENTRY -l InLoadOrderLinks.Flink BaseDllName EntryPoint
- dt <list head address> <data structure> -l <flink path> <variables to print> - if you are mistaken in the name of the flink member,
	it will show you only the first element in the list.
- dt nt!_LDR_DATA_TABLE_ENTRY poi(nt!PsLoadedModuleList)
- !poolfind
- !kp, !kc
- .frame <id>
- !gflag +ksl, sxe ld dll_name
- !ioctldecoder
- %...%\WindowsApps\Microsoft.WinDbg_8wekyb3d8bbwe\WinDbgX.exe -k com:pipe,resets=0,reconnect,port=$(pipename) -c "$$< c:\tools\virtualkd\kdinit"
- CTRL-ALT-K - Enable boot breakpoint - remember to use "Restart Guest" and not simply a reset to keep the same windbg process
- For vmware 15: https://github.com/4d61726b/VirtualKD-Redux
- Use DbgKit for object exploration: http://www.andreybazhan.com/dbgkit.html
- Use "dx" to explore processes, threads, ..
- Use "bp /w" to set smart conditional breakpoints
- Jump to address: r rip = fffff802`64c763f0 
- dx -id 0, 0, <process_object> <expression>
- Change the value of register: r <reg_name> = <reg_value>
- .pagein
- Breakpoint in process by name after DLLs are loaded: 
```
	bp /w "@$curprocess.Name.ToLower() == \"apcinjector.exe\"" nt!NtTestAlert ".reload;bp /t 1 apcinjector!main;g"
```
- Wow64 Debugging: https://docs.microsoft.com/en-us/windows/win32/winprog64/debugging-wow64
- .thread <address> - set register context
- Replace existing system drivers with kdfiles: https://kobyk.wordpress.com/2008/07/04/replacing-boot-load-drivers-with-the-windows-boot-debugger/
