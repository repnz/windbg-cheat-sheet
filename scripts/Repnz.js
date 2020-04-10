"use strict";

/*
----------------------------------------------------
-----------------Common Functions-------------------
----------------------------------------------------            
*/

// Shortcuts
const Debugger = () => host.namespace.Debugger;
const Registers = () => host.currentThread.Registers.User
var repnz = {}

// Conversions

function integerToHex(val) 
{
    return val.toString(16)
}

function addressToHex(address) 
{ 
    return address.ToDisplayString("x").substring(2)
}

// Memory Read/Write

const read8 = x => host.memory.readMemoryValues(x, 1, 1)[0];
const read16 = x => host.memory.readMemoryValues(x, 1, 2)[0];
const read32 = x => host.memory.readMemoryValues(x, 1, 4)[0];
const read64 = x => host.memory.readMemoryValues(x, 1, 8)[0];

function writeValue(t, address, val)
{
    execute("e{t} {address} {hexVal}", { 
        t: t, 
        address: address.ToDisplayString(), 
        hexVal: integerToHex(val)
    })
}


function write8(address, val) { writeValue("b", address, val) }
function write16(address, val) { writeValue("w", address, val) }
function write32(address, val) { writeValue("d", address, val) }
function write64(address, val) { writeValue("q", address, val) }

function writeString(address, str) { 
    execute(`ea ${address.ToDisplayString()} ${str}`)
}


function readUnicodeString(unicode_string) 
{ 
    return host.memory.readWideString(unicode_string.Buffer, unicode_string.Length)
}

function writeUnicodeString(address) 
{ 

}

// String functions
function formatString(format, args) {
    return format.replace(/{(\w+)}/g, function(match, argumentName) { 
        return typeof args[argumentName] != 'undefined' ? args[argumentName] : match
    })
}


// Windbg interface commands
function print() 
{ 
    var pureArguments = Array.prototype.slice.call(arguments)
    host.diagnostics.debugLog(pureArguments)
    host.diagnostics.debugLog("\n")
}

print("repnz: functions reloaded.")


function execute(command, args) // x: string
{
    if (args != undefined) {
        command = formatString(format, args)
    }

    return Debugger().Utility.Control.ExecuteCommand(command);
}

function setBreakpoint(address, callback) 
{
    execute('bp /w "@$scriptContents.{funcName}()" {bpAddress}', {
        funcName: callback.name, 
        bpAddress: addressToHex(address)
    })
}

function print_exception(e)
{
    print(e)
    print(e.stack)
}

function initializeScript()
{    
    return [
        new host.apiVersionSupport(1, 3)
        ];
}

function main() 
{ 
    print("repnz: main loaded.")
}

function invokeScript()
{   
    main()
}


/*
-------------------------------------------------------------
----------------- Process Extensions ------------------------
-------------------------------------------------------------
*/

function getProcessCommandLine(process) 
{
    return process.Environment.EnvironmentBlock.ProcessParameters.CommandLine.ToDisplayString()
}




/*
--------------------------------------------------------------
-----------------Virtual Address Space -----------------------
--------------------------------------------------------------
*/


const Common = () => host.namespace.Debugger.State.Scripts.DbgCommon

var AllocationType = {
    MEM_IMAGE   : "MEM_MAPPED",
    MEM_MAPPED  : "MEM_IMAGE",
    MEM_PRIVATE : "MEM_PRIVATE"
}

var Protection = {
    PAGE_NOACCESS          : "PAGE_NOACCESS",
    PAGE_READONLY          : "PAGE_READONLY",
    PAGE_READWRITE         : "PAGE_READWRITE",
    PAGE_WRITECOPY         : "PAGE_WRITECOPY",
    PAGE_EXECUTE           : "PAGE_EXECUTE",
    PAGE_EXECUTE_READ      : "PAGE_EXECUTE_READ",
    PAGE_EXECUTE_READWRITE : "PAGE_EXECUTE_READWRITE",
    PAGE_EXECUTE_WRITECOPY : "PAGE_EXECUTE_WRITECOPY",
    PAGE_GUARD             : "PAGE_GUARD",
    PAGE_NOCACHE           : "PAGE_NOCACHE",
    PAGE_WRITECOMBINE      : "PAGE_WRITECOMBINE"
}

class VadEntry {

    constructor(){
        this.Start = host.parseInt64("0")
        this.End = host.parseInt64("0")
        this.Level = host.parseInt64("0")
        this.Address = host.parseInt64("0")
        this.AllocationType = null
        this.Protection = null
        this.Details = null
    } 
}

function parseVadEntry(pageLine) {

    var lineParts = pageLine.split(" ").filter(x => x)

    var entry = new VadEntry()

    entry.Address = host.parseInt64(lineParts[0], 16)  
    entry.Level = parseInt(lineParts[1])
    entry.Start = host.parseInt64(lineParts[2], 16).bitwiseShiftLeft(16)
    entry.End = host.parseInt64(lineParts[3], 16).bitwiseShiftLeft(16)
    entry.Commited = parseInt(lineParts[4])

    var vadType = lineParts[5]
    var protectionIndex = 6

    if (vadType == "Private") {
        entry.AllocationType = AllocationType.MEM_PRIVATE
    } else if (vadType == "Mapped") {
        if (lineParts[6] == "Exe") {
            entry.AllocationType = AllocationType.MEM_IMAGE
            protectionIndex = 7
        } else {
            entry.AllocationType = AllocationType.MEM_MAPPED
        }
    } else {
        throw "Invalid mapping!"
    }

    entry.Protection = "PAGE_" + lineParts[protectionIndex]
    entry.Details = lineParts[protectionIndex+1]

    for (var i=protectionIndex+2; i<lineParts.length; i++) {
        entry.Details += " " + lineParts[i]
    }

    return entry
}

function parseVadOutput(output) {
     var index = 0
    var entries = []

    for (var line of output) {
        
        if (index == 0) {
            index += 1
            continue
        }

        if (line.length == 0) {
            break
        }

        var entry = parseVadEntry(line)
        entries.push(entry)
    }

    return entries
}

function getVadEntries()
{
    var output = execute("!vad")
    return parseVadOutput(output)
}

function getVadRoot(processObj) 
{
}

function checkVirtualProtect(virtualAddress) 
{
}




/*
--------------------------------------------------------------
----------------------- RPC Utils ----------------------------
--------------------------------------------------------------
*/
function getRpcClient() 
{ 
    var teb = host.currentThread.Environment.EnvironmentBlock   
    var magicXorValue = host.parseInt64("0x0ABABABABDEDEDEDE")
    var rpcBindingHandle = teb.ReservedForNtRpc.address.bitwiseXor(magicXorValue)
    var rpcCallState =  read_u64(rpcBindingHandle.add(0x20)) // THREAD->RpcMessage
    var portMessageAddress = read_u64(rpcCallState.add(0x1b8)) // RpcMessage->PortMessage
    var portMessage = host.createPointerObject(portMessageAddress, "nt", "_PORT_MESSAGE*")

    return { 
        ProcessId: portMessage.ClientId.UniqueProcess.address,
        ThreadId: portMessage.ClientId.UniqueThread.address
    }
}

