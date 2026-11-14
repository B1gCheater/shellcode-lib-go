package donut

import (
	"encoding/binary"
)

// This file reproduces donut's DONUT_INSTANCE and DONUT_MODULE binary layouts.
//
// The loader reads the instance as a raw C struct at fixed offsets, and the
// encryption boundary is a byte offset into it, so these offsets are part of the
// wire format. They were dumped from a real build with
//
//	gcc -fpack-struct=8 -DDONUT_EXE ...   (as the upstream Makefile does)
//
// and are asserted against golden reference shellcode by the tests. Nothing here
// is a Go struct: the instance is assembled into a byte slice, which is why the
// generator is portable and produces identical bytes on every host.
//
// Measured layout:
//
//	sizeof(DONUT_CRYPT)    =   32
//	sizeof(DONUT_MODULE)   = 1328
//	sizeof(DONUT_INSTANCE) = 4752   (encrypted region begins at 572)
//
// Under -fpack-struct=8 the C layout happens to match Go's natural alignment for
// every member here, including the 8-byte pointer/uint64 union that starts at
// offset 48.

const (
	cryptSize = 32 // two 16-byte halves: master key and counter/nonce

	// Field size limits from include/donut.h.
	maxName    = 256
	maxDLL     = 8
	maxModName = 8
	sigLen     = 8
	verLen     = 32
	domainLen  = 8

	// DONUT_MODULE
	moduleSize    = 1328
	modOffType    = 0
	modOffThread  = 4
	modOffComp    = 8
	modOffRuntime = 12
	modOffDomain  = 268
	modOffClass   = 524
	modOffMethod  = 780
	modOffArgs    = 1036
	modOffUnicode = 1292
	modOffSig     = 1296
	modOffMac     = 1304
	modOffZLen    = 1312
	modOffLen     = 1316
	modOffData    = 1320

	// DONUT_INSTANCE
	//
	// InstanceSize is exported so tests and callers can attribute a byte offset
	// inside generated shellcode to the region it belongs to.
	InstanceSize = 4752

	instOffLen        = 0
	instOffKey        = 4
	instOffIV         = 40
	instOffAPI        = 48
	instOffAPICount   = 64 // the union holds up to 64 hashes
	instOffExitOpt    = 560
	instOffEntropy    = 564
	instOffOEP        = 568 // DONUT_INSTANCE.oep; always zero, see buildInstance
	instOffAPICnt     = 572 // encryption starts here
	instOffDLLNames   = 576
	instOffDataName   = 832
	instOffKernelbase = 840
	instOffAmsi       = 852
	instOffClr        = 860
	instOffWldp       = 864
	instOffNtdll      = 872
	instOffCmdSyms    = 880
	instOffExitAPI    = 1136
	instOffBypass     = 1392
	instOffHeaders    = 1396
	instOffWldpQuery  = 1400
	instOffWldpIsApr  = 1432
	instOffAmsiInit   = 1464
	instOffAmsiScanB  = 1480
	instOffAmsiScanS  = 1496
	instOffEtwWrite   = 1512
	instOffEtwUnreg   = 1528
	instOffEtwRet64   = 1548
	instOffEtwRet32   = 1549
	instOffWScript    = 1553
	instOffWScriptX   = 1561
	instOffDecoy      = 1573
	instOffGUIDs      = 2096
	instOffType       = 2336
	instOffServer     = 2340
	instOffUsername   = 2596
	instOffPassword   = 2852
	instOffHTTPReq    = 3108
	instOffSig        = 3116
	instOffMac        = 3376
	instOffModKey     = 3384
	instOffModLen     = 3416
	instOffModule     = 3424

	// The GUID region holds donut's 15 COM identifiers, 16 bytes each, from
	// instOffGUIDs up to instOffType. Nothing is written into it now that managed
	// and script modules are refused, but the span must stay reserved.
	guidSlots = 15
	guidSize  = 16
	decoyLen  = 520 // MAX_PATH * 2

	// argsMaxLen is donut's strncat bound for DONUT_MODULE.args:
	// strncat(mod->args, c->args, DONUT_MAX_NAME-6). An unmanaged EXE also
	// carries a five byte placeholder prefix inside the same field, so its total
	// reaches 255, while every other module type stops at 250.
	argsMaxLen = maxName - 6
)

// apiImports is the loader's import table, in the exact order the loader expects
// because the hashes are matched positionally against this list.
var apiImports = []struct{ module, name string }{
	{"kernel32.dll", "LoadLibraryA"},
	{"kernel32.dll", "GetProcAddress"},
	{"kernel32.dll", "GetModuleHandleA"},
	{"kernel32.dll", "VirtualAlloc"},
	{"kernel32.dll", "VirtualFree"},
	{"kernel32.dll", "VirtualQuery"},
	{"kernel32.dll", "VirtualProtect"},
	{"kernel32.dll", "Sleep"},
	{"kernel32.dll", "MultiByteToWideChar"},
	{"kernel32.dll", "GetUserDefaultLCID"},
	{"kernel32.dll", "WaitForSingleObject"},
	{"kernel32.dll", "CreateThread"},
	{"kernel32.dll", "CreateFileA"},
	{"kernel32.dll", "GetFileSizeEx"},
	{"kernel32.dll", "GetThreadContext"},
	{"kernel32.dll", "GetCurrentThread"},
	{"kernel32.dll", "GetCurrentProcess"},
	{"kernel32.dll", "GetCommandLineA"},
	{"kernel32.dll", "GetCommandLineW"},
	{"kernel32.dll", "HeapAlloc"},
	{"kernel32.dll", "HeapReAlloc"},
	{"kernel32.dll", "GetProcessHeap"},
	{"kernel32.dll", "HeapFree"},
	{"kernel32.dll", "GetLastError"},
	{"kernel32.dll", "CloseHandle"},

	{"shell32.dll", "CommandLineToArgvW"},

	{"oleaut32.dll", "SafeArrayCreate"},
	{"oleaut32.dll", "SafeArrayCreateVector"},
	{"oleaut32.dll", "SafeArrayPutElement"},
	{"oleaut32.dll", "SafeArrayDestroy"},
	{"oleaut32.dll", "SafeArrayGetLBound"},
	{"oleaut32.dll", "SafeArrayGetUBound"},
	{"oleaut32.dll", "SysAllocString"},
	{"oleaut32.dll", "SysFreeString"},
	{"oleaut32.dll", "LoadTypeLib"},

	{"wininet.dll", "InternetCrackUrlA"},
	{"wininet.dll", "InternetOpenA"},
	{"wininet.dll", "InternetConnectA"},
	{"wininet.dll", "InternetSetOptionA"},
	{"wininet.dll", "InternetReadFile"},
	{"wininet.dll", "InternetQueryDataAvailable"},
	{"wininet.dll", "InternetCloseHandle"},
	{"wininet.dll", "HttpOpenRequestA"},
	{"wininet.dll", "HttpSendRequestA"},
	{"wininet.dll", "HttpQueryInfoA"},

	{"mscoree.dll", "CorBindToRuntime"},
	{"mscoree.dll", "CLRCreateInstance"},

	{"ole32.dll", "CoInitializeEx"},
	{"ole32.dll", "CoCreateInstance"},
	{"ole32.dll", "CoUninitialize"},

	{"ntdll.dll", "RtlEqualUnicodeString"},
	{"ntdll.dll", "RtlEqualString"},
	{"ntdll.dll", "RtlUnicodeStringToAnsiString"},
	{"ntdll.dll", "RtlInitUnicodeString"},
	{"ntdll.dll", "RtlExitUserThread"},
	{"ntdll.dll", "RtlExitUserProcess"},
	{"ntdll.dll", "RtlCreateUnicodeString"},
	{"ntdll.dll", "RtlGetCompressionWorkSpaceSize"},
	{"ntdll.dll", "RtlDecompressBuffer"},
	{"ntdll.dll", "NtContinue"},
	{"ntdll.dll", "NtCreateSection"},
	{"ntdll.dll", "NtMapViewOfSection"},
	{"ntdll.dll", "NtUnmapViewOfSection"},
}

// dllNames is the loader's DLL search list, semicolon separated.
const dllNames = "ole32;oleaut32;wininet;mscoree;shell32"

// cmdSyms are the CRT command line symbols the loader rewrites when the user
// supplies parameters for an unmanaged EXE.
const cmdSyms = "_acmdln;__argv;__p__acmdln;__p___argv;_wcmdln;__wargv;__p__wcmdln;__p___wargv"

// exitAPI are the exit-related imports the loader redirects when the module is
// run as a thread.
const exitAPI = "ExitProcess;exit;_exit;_cexit;_c_exit;quick_exit;_Exit;_o_exit"

// The GUID table that used to live here held the CLSID and IID values the loader
// needs to host the CLR and the Active Script engine. Those slots of
// DONUT_INSTANCE are now always zero, because this package generates shellcode for
// native modules only; the region's size and offset are unchanged, and
// instOffGUIDs still names it.

// module is the generator's view of DONUT_MODULE. Data is the payload (or its
// compressed form), which donut stores as a flexible array member after the
// fixed header.
type module struct {
	Type     int
	Thread   int
	Compress int

	Runtime string
	Domain  string
	Class   string
	Method  string
	Args    string
	Unicode int

	Sig  [sigLen]byte
	Mac  uint64
	ZLen uint32
	Len  uint32

	Data []byte
}

// marshal renders the module including its trailing payload.
func (m *module) marshal() []byte {
	out := make([]byte, moduleSize+len(m.Data))

	binary.LittleEndian.PutUint32(out[modOffType:], uint32(m.Type))
	binary.LittleEndian.PutUint32(out[modOffThread:], uint32(m.Thread))
	binary.LittleEndian.PutUint32(out[modOffComp:], uint32(m.Compress))

	// These are strncpy into a zeroed buffer: no forced terminator, but a value
	// longer than the field fills it exactly.
	putString(out[modOffRuntime:modOffRuntime+maxName], m.Runtime)
	putString(out[modOffDomain:modOffDomain+maxName], m.Domain)
	putString(out[modOffClass:modOffClass+maxName], m.Class)
	putString(out[modOffMethod:modOffMethod+maxName], m.Method)
	putString(out[modOffArgs:modOffArgs+maxName], m.Args)

	binary.LittleEndian.PutUint32(out[modOffUnicode:], uint32(m.Unicode))
	copy(out[modOffSig:modOffSig+sigLen], m.Sig[:])
	binary.LittleEndian.PutUint64(out[modOffMac:], m.Mac)
	binary.LittleEndian.PutUint32(out[modOffZLen:], m.ZLen)
	binary.LittleEndian.PutUint32(out[modOffLen:], m.Len)
	copy(out[modOffData:], m.Data)

	return out
}

// instance is the generator's view of DONUT_INSTANCE.
type instance struct {
	Key [cryptSize]byte
	IV  uint64

	ExitOpt int
	Entropy int
	OEP     uint32

	DLLNames string

	DataName   string
	Kernelbase string
	Amsi       string
	Clr        string
	Wldp       string
	Ntdll      string

	CmdSyms   string
	ExitAPI   string
	Bypass    int
	Headers   int
	WldpQuery string
	WldpIsApr string
	AmsiInit  string
	AmsiScanB string
	AmsiScanS string
	EtwWrite  string
	EtwUnreg  string
	EtwRet64  string
	EtwRet32  string

	WScript  string
	WScriptX string
	Decoy    string

	Type    int
	Server  string
	User    string
	Pass    string
	HTTPReq string

	Sig    [maxName]byte
	Mac    uint64
	ModKey [cryptSize]byte
	ModLen uint64

	Module     module
	ModuleBlob []byte
}

func newInstance() *instance {
	return &instance{
		DLLNames: dllNames,
		Type:     InstanceEmbed,
		Headers:  HeadersOverwrite,
		Bypass:   BypassNone,
		ExitOpt:  ExitThread,
		Entropy:  EntropyNone,
	}
}

// marshal renders the fixed instance header followed by the module blob.
func (in *instance) marshal() ([]byte, error) {
	blob := in.ModuleBlob
	if blob == nil {
		blob = in.Module.marshal()
	}
	total := InstanceSize + len(blob)
	out := make([]byte, total)

	binary.LittleEndian.PutUint32(out[instOffLen:], uint32(total))
	copy(out[instOffKey:], in.Key[:])
	binary.LittleEndian.PutUint64(out[instOffIV:], in.IV)

	hashes := in.apiHashes()
	for i, h := range hashes {
		binary.LittleEndian.PutUint64(out[instOffAPI+i*8:], h)
	}
	binary.LittleEndian.PutUint32(out[instOffAPICnt:], uint32(len(hashes)))

	binary.LittleEndian.PutUint32(out[instOffExitOpt:], uint32(in.ExitOpt))
	binary.LittleEndian.PutUint32(out[instOffEntropy:], uint32(in.Entropy))
	binary.LittleEndian.PutUint32(out[instOffOEP:], in.OEP)
	putString(out[instOffDLLNames:instOffDLLNames+maxName], in.DLLNames)

	putString(out[instOffDataName:instOffDataName+8], in.DataName)
	putString(out[instOffKernelbase:instOffKernelbase+12], in.Kernelbase)
	putString(out[instOffAmsi:instOffAmsi+8], in.Amsi)
	putString(out[instOffClr:instOffClr+4], in.Clr)
	putString(out[instOffWldp:instOffWldp+8], in.Wldp)
	putString(out[instOffNtdll:instOffNtdll+8], in.Ntdll)
	putString(out[instOffCmdSyms:instOffCmdSyms+maxName], in.CmdSyms)
	putString(out[instOffExitAPI:instOffExitAPI+maxName], in.ExitAPI)

	binary.LittleEndian.PutUint32(out[instOffBypass:], uint32(in.Bypass))
	binary.LittleEndian.PutUint32(out[instOffHeaders:], uint32(in.Headers))

	putString(out[instOffWldpQuery:instOffWldpQuery+32], in.WldpQuery)
	putString(out[instOffWldpIsApr:instOffWldpIsApr+32], in.WldpIsApr)
	putString(out[instOffAmsiInit:instOffAmsiInit+16], in.AmsiInit)
	putString(out[instOffAmsiScanB:instOffAmsiScanB+16], in.AmsiScanB)
	putString(out[instOffAmsiScanS:instOffAmsiScanS+16], in.AmsiScanS)
	putString(out[instOffEtwWrite:instOffEtwWrite+16], in.EtwWrite)
	putString(out[instOffEtwUnreg:instOffEtwUnreg+20], in.EtwUnreg)
	putString(out[instOffEtwRet64:instOffEtwRet64+1], in.EtwRet64)
	putString(out[instOffEtwRet32:instOffEtwRet32+4], in.EtwRet32)

	putString(out[instOffWScript:instOffWScript+8], in.WScript)
	putString(out[instOffWScriptX:instOffWScriptX+12], in.WScriptX)
	putString(out[instOffDecoy:instOffDecoy+decoyLen], in.Decoy)

	binary.LittleEndian.PutUint32(out[instOffType:], uint32(in.Type))
	putString(out[instOffServer:instOffServer+maxName], in.Server)
	putString(out[instOffUsername:instOffUsername+maxName], in.User)
	putString(out[instOffPassword:instOffPassword+maxName], in.Pass)
	putString(out[instOffHTTPReq:instOffHTTPReq+8], in.HTTPReq)

	copy(out[instOffSig:instOffSig+maxName], in.Sig[:])
	binary.LittleEndian.PutUint64(out[instOffMac:], in.Mac)
	copy(out[instOffModKey:], in.ModKey[:])
	binary.LittleEndian.PutUint64(out[instOffModLen:], in.ModLen)

	copy(out[instOffModule:], blob)
	return out, nil
}

// apiHashes computes MARU(module, iv) XOR MARU(name, iv) for every import.
func (in *instance) apiHashes() []uint64 {
	out := make([]uint64, len(apiImports))
	for i, imp := range apiImports {
		out[i] = Maru(imp.name, in.IV) ^ Maru(imp.module, in.IV)
	}
	return out
}

// The CLR and Active Script GUID slots that selectGUIDs used to fill are now
// always zero: this package generates native modules only. The region is still
// reserved by marshal, at instOffGUIDs, because the loader stubs were compiled
// against that layout.

// putString copies s into dst without forcing a terminator, matching strncpy
// into a zeroed buffer.
func putString(dst []byte, s string) {
	copy(dst, s)
}
