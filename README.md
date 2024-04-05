# MemoryModule  

![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/yurisizuku/memorymodule?color=green&label=MemoryModule)![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/YuriSizuku/MemoryModule/build_wintools.yml?label=build_wintools)  

☘️ A flexible PE loader, loading module in memory.
Most of the functions can be inline,  compatible for shellcode.

**compatible list:**

- [x] windows xp
- [x] windows 7
- [x] windows 8
- [x] windows 10
- [x] windows 11
- [x] linux wine

## build

You can use `clang`(llvm-mingw), `gcc`(mingw-w64) or `tcc`  and `msvc`(visual studio 2022) to compile.  

Here's a example for using `llvm-mingw`

```shell
git clone https://github.com/YuriSizuku/MemoryModule.git --recursive
cd MemoryModule/project/win_memdll
make winmemdll_shellcode # only if you want to generate shellcode
make winmemdll CC=i686-w64-mingw32-gcc BUILD_TYPE=32d # x86 debug
```

## Usage

``` mermaid
%%{init: {'theme':'forest'}}%%
graph LR;
f1[winpe_findspace]
f2[winpe_memreloc];
f3[winpe_membindiat]
f4[winpe_membindtls]
f5[pfnDllMain]

f1 --> f2 --> f3 --> f4 --> f5
```

### load DLL in memory

```c
const char *dllpath = "test.dll";
size_t mempesize = 0;
void *memdll = NULL;

// load the pe file in memory and align it to memory align
void *mempe = winpe_memload_file(dllpath, &mempesize, TRUE); 

// memory loadlibrary
memdll = winpe_memLoadLibrary(mempe);
winpe_memFreeLibrary(memdll);

// memory loadlibrary at specific address
size_t targetaddr = sizeof(size_t) > 4 ? 0x140030000: 0x90000;
memdll = winpe_memLoadLibraryEx(mempe, targetaddr, 
    WINPE_LDFLAG_MEMALLOC, (PFN_LoadLibraryA)winpe_findloadlibrarya(), 
    (PFN_GetProcAddress)winpe_memGetProcAddress);
winpe_memFreeLibrary(memdll);
free(mempe);
```

### attach DLL in exe

```shell
win_injectmemdll.exe exepath dllpath [outpath]
```

### API

These functions are essential to load memory module in windows.  

See [winpe.h](https://github.com/YuriSizuku/ReverseTool/blob/master/src/winpe.h)  in detail.

```c
/**
 * load the origin rawpe file in memory buffer by mem align
 * mempe means the pe in memory alignment
 * @param pmemsize mempe buffer size
 * @return mempe buf
*/
WINPE_API
void* STDCALL winpe_memload_file(const char *path, size_t *pmemsize, bool_t same_align);

/**
 * load the mempe in a valid imagebase, will call dll entry
 * @param imagebase if 0, will load on mempe, else in imagebase
 * @param flag WINPE_LDFLAG_MEMALLOC 0x1, will alloc memory to imagebase
 *             WINPE_LDFLAG_MEMFIND 0x2, will find a valid space, 
 * @return hmodule base
*/
WINPE_API
void* STDCALL winpe_memLoadLibraryEx(void *mempe, size_t imagebase, DWORD flag,
    PFN_LoadLibraryA pfnLoadLibraryA, PFN_GetProcAddress pfnGetProcAddress);

/**
 * similar to FreeLibrary, will call dll entry
 * @return True on successful
*/
WINPE_API
BOOL STDCALL winpe_memFreeLibrary(void *mempe);

/**
 * similar to GetProcAddress
 * @return function va
*/
WINPE_API
PROC STDCALL winpe_memGetProcAddress(void *mempe, const char *funcname);

/**
 * use peb and ldr list, similar as GetModuleHandleA
 * @return ldr module address
*/
WINPE_API
void* STDCALL winpe_findmodulea(const char *modulename)
{
    return winpe_findmoduleaex(NULL, modulename);
}
```

## Known issues

- [x] attach x64 DLL to exe crash on calling some windows API
  problem occured by `movaps xmm0, xmmword ptr ss:[rsp]`
  fixed by stack memory align with 0x10  

## Todo

- [x] TLS initialize support, finished, but not tested, because I didn't find DLL with TLS example.  
- [x] support ASLR finished  
