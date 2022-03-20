# MemoryModule
A tool to parse and load module in memory, as well as attach a DLL in EXE.
Most of the functions are inline, so that it can also be used in shellcode.

This project is tested on `windows  xp `,  `windows 7`,  `windows 10`,  `windows 11`.

## compile

```shell
cd ./src/memdll
pip install lief
pip install keystone
make ARCH=i686  # x86 release
make ARCH=x86_64 # x64 release 
make ARCH=i686 DEBUG=1 # x86 debug
make ARCH=x86_64 DEBUG=1 # x64 debug
```

## usage

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

## memory module API

These functions are essential to load memory module in windows. 

```c
/*
  similar to LoadlibrayA, will call dllentry
  will load the mempe in a valid imagebase
    return hmodule base
*/
inline void* STDCALL winpe_memLoadLibrary(void *mempe);

/*
  if imagebase==0, will load on mempe, or in imagebase
  will load the mempe in a valid imagebase, flag as below:
    WINPE_LDFLAG_MEMALLOC 0x1, will alloc memory to imagebase
    WINPE_LDFLAG_MEMFIND 0x2, will find a valid space, 
        must combined with WINPE_LDFLAG_MEMALLOC
    return hmodule base
*/
inline void* STDCALL winpe_memLoadLibraryEx(void *mempe, 
    size_t imagebase, DWORD flag,
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress);

/*
   similar to FreeLibrary, will call dllentry
     return true or false
*/
inline BOOL STDCALL winpe_memFreeLibrary(void *mempe);

/*
   FreeLibraryEx with VirtualFree custom function
     return true or false
*/
inline BOOL STDCALL winpe_memFreeLibraryEx(void *mempe, 
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress);

/*
   similar to GetProcAddress
     return function va
*/
inline PROC STDCALL winpe_memGetProcAddress(
    void *mempe, const char *funcname);

// mempe internal functions
/*
  load the origin rawpe in memory buffer by mem align
    return memsize
*/
inline size_t winpe_memload(const void *rawpe, size_t rawsize, 
    void *mempe, size_t memsize, bool_t same_align);


/*
  realoc the addrs for the mempe addr as image base
    return realoc count
*/
inline size_t winpe_memreloc(void *mempe, size_t newimagebase);

/*
  load the iat for the mempe
    return iat count
*/
inline size_t winpe_membindiat(void *mempe, 
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress);
```

See `winpe.h`  for parsing and loading PE structure in detail.

## known issues

* ~~attach x64 DLL to exe crash on calling some windows API~~  
  problem occured  by `movaps xmm0, xmmword ptr ss:[rsp]`
  fixed by stack memory align with 0x10