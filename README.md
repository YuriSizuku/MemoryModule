# MemoryModule
A tool to parse and load module in memory, as well as attach a DLL in EXE.

## winpe

These functions are essential to load memory module in windows. 

```c
/*
  load the origin rawpe in memory buffer by mem align
    return memsize
*/
size_t winpe_memload(const void *rawpe, size_t rawsize, 
    void *mempe, size_t memsize, bool_t same_align);


/*
  realoc the addrs for the mempe addr as image base
    return realoc count
*/
size_t winpe_memreloc(void *mempe, size_t newimagebase);

/*
  load the iat for the mempe
    return iat count
*/
size_t winpe_membindiat(void *mempe, 
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress);
```

See `winpe.h`  for parsing and loading PE structure in detail.

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

```shell
win_injectmemdll exepath dllpath [outpath]
```

