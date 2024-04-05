#include <stdio.h>
#include <assert.h>
#include <windows.h>
#define WINPE_IMPLEMENTATION
#ifndef WINPE_NOASM
#define WINPE_NOASM
#endif
#include "winpe.h"

void test_memdll(char *dllpath)
{
    printf("[test_memdll] dllpath=%s\n", dllpath);
    size_t mempesize = 0;
    void *memdll = NULL;
    void *mempe = winpe_memload_file(dllpath, &mempesize, TRUE);;
    assert(mempe!=0 && mempesize!=0);
    memdll = winpe_memLoadLibrary(mempe);
    printf("[test_memdll] winpe_memLoadLibrary %p\n", memdll);
    assert(memdll!=0);
    winpe_memFreeLibrary(memdll);
    
    size_t targetaddr = sizeof(size_t) > 4 ? 0x140030000: 0x290000;
    memdll = winpe_memLoadLibraryEx(memdll, targetaddr, 
        WINPE_LDFLAG_MEMALLOC, (PFN_LoadLibraryA)winpe_findloadlibrarya(), 
        (PFN_GetProcAddress)winpe_memGetProcAddress);
    printf("[test_memdll] winpe_memLoadLibraryEx %p\n", memdll);
    // assert((size_t)memdll==targetaddr);
    assert(memdll!=0);
    winpe_memFreeLibrary(memdll);
    free(mempe);
}

int main(int argc, char *argv[])
{    
    if(argc > 1) test_memdll(argv[1]);
    printf("%s finish!\n", argv[0]);
} 