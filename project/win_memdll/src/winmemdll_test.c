#include <stdio.h>
#include <assert.h>
#define WINPE_IMPLEMENTATION
#ifndef WINPE_NOASM
#define WINPE_NOASM
#endif
#include "winpe.h"

void test_getfunc(HMODULE hmod, const char *funcname)
{
    size_t expva = (size_t)GetProcAddress(hmod, funcname);
    size_t exprva = (size_t)winpe_memfindexp(hmod, funcname) - (size_t)hmod;
    void *func = winpe_memforwardexp(hmod, exprva, 
        LoadLibraryA, (PFN_GetProcAddress)winpe_memfindexp);
    void *func2 = winpe_memGetProcAddress(hmod, funcname);
    assert(exprva!=0 && (size_t)func==expva  
        && func!=NULL && func2==func);
    printf("test_getfunc %p %s passed!\n", hmod, funcname);
}

void test_exp()
{
    HMODULE hmod = NULL, hmod2 = NULL, hmod3 = NULL;
    // test winpe_findmodulea
    hmod = GetModuleHandleA(NULL);
    hmod2 = winpe_findmodulea(NULL);
    assert(hmod!=NULL && hmod==hmod2);
    printf("winpe_findmodulea(NULL) %p passed!\n", hmod2);
    
    // test loadlibrary, getprocaddress
    hmod = LoadLibraryA("kernel32.dll");
    hmod2 = winpe_findkernel32();
    hmod3 = winpe_findmodulea("kernel32.dll");
    assert(hmod!=NULL && hmod==hmod2 && hmod==hmod3);
    printf("winpe_findkernel32, winpe_findmodulea(kernel32) %p passed!\n", hmod);
    hmod3 = winpe_findmodulea("invalid.dll");
    assert(hmod3==NULL);

    // test some weird function
    hmod = LoadLibraryA("kernel32.dll");
    void* func = winpe_memGetProcAddress(hmod, "GetProcessMitigationPolicy");
    assert(func == GetProcAddress(hmod, "GetProcessMitigationPolicy"));
    printf("winpe_memGetProcAddress, GetProcessMitigationPolicy %p passed!\n", func);
    
    // test findexp and forwardexp
    hmod = LoadLibraryA("kernel32.dll");
    test_getfunc(hmod, "LoadLibraryA");
    test_getfunc(hmod, "InitializeSListHead");
    test_getfunc(hmod, "GetSystemTimeAsFileTime");

    printf("test_exp passed!\n\n");
}

void test_memdll(char *dllpath)
{
    size_t mempesize = 0;
    void *memdll = NULL;
    void *mempe = winpe_memload_file(dllpath, &mempesize, TRUE);;
    assert(mempe!=0 && mempesize!=0);
    memdll = winpe_memLoadLibrary(mempe);
    assert(memdll!=0);
    printf("winpe_memLoadLibrary, load at %p passed!\n", memdll);
    winpe_memFreeLibrary(memdll);
    
    size_t targetaddr = sizeof(size_t) > 4 ? 0x140030000: 0x290000;
    memdll = winpe_memLoadLibraryEx(memdll, targetaddr, 
        WINPE_LDFLAG_MEMALLOC, (PFN_LoadLibraryA)winpe_findloadlibrarya(), 
        (PFN_GetProcAddress)winpe_memGetProcAddress);
    // assert((size_t)memdll==targetaddr);
    printf("winpe_memLoadLibraryEx, load at %p passed!\n", memdll);
    winpe_memFreeLibrary(memdll);

    printf("test_memdll %s passed]\n\n", dllpath);
    free(mempe);
}

int main(int argc, char *argv[])
{    
    test_exp();
    if(argc > 1) test_memdll(argv[1]);
} 