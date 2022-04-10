/* 
A tool to attach a dll inside a pe file
    v0.3.3, developed by devseed

history: 
    see win_injectmemdll_shellcodestub.py
*/

#include <stdio.h>
#include <assert.h>
#include "winpe.h"

#define DUMP(path, addr, size)\
   FILE *_fp = fopen(path, "wb");\
   fwrite(addr, 1, size, _fp);\
   fclose(_fp)

// these functions are stub function, will be filled by python
#define FUNC_SIZE 0x400
#define SHELLCODE_SIZE 0X2000
unsigned char g_oepinit_code[] = {0x90};
unsigned char g_memreloc_code[] = {0x90};
unsigned char g_membindiat_code[] = {0x90};
unsigned char g_membindtls_code[] = {0x90};
unsigned char g_findloadlibrarya_code[] = {0x90};
unsigned char g_findgetprocaddress_code[] = {0x90};

void _makeoepcode(void *shellcode, 
    size_t shellcoderva, size_t dllrva, 
    DWORD orgexeoeprva, DWORD orgdlloeprva)
{
    // bind the pointer to buffer
    size_t oepinit_end = sizeof(g_oepinit_code);
    size_t memreloc_start = FUNC_SIZE;
    size_t membindiat_start = memreloc_start + FUNC_SIZE;
    size_t membindtls_start = membindiat_start + FUNC_SIZE;
    size_t findloadlibrarya_start = membindtls_start + FUNC_SIZE;
    size_t findgetprocaddress_start = findloadlibrarya_start + FUNC_SIZE;

     // fill the address table
    size_t *pexeoeprva = (size_t*)(g_oepinit_code + oepinit_end - 8*sizeof(size_t));
    size_t *pdllbrva = (size_t*)(g_oepinit_code + oepinit_end - 7*sizeof(size_t));
    size_t *pdlloeprva = (size_t*)(g_oepinit_code + oepinit_end - 6*sizeof(size_t));
    size_t *pmemrelocrva = (size_t*)(g_oepinit_code + oepinit_end - 5*sizeof(size_t));
    size_t *pmembindiatrva = (size_t*)(g_oepinit_code + oepinit_end - 4*sizeof(size_t));
    size_t *pmembindtlsrva = (size_t*)(g_oepinit_code + oepinit_end - 3*sizeof(size_t));
    size_t *pfindloadlibrarya = (size_t*)(g_oepinit_code + oepinit_end - 2*sizeof(size_t));
    size_t *pfindgetprocaddress = (size_t*)(g_oepinit_code + oepinit_end - 1*sizeof(size_t));
    *pexeoeprva = orgexeoeprva;
    *pdllbrva =  dllrva;
    *pdlloeprva = dllrva + orgdlloeprva;
    *pmemrelocrva = shellcoderva + memreloc_start;
    *pmembindiatrva = shellcoderva + membindiat_start;
    *pmembindtlsrva = shellcoderva + membindtls_start;
    *pfindloadlibrarya = shellcoderva + findloadlibrarya_start;
    *pfindgetprocaddress = shellcoderva + findgetprocaddress_start;

    // copy to the target
    memcpy(shellcode , 
        g_oepinit_code, sizeof(g_oepinit_code));
    memcpy(shellcode + memreloc_start, 
        g_memreloc_code, sizeof(g_memreloc_code));
    memcpy(shellcode + membindiat_start, 
        g_membindiat_code, sizeof(g_membindiat_code));
    memcpy(shellcode + membindtls_start, 
        g_membindtls_code, sizeof(g_membindtls_code));
    memcpy(shellcode + findloadlibrarya_start, 
        g_findloadlibrarya_code, sizeof(g_findloadlibrarya_code));
    memcpy(shellcode + findgetprocaddress_start, 
        g_findgetprocaddress_code, sizeof(g_findgetprocaddress_code));
}


size_t _sectpaddingsize(void *mempe, void *mempe_dll, size_t align)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)mempe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    size_t _v = (pOptHeader->SizeOfImage + SHELLCODE_SIZE) % align;
    if (_v) return align - _v;
    else return 0;
}

// memory structure: [exe sections], [shellcode, padding, dll]
int injectdll_mem(const char *exepath, 
    const char *dllpath, const char *outpath)
{
    size_t exe_overlayoffset = 0;
    size_t exe_overlaysize = 0;
    void *mempe_dll = NULL;
    size_t mempe_dllsize = 0;
    void *mempe_exe = NULL;
    size_t mempe_exesize = 0;
    void *overlay_exe = NULL;
    size_t overlay_exesize = 0;
    size_t imgbase_exe = 0;
    IMAGE_SECTION_HEADER secth = {0};
    char shellcode[SHELLCODE_SIZE];

    // load exe and dll pe 
    mempe_exe = winpe_memload_file(exepath, &mempe_exesize, TRUE);
    mempe_dll = winpe_memload_file(dllpath, &mempe_dllsize, TRUE);
    overlay_exe = winpe_overlayload_file(exepath, &overlay_exesize);
    void *mempe = mempe_exe;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)mempe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;

    // append section header to exe
    size_t align = sizeof(size_t) > 4 ? 0x10000: 0x1000; 
    size_t padding = _sectpaddingsize(mempe_exe, mempe_dll, align);
    secth.Characteristics = IMAGE_SCN_MEM_READ | 
        IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
    secth.Misc.VirtualSize = SHELLCODE_SIZE + padding + mempe_dllsize;
    secth.SizeOfRawData = SHELLCODE_SIZE + padding + mempe_dllsize;
    strcpy((char*)secth.Name, ".module");
    winpe_noaslr(mempe_exe);
    winpe_appendsecth(mempe_exe, &secth);

    // adjust dll addr and append shellcode, iatbind is in runing
    size_t shellcoderva = secth.VirtualAddress;
    size_t dllrva = shellcoderva + SHELLCODE_SIZE + padding;
    DWORD orgdlloeprva = winpe_oepval(mempe_dll, 0); // origin orgdlloeprva
    DWORD orgexeoeprva = winpe_oepval(mempe_exe, secth.VirtualAddress);
    _makeoepcode(shellcode, shellcoderva, dllrva, orgexeoeprva, orgdlloeprva);
    // reloc while runing
    // winpe_memreloc(mempe_dll, dllrva);

    // write data to new exe
    FILE *fp = fopen(outpath, "wb");
    fwrite(mempe_exe, 1, mempe_exesize, fp);
    fwrite(shellcode, 1, SHELLCODE_SIZE, fp);
    for(int i=0;i<padding;i++) fputc(0x0, fp);
    fwrite(mempe_dll, 1, mempe_dllsize, fp);
    if(overlay_exe) fwrite(overlay_exe, 1, overlay_exesize, fp);
    fclose(fp);
   
    if(overlay_exe) free(overlay_exe);
    if(mempe_exe) free(mempe_exe);
    if(mempe_dll) free(mempe_dll);
    return 0;
}

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
    
    size_t targetaddr = sizeof(size_t) > 4 ? 0x140030000: 0x90000;
    memdll = winpe_memLoadLibraryEx(memdll, targetaddr, 
        WINPE_LDFLAG_MEMALLOC, (PFN_LoadLibraryA)winpe_findloadlibrarya(), 
        (PFN_GetProcAddress)winpe_memGetProcAddress);
    assert((size_t)memdll==targetaddr);
    printf("winpe_memLoadLibraryEx, load at %p passed!\n", memdll);
    winpe_memFreeLibrary(memdll);

    printf("test_memdll %s passed]\n\n", dllpath);
    free(mempe);
}

int main(int argc, char *argv[])
{    
#ifdef _DEBUG
    test_exp();
    if(argc > 3) test_memdll(argv[2]);
#endif
    if(argc < 3)
    {
        printf("usage: win_injectmemdll exepath dllpath [outpath]\n");
        printf("v0.3.3, developed by devseed\n");
        return 0;
    }
    char outpath[MAX_PATH];
    if(argc >= 4) strcpy(outpath, argv[3]);
    else strcpy(outpath, "out.exe");
    return injectdll_mem(argv[1], argv[2], outpath);
}