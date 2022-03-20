/* 
  a tool to attach a dll inside a pe file
  v0.3, developed by devseed

  history: 
    v0.2, support for x86
    v0.3, add test part, support for x64, optimizing code structure
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
unsigned char g_findloadlibrarya_code[] = {0x90};
unsigned char g_memGetProcAddress_code[] = {0x90};

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

void _oepshellcode(void *mempe_exe, void *mempe_dll, void *shellcode, 
    size_t shellcodebase, size_t dllimagebase, DWORD orgoeprva)
{
    // PE struct declear
    void *mempe;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS  pNtHeader;
    PIMAGE_FILE_HEADER pFileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory;
    PIMAGE_DATA_DIRECTORY pImpEntry;
    PIMAGE_IMPORT_DESCRIPTOR pImpDescriptor;
    PIMAGE_THUNK_DATA pFtThunk = NULL;
    PIMAGE_THUNK_DATA pOftThunk = NULL;
    LPCSTR pDllName = NULL;
    PIMAGE_IMPORT_BY_NAME pFuncName = NULL;

    // bind the pointer to buffer
    size_t oepinit_end = sizeof(g_oepinit_code);
    size_t memreloc_start = FUNC_SIZE;
    size_t memiatbind_start = memreloc_start + FUNC_SIZE;
    size_t memfindloadlibrarya_start = memiatbind_start + FUNC_SIZE;
    size_t memGetProcAddress_start = memfindloadlibrarya_start + FUNC_SIZE;
    size_t *pexeoepva = (size_t*)(g_oepinit_code + oepinit_end - 6*sizeof(size_t));
    size_t *pdllbase = (size_t*)(g_oepinit_code + oepinit_end - 5*sizeof(size_t));
    size_t *pdlloepva = (size_t*)(g_oepinit_code + oepinit_end - 4*sizeof(size_t));
    size_t *pmemiatbind = (size_t*)(g_oepinit_code + oepinit_end - 3*sizeof(size_t));
    size_t *pfindloadlibrarya = (size_t*)(g_oepinit_code + oepinit_end - 2*sizeof(size_t));
    size_t *pgetprocessaddress = (size_t*)(g_oepinit_code + oepinit_end - 1*sizeof(size_t));

    // get the information of exe
    mempe = mempe_exe;
    pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    pNtHeader = (PIMAGE_NT_HEADERS)((void*)mempe + pDosHeader->e_lfanew);
    pFileHeader = &pNtHeader->FileHeader;
    pOptHeader = &pNtHeader->OptionalHeader;
    pDataDirectory = pOptHeader->DataDirectory;
    pImpEntry =  &pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    pImpDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(mempe + pImpEntry->VirtualAddress);
    size_t exeimagebase = pOptHeader->ImageBase;

    // get the information of dll
    mempe = mempe_dll;
    pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    pNtHeader = (PIMAGE_NT_HEADERS)((void*)mempe + pDosHeader->e_lfanew);
    pFileHeader = &pNtHeader->FileHeader;
    pOptHeader = &pNtHeader->OptionalHeader;
    pDataDirectory = pOptHeader->DataDirectory;
    DWORD dlloeprva = pOptHeader->AddressOfEntryPoint;

    // fill the address table
    *pexeoepva = exeimagebase + orgoeprva;
    *pdllbase =  dllimagebase;
    *pdlloepva = dllimagebase + pOptHeader->AddressOfEntryPoint;
    *pmemiatbind = shellcodebase + memiatbind_start;
    *pfindloadlibrarya = shellcodebase + memfindloadlibrarya_start;
    *pgetprocessaddress = shellcodebase + memGetProcAddress_start;

    // copy to the target
    memcpy(shellcode , g_oepinit_code, sizeof(g_oepinit_code));
    memcpy(shellcode + memreloc_start, 
        g_memreloc_code, sizeof(g_memreloc_code));
    memcpy(shellcode + memiatbind_start, 
        g_membindiat_code, sizeof(g_membindiat_code));
    memcpy(shellcode + memfindloadlibrarya_start, 
        g_findloadlibrarya_code, sizeof(g_findloadlibrarya_code));
    memcpy(shellcode + memGetProcAddress_start, 
        g_memGetProcAddress_code, sizeof(g_memGetProcAddress_code));
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
    imgbase_exe = pOptHeader->ImageBase;

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
    DWORD orgoeprva = winpe_oepval(mempe_exe, secth.VirtualAddress);
    size_t shellcodebase = imgbase_exe + secth.VirtualAddress;
    size_t dllimagebase = shellcodebase + SHELLCODE_SIZE + padding;
    _oepshellcode(mempe_exe, mempe_dll, shellcode, 
        shellcodebase, dllimagebase, orgoeprva);
    winpe_memreloc(mempe_dll, dllimagebase);

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
    // test loadlibrary, getprocaddress
    HMODULE hmod = NULL, hmod2 = NULL, hmod3 = NULL;
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
    if(argc>3) test_memdll(argv[2]);
#endif
    if(argc < 3)
    {
        printf("usage: win_injectmemdll exepath dllpath [outpath]\n");
        printf("v0.2, developed by devseed\n");
        return 0;
    }
    char outpath[MAX_PATH];
    if(argc >= 4) strcpy(outpath, argv[3]);
    else strcpy(outpath, "out.exe");
    return injectdll_mem(argv[1], argv[2], outpath);
}