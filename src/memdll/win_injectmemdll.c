/* 
    a tool to attach a dll inside a pe file
    v0.2, developed by devseed
*/

#include <stdio.h>
#include <assert.h>
#include "winpe.h"

#define DUMP(path, addr, size)\
   FILE *_fp = fopen(path, "wb");\
   fwrite(addr, 1, size, _fp);\
   fclose(_fp)

// these functions are stub function, will be filled by python
unsigned char g_oepinit_code[] = {0x90};
unsigned char g_membindiat_code[] = {0x90};
unsigned char g_memfindexp_code[] = {0x90};

void _oepshellcode(void *mempe_exe, void *mempe_dll, 
    void *shellcode, PIMAGE_SECTION_HEADER psecth, DWORD orgoeprva)
{
    // PE struct declear
#define FUNC_SIZE 0x200
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
    size_t memiatbind_start = FUNC_SIZE;
    size_t memfindexp_start = memiatbind_start + FUNC_SIZE;
    size_t *pexeoepva = (size_t*)(g_oepinit_code + oepinit_end - 6*sizeof(size_t));
    size_t *pdllbase = (size_t*)(g_oepinit_code + oepinit_end - 5*sizeof(size_t));
    size_t *pdlloepva = (size_t*)(g_oepinit_code + oepinit_end - 4*sizeof(size_t));
    size_t *pmemiatbind = (size_t*)(g_oepinit_code + oepinit_end - 3*sizeof(size_t));
    size_t *pexeloadlibrarya = (size_t*)(g_oepinit_code + oepinit_end - 2*sizeof(size_t));
    size_t *pexegetprocessaddress = (size_t*)(g_oepinit_code + oepinit_end - 1*sizeof(size_t));

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
    size_t shellcodebase = exeimagebase + psecth->VirtualAddress; 

    // get the information of dll
    mempe = mempe_dll;
    pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    pNtHeader = (PIMAGE_NT_HEADERS)((void*)mempe + pDosHeader->e_lfanew);
    pFileHeader = &pNtHeader->FileHeader;
    pOptHeader = &pNtHeader->OptionalHeader;
    pDataDirectory = pOptHeader->DataDirectory;
    size_t dllimagebase = pOptHeader->ImageBase;
    DWORD dlloeprva = pOptHeader->AddressOfEntryPoint;

    // fill the address table
    *pexeoepva = exeimagebase + orgoeprva;
    *pdllbase =  dllimagebase;
    *pdlloepva = dllimagebase + pOptHeader->AddressOfEntryPoint;
    *pmemiatbind = shellcodebase + memiatbind_start;
    *pexeloadlibrarya = exeimagebase + 
        (size_t)(winpe_memfindiat(mempe_exe, 
            "kernel32.dll", "LoadLibraryA") - mempe_exe);
    *pexegetprocessaddress = sizeof(size_t) > 4 ?
         shellcodebase + memfindexp_start : // x64
         exeimagebase + (size_t)(winpe_memfindiat(mempe_exe, // x86
            "kernel32.dll", "GetProcAddress") - mempe_exe);

    // copy to the target
    memcpy(shellcode , g_oepinit_code, sizeof(g_oepinit_code));
    memcpy(shellcode + memiatbind_start, 
        g_membindiat_code, sizeof(g_membindiat_code));
    memcpy(shellcode + memfindexp_start, 
        g_memfindexp_code, sizeof(g_memfindexp_code));
}

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
    #define SHELLCODE_SIZE 0X1000
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

    // append the dll section and adjust
    secth.Characteristics = IMAGE_SCN_MEM_READ | 
        IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
    secth.Misc.VirtualSize = mempe_dllsize + SHELLCODE_SIZE;
    secth.SizeOfRawData = mempe_dllsize + SHELLCODE_SIZE;
    strcpy((char*)secth.Name, ".module");
    winpe_noaslr(mempe_exe);
    winpe_appendsecth(mempe_exe, &secth);
    DWORD orgoeprva = winpe_oepval(mempe_exe, secth.VirtualAddress);
    winpe_memreloc(mempe_dll, imgbase_exe + secth.VirtualAddress + SHELLCODE_SIZE);
    _oepshellcode(mempe_exe, mempe_dll, shellcode, &secth, orgoeprva);

    // write data to new exe
    FILE *fp = fopen(outpath, "wb");
    fwrite(mempe_exe, 1, mempe_exesize, fp);
    fwrite(shellcode, 1, SHELLCODE_SIZE, fp);
    fwrite(mempe_dll, 1, mempe_dllsize, fp);
    if(overlay_exe) fwrite(overlay_exe, 1, overlay_exesize, fp);
    fclose(fp);
   
    if(overlay_exe) free(overlay_exe);
    if(mempe_exe) free(mempe_exe);
    if(mempe_dll) free(mempe_dll);
    return 0;
}

void test_exp()
{
    // test loadlibrary, getprocaddress
    HMODULE hmod = NULL;
    size_t exprva = 0;
    size_t expva = 0;
    void* func = NULL;

    hmod = LoadLibraryA("kernel32.dll");
    assert(hmod!=NULL);
    expva = (size_t)GetProcAddress(hmod, "LoadLibraryA");
    exprva = (size_t)winpe_memfindexp(hmod, "LoadLibraryA") - (size_t)hmod;
    func = winpe_memforwardexp(hmod, exprva, LoadLibraryA, (PFN_GetProcAddress)winpe_memfindexp);
    assert(exprva!=0 && (size_t)func==expva  && func!=NULL);
    expva = (size_t)GetProcAddress(hmod, "InitializeSListHead");
    exprva = (size_t)winpe_memfindexp(hmod, "InitializeSListHead") - (size_t)hmod;
    func = winpe_memforwardexp(hmod, exprva, LoadLibraryA, (PFN_GetProcAddress)winpe_memfindexp);
    assert(exprva!=0 && (size_t)func==expva  && func!=NULL);
    expva = (size_t)GetProcAddress(hmod, "GetSystemTimeAsFileTime");
    exprva = (size_t)winpe_memfindexp(hmod, "GetSystemTimeAsFileTime") - (size_t)hmod;
    func = winpe_memforwardexp(hmod, exprva, LoadLibraryA, (PFN_GetProcAddress)winpe_memfindexp);
    assert(exprva!=0 && (size_t)func==expva  && func!=NULL);
}

void test_memdll(char *dllpath)
{
    size_t mempesize = 0;
    void *mempe = winpe_memload_file(dllpath, &mempesize, TRUE);;
    assert(mempe!=0 && mempesize!=0);
    winpe_membindiat(mempe, LoadLibraryA, (PFN_GetProcAddress)winpe_memfindexp);
    winpe_memLoadLibrary(mempe);
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