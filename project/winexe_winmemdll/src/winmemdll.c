/**
 * Attach dll in exe as memory module
 *   v0.3.6, developed by devseed
*/

#include <stdio.h>
#define WINPE_IMPLEMENTATION
#define WINPE_NOASM
#include "winpe.h"
#include <assert.h>

#define DUMP(path, addr, size)\
   FILE *_fp = fopen(path, "wb");\
   fwrite(addr, 1, size, _fp);\
   fclose(_fp)

// these functions are stub function, will be filled by python
#include "winmemdll_shellcode.h"
#define FUNC_SIZE 0x400
#define SHELLCODE_SIZE 0X2000

#ifdef _WIN64
#define g_oepinit_code g_oepinit_code64
#define g_memreloc_code g_memreloc_code64
#define g_membindiat_code g_membindiat_code64
#define g_membindtls_code g_membindtls_code64
#define g_findloadlibrarya_code g_findloadlibrarya_code64
#define g_findgetprocaddress_code g_findgetprocaddress_code64
#else
#define g_oepinit_code g_oepinit_code32
#define g_memreloc_code g_memreloc_code32
#define g_membindiat_code g_membindiat_code32
#define g_membindtls_code g_membindtls_code32
#define g_findloadlibrarya_code g_findloadlibrarya_code32
#define g_findgetprocaddress_code g_findgetprocaddress_code32
#endif

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
    memcpy(shellcode , g_oepinit_code, sizeof(g_oepinit_code));
    memcpy((uint8_t*)shellcode + memreloc_start, g_memreloc_code, sizeof(g_memreloc_code));
    memcpy((uint8_t*)shellcode + membindiat_start, g_membindiat_code, sizeof(g_membindiat_code));
    memcpy((uint8_t*)shellcode + membindtls_start, g_membindtls_code, sizeof(g_membindtls_code));
    memcpy((uint8_t*)shellcode + findloadlibrarya_start,
        g_findloadlibrarya_code, sizeof(g_findloadlibrarya_code));
    memcpy((uint8_t*)shellcode + findgetprocaddress_start,
        g_findgetprocaddress_code, sizeof(g_findgetprocaddress_code));
}


size_t _sectpaddingsize(void *mempe, void *mempe_dll, size_t align)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)((uint8_t*)mempe + pDosHeader->e_lfanew);
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
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)((uint8_t*)mempe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;

    // append section header to exe
    size_t align = sizeof(size_t) > 4 ? 0x10000: 0x1000; 
    size_t padding = _sectpaddingsize(mempe_exe, mempe_dll, align);
    secth.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
    secth.Misc.VirtualSize = (DWORD)(SHELLCODE_SIZE + padding + mempe_dllsize);
    secth.SizeOfRawData = (DWORD)(SHELLCODE_SIZE + padding + mempe_dllsize);
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
    for(size_t i=0;i<padding;i++) fputc(0x0, fp);
    fwrite(mempe_dll, 1, mempe_dllsize, fp);
    if(overlay_exe) fwrite(overlay_exe, 1, overlay_exesize, fp);
    fclose(fp);
   
    if(overlay_exe) free(overlay_exe);
    if(mempe_exe) free(mempe_exe);
    if(mempe_dll) free(mempe_dll);
    return 0;
}

int main(int argc, char *argv[])
{    
    if(argc < 3)
    {
        printf("usage: winmemdll exepath dllpath [outpath]\n");
        printf("v0.3.6, developed by devseed\n");
        return 0;
    }
    char outpath[MAX_PATH];
    if(argc >= 4) strcpy(outpath, argv[3]);
    else strcpy(outpath, "out.exe");
    return injectdll_mem(argv[1], argv[2], outpath);
}

/**
 * history:
 * v0.1, initial version
 * v0.2, add more function for shellcode
 * v0.3, x86 and x64 no need to use exe's LoadLibraryA
 * v0.3.1, fix x64 attach dll crash by align stack with 0x10
 * v0.3.2, add support for ordinal iat and tls 
 * v0.3.3, add support for aslr
 * v0.3.4, replace win_injectmemdll_shellcodestub with make shellocde from obj
 * v0.3.5, this can be used without python
 * v0.3.6, use llvm-mingw to generate shellcode instead of clang
*/