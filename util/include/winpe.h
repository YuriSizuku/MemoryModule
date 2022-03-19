/*
  winpe.h, by devseed, v0.2.2
  for parsing windows pe structure, adjust realoc addrs, or iat
  this function for shellcode should only use release version

  history:
  v0.1 initial version, with load pe in memory align
  V0.1.2 adjust declear name, load pe iat
  v0.2 add append section, findiat function
  v0.2.2 add function winpe_memfindexp
  v0.2.5 inline basic functions, better for shellcode
  v0.3 add winpe_memloadlibrary, winpe_memgetprocaddress, winpe_memfreelibrary

*/

#ifndef _WINPE_H
#define _WINPE_H
#include <stdint.h>
#include <Windows.h>

#ifndef WINPEDEF
#ifdef WINPE_STATIC
#define WINPEDEF static
#else
#define WINPEDEF extern
#endif
#endif

#ifndef WINPE_SHARED
#define WINPE_EXPORT
#else
#ifdef _WIN32
#define WINPE_EXPORT __declspec(dllexport)
#else
#define WINPE_EXPORT __attribute__((visibility("default")))
#endif
#endif

#ifdef _WIN32
#define STDCALL __stdcall
#else
#define STDCALL __attribute__((stdcall))
#endif

#ifdef __cplusplus
extern "C" {
#endif
typedef struct _RELOCOFFSET
{
	WORD offset : 12;
	WORD type	: 4;
}RELOCOFFSET,*PRELOCOFFSET;

typedef int bool_t;

typedef HMODULE (WINAPI *PFN_LoadLibraryA)(
    LPCSTR lpLibFileName);

typedef FARPROC (WINAPI *PFN_GetProcAddress)(
    HMODULE hModule, LPCSTR lpProcName);

typedef PFN_GetProcAddress PFN_GetProcRVA;

typedef LPVOID (WINAPI *PFN_VirtualAlloc)(
    LPVOID lpAddress, SIZE_T dwSize, 
    DWORD  flAllocationType, DWORD flProtect);

typedef BOOL (WINAPI *PFN_VirtualFree)(
    LPVOID lpAddress, SIZE_T dwSize, 
    DWORD dwFreeType);

typedef BOOL (WINAPI *PFN_VirtualProtect)(
    LPVOID lpAddress, SIZE_T dwSize,
    DWORD  flNewProtect, PDWORD lpflOldProtect);

typedef SIZE_T (WINAPI *PFN_VirtualQuery)(
    LPCVOID lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T dwLength);

typedef BOOL (WINAPI *PFN_DllMain)(HINSTANCE hinstDLL,
    DWORD fdwReason, LPVOID lpReserved );

#define WINPE_LDFLAG_RVAPROC 0x1

// PE high order fnctions
/*
  load the origin rawpe file in memory buffer by mem align
  mempe means the pe in memory alignment
    return mempe buffer, memsize
*/
WINPEDEF WINPE_EXPORT 
void* winpe_memload_file(const char *path, 
    size_t *pmemsize, bool_t same_align);

/*
  load the overlay data in a pe file
    return overlay buf, overlay size
*/
WINPEDEF WINPE_EXPORT
void* winpe_overlayload_file(const char *path, 
    size_t *poverlaysize);

/*
  similar to LoadlibrayA, will call dllentry
  will load the mempe in a valid imagebase
    return hmodule base
*/
WINPEDEF WINPE_EXPORT
void* STDCALL winpe_memLoadLibrary(void *mempe);

/*
  if imagebase==0, will load on mempe, or in imagebase
  will load the mempe in a valid imagebase, 
    return hmodule base
*/
WINPEDEF WINPE_EXPORT
inline void* STDCALL winpe_memLoadLibraryEx(void *mempe, 
    size_t imagebase, DWORD flag,
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress);

/*
   similar to FreeLibrary, will call dllentry
     return true or false
*/
WINPEDEF WINPE_EXPORT
inline BOOL STDCALL winpe_memFreeLibrary(void *mempe);

/*
   similar to GetProcAddress
     return function va
*/
WINPEDEF WINPE_EXPORT
inline PROC STDCALL winpe_memGetProcAddress(
    void *mempe, const char *funcname);

// PE query functions
/*
   use ped to find kernel32.dll address
     return kernel32.dll address
*/
WINPEDEF WINPE_EXPORT
inline void* winpe_findkernel32();

WINPEDEF WINPE_EXPORT
inline PROC winpe_findloadlibrarya();

WINPEDEF WINPE_EXPORT
inline PROC winpe_findgetprocaddress();

/*
    find a valid space address start from imagebase with imagesize
    use PFN_VirtualQuery for better use 
      return va with imagesize
*/
WINPEDEF WINPE_EXPORT
inline void* winpe_findspace(
    size_t imagebase, size_t imagesize, 
    PFN_VirtualQuery pfnVirtualQuery);

// PE load, adjust functions
/*
  for overlay section in a pe file
    return the overlay offset
*/
WINPEDEF WINPE_EXPORT 
inline size_t winpe_overlayoffset(const void *rawpe);

/*
  load the origin rawpe in memory buffer by mem align
    return memsize
*/
WINPEDEF WINPE_EXPORT 
inline size_t winpe_memload(
    const void *rawpe, size_t rawsize, 
    void *mempe, size_t memsize, 
    bool_t same_align);

/*
  realoc the addrs for the mempe addr as image base
  origin image base usually at 0x00400000, 0x0000000180000000
  new image base mush be divided by 0x10000, if use loadlibrary
    return realoc count
*/
WINPEDEF WINPE_EXPORT 
inline size_t winpe_memreloc(
    void *mempe, size_t newimagebase);

/*
  load the iat for the mempe, use rvafunc for winpe_memfindexp 
    return iat count
*/
WINPEDEF WINPE_EXPORT 
inline size_t winpe_membindiat(void *mempe, 
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress);

/*
  find the iat addres, for call [iat]
    return target iat va
*/
WINPEDEF WINPE_EXPORT
inline void* winpe_memfindiat(void *mempe, 
    LPCSTR dllname, LPCSTR funcname);

/*
  find the exp  addres, the same as GetProcAddress
  without forward to other dll
  such as NTDLL.RtlInitializeSListHead
    return target exp va
*/
WINPEDEF WINPE_EXPORT 
inline void* STDCALL winpe_memfindexp(
    void *mempe, LPCSTR funcname);

/*
  forward the exp to the final expva
    return the final exp va
*/
WINPEDEF WINPE_EXPORT
inline void *winpe_memforwardexp(
    void *mempe, size_t exprva, 
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress);

// PE modify function
/* 
  change the oep of the pe if newoeprva!=0
    return the old oep rva
*/
WINPEDEF WINPE_EXPORT
inline DWORD winpe_oepval(void *mempe, DWORD newoeprva);

/* 
  change the imagebase of the pe if newimagebase!=0
    return the old imagebase va
*/
WINPEDEF WINPE_EXPORT
inline size_t winpe_imagebaseval(void *mempe, size_t newimagebase);

/*
    close the aslr feature of an pe
*/
WINPEDEF WINPE_EXPORT
inline void winpe_noaslr(void *pe);

/* 
  Append a section header in a pe, sect rva will be ignored
  the mempe size must be enough for extend a section
    return image size
*/
WINPEDEF WINPE_EXPORT 
inline size_t winpe_appendsecth(void *mempe, 
    PIMAGE_SECTION_HEADER psecth);


#ifdef __cplusplus
}
#endif


#ifdef WINPE_IMPLEMENTATION
#include <stdio.h>
#ifndef _DEBUG
#define NDEBUG
#endif
#include <assert.h>
#include <Windows.h>

inline static int _inl_stricmp(const char *str1, const char *str2)
{
    int i=0;
    while(str1[i]!=0 && str2[i]!=0)
    {
        if (str1[i] == str2[i] 
        || str1[i] + 0x20 == str2[i] 
        || str2[i] + 0x20 == str1[i])
        {
            i++;
        }
        else
        {
            return (int)str1[i] - (int)str2[i];
        }
    }
    return (int)str1[i] - (int)str2[i];
}

inline static void* _inl_memset(void *buf, int ch, size_t n)
{
    char *p = buf;
    for(int i=0;i<n;i++) p[i] = (char)ch;
    return buf;
}

inline static void* _inl_memcpy(void *dst, const void *src, size_t n)
{
    char *p1 = (char*)dst;
    char *p2 = (char*)src;
    for(int i=0;i<n;i++) p1[i] = p2[i];
    return dst;
}

// PE high order fnctions
WINPEDEF WINPE_EXPORT 
void* winpe_memload_file(const char *path, 
    size_t *pmemsize, bool_t same_align)
{
    FILE *fp = fopen(path, "rb");
    fseek(fp, 0, SEEK_END);
    size_t rawsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    void *rawpe = malloc(rawsize);
    fread(rawpe, 1, rawsize, fp);
    fclose(fp);

    void *mempe = NULL;
    if(pmemsize)
    {
        *pmemsize = winpe_memload(rawpe, 0, NULL, 0, FALSE);
        mempe = malloc(*pmemsize);
        winpe_memload(rawpe, rawsize, mempe, *pmemsize, same_align);
    }
    free(rawpe);
    return mempe;
}

WINPEDEF WINPE_EXPORT 
void* winpe_overlayload_file(
    const char *path, size_t *poverlaysize)
{
    FILE *fp = fopen(path, "rb");
    fseek(fp, 0, SEEK_END);
    size_t rawsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    void *rawpe = malloc(rawsize);
    fread(rawpe, 1, rawsize, fp);
    fclose(fp);
    void *overlay = NULL;
    size_t overlayoffset = winpe_overlayoffset(rawpe);
    
    if(poverlaysize)
    {
        *poverlaysize = rawsize - overlayoffset;
        if(*poverlaysize>0)
        {
            overlay = malloc(*poverlaysize);
            memcpy(overlay, rawpe+overlayoffset, *poverlaysize);
        }
    }
    free(rawpe);
    return overlay;
}


WINPEDEF WINPE_EXPORT
void* STDCALL winpe_memLoadLibrary(void *mempe)
{
    return NULL;
}

WINPEDEF WINPE_EXPORT
inline void* STDCALL winpe_memLoadLibraryEx(void *mempe, 
    size_t imagebase, DWORD flag,
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress)
{
    return NULL;
}

WINPEDEF WINPE_EXPORT
inline BOOL STDCALL winpe_memFreeLibrary(void *mempe)
{
    return TRUE;
}

WINPEDEF WINPE_EXPORT
inline PROC STDCALL winpe_memGetProcAddress(
    void *mempe, const char *funcname)
{
    void* expva = winpe_memfindexp(mempe, funcname);
    size_t exprva = (size_t)(expva - mempe);
    return (PROC)winpe_memforwardexp(mempe, exprva, 
        (PFN_LoadLibraryA)winpe_findloadlibrarya(), 
        (PFN_GetProcAddress)winpe_memfindexp);
}

// PE query functions
WINPEDEF WINPE_EXPORT
inline void* winpe_findkernel32()
{
    return NULL;
}

WINPEDEF WINPE_EXPORT
inline PROC winpe_findloadlibrarya()
{
    return NULL;
}

WINPEDEF WINPE_EXPORT
inline PROC winpe_findgetprocaddress()
{
    return NULL;
}

WINPEDEF WINPE_EXPORT
inline void* winpe_findspace(
    size_t imagebase, size_t imagesize, 
    PFN_VirtualQuery pfnVirtualQuery)
{
    return NULL;
}

// PE load, adjust functions
WINPEDEF WINPE_EXPORT 
inline size_t winpe_overlayoffset(const void *rawpe)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)rawpe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)rawpe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
    PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)
        ((void*)pOptHeader + pFileHeader->SizeOfOptionalHeader);
    WORD sectNum = pFileHeader->NumberOfSections;

    return pSectHeader[sectNum-1].PointerToRawData + 
           pSectHeader[sectNum-1].SizeOfRawData;
}

WINPEDEF WINPE_EXPORT 
inline size_t winpe_memload(
    const void *rawpe, size_t rawsize, 
    void *mempe, size_t memsize, 
    bool_t same_align)
{
    // load rawpe to memalign
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)rawpe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)rawpe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)
        ((void *)pOptHeader + pFileHeader->SizeOfOptionalHeader);
    WORD sectNum = pFileHeader->NumberOfSections;
    size_t imagesize = pOptHeader->SizeOfImage;
    if(!mempe) return imagesize;
    else if(memsize!=0 && memsize<imagesize) return 0;

    _inl_memset(mempe, 0, imagesize);
    _inl_memcpy(mempe, rawpe, pOptHeader->SizeOfHeaders);
    
    for(WORD i=0;i<sectNum;i++)
    {
        _inl_memcpy(mempe+pSectHeader[i].VirtualAddress, 
            rawpe+pSectHeader[i].PointerToRawData,
            pSectHeader[i].SizeOfRawData);
    }

    // adjust all to mem align
    if(same_align)
    {
        pDosHeader = (PIMAGE_DOS_HEADER)mempe;
        pNtHeader = (PIMAGE_NT_HEADERS)((void*)mempe + pDosHeader->e_lfanew);
        pFileHeader = &pNtHeader->FileHeader;
        pOptHeader = &pNtHeader->OptionalHeader;
        pSectHeader = (PIMAGE_SECTION_HEADER)
            ((void *)pOptHeader + pFileHeader->SizeOfOptionalHeader);
        sectNum = pFileHeader->NumberOfSections;

        pOptHeader->FileAlignment = pOptHeader->SectionAlignment;

        for(WORD i=0;i<sectNum;i++)
        {
            pSectHeader[i].PointerToRawData = pSectHeader[i].VirtualAddress;
        }
    }
    return imagesize;
}

WINPEDEF WINPE_EXPORT 
inline size_t winpe_memreloc(
    void *mempe, size_t newimagebase)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)mempe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
    PIMAGE_DATA_DIRECTORY pRelocEntry = &pDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	
    DWORD reloc_count = 0;
	DWORD reloc_offset = 0;
    int64_t shift = (int64_t)newimagebase - 
        (int64_t)pOptHeader->ImageBase;
	while (reloc_offset < pRelocEntry->Size)
	{
		PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)
            ((void*)mempe + pRelocEntry->VirtualAddress + reloc_offset);
        PRELOCOFFSET pRelocOffset = (PRELOCOFFSET)((void*)pBaseReloc 
            + sizeof(IMAGE_BASE_RELOCATION));
		DWORD item_num = (pBaseReloc->SizeOfBlock - // RELOCOFFSET block num
			sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOCOFFSET);
		for (size_t i = 0; i < item_num; i++)
		{
			if (!pRelocOffset[i].type && 
                !pRelocOffset[i].offset) continue;
			DWORD targetoffset = pBaseReloc->VirtualAddress + 
                    pRelocOffset[i].offset;
            size_t *paddr = (size_t *)((void*)mempe + targetoffset);
            size_t relocaddr = (size_t)((int64_t)*paddr + shift);
            //printf("reloc 0x%08x->0x%08x\n", *paddr, relocaddr);
            *paddr = relocaddr;
		}
		reloc_offset += sizeof(IMAGE_BASE_RELOCATION) + 
            sizeof(RELOCOFFSET) * item_num;
		reloc_count += item_num;
	}
    pOptHeader->ImageBase = newimagebase;
	return reloc_count;
}

WINPEDEF WINPE_EXPORT 
inline size_t winpe_membindiat(void *mempe, 
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)mempe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
    PIMAGE_DATA_DIRECTORY pImpEntry =  
        &pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR pImpDescriptor =  
        (PIMAGE_IMPORT_DESCRIPTOR)(mempe + pImpEntry->VirtualAddress);

    PIMAGE_THUNK_DATA pFtThunk = NULL;
    PIMAGE_THUNK_DATA pOftThunk = NULL;
    LPCSTR pDllName = NULL;
    PIMAGE_IMPORT_BY_NAME pImpByName = NULL;

    // origin GetProcAddress will crash at InitializeSListHead 
    if(!pfnLoadLibraryA) pfnLoadLibraryA = LoadLibraryA;
    if(!pfnGetProcAddress) pfnGetProcAddress = GetProcAddress;
    DWORD iat_count = 0;
    for (; pImpDescriptor->Name; pImpDescriptor++) 
    {
        pDllName = (LPCSTR)(mempe + pImpDescriptor->Name);
        pFtThunk = (PIMAGE_THUNK_DATA)
            (mempe + pImpDescriptor->FirstThunk);
        pOftThunk = (PIMAGE_THUNK_DATA)
            (mempe + pImpDescriptor->OriginalFirstThunk);
        size_t dllbase = (size_t)pfnLoadLibraryA(pDllName);
        if(!dllbase) return 0;

        for (int j=0; pFtThunk[j].u1.Function 
            &&  pOftThunk[j].u1.Function; j++) 
        {
            // supposed iat has no ordinal only
            pImpByName=(PIMAGE_IMPORT_BY_NAME)(mempe +
                pOftThunk[j].u1.AddressOfData);
            size_t addr = (size_t)pfnGetProcAddress(
                (HMODULE)dllbase, pImpByName->Name);
            addr = (size_t)winpe_memforwardexp((void*)dllbase, 
                addr-dllbase, pfnLoadLibraryA, pfnGetProcAddress);
            if(!addr) continue;
            pFtThunk[j].u1.Function = addr;
            assert(addr == (size_t)GetProcAddress(
                (HMODULE)dllbase, pImpByName->Name));
            iat_count++;
        }
    }
    return iat_count;
}

WINPEDEF WINPE_EXPORT
inline void* winpe_memfindiat(void *mempe, 
    LPCSTR dllname, LPCSTR funcname)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)mempe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
    PIMAGE_DATA_DIRECTORY pImpEntry =  
        &pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR pImpDescriptor =  
        (PIMAGE_IMPORT_DESCRIPTOR)(mempe + pImpEntry->VirtualAddress);

    PIMAGE_THUNK_DATA pFtThunk = NULL;
    PIMAGE_THUNK_DATA pOftThunk = NULL;
    LPCSTR pDllName = NULL;
    PIMAGE_IMPORT_BY_NAME pImpByName = NULL;

    for (; pImpDescriptor->Name; pImpDescriptor++) 
    {
        pDllName = (LPCSTR)(mempe + pImpDescriptor->Name);
        if(dllname && _inl_stricmp(pDllName, dllname)!=0) continue;
        pFtThunk = (PIMAGE_THUNK_DATA)
            (mempe + pImpDescriptor->FirstThunk);
        pOftThunk = (PIMAGE_THUNK_DATA)
            (mempe + pImpDescriptor->OriginalFirstThunk);

        for (int j=0; pFtThunk[j].u1.Function 
            &&  pOftThunk[j].u1.Function; j++) 
        {
            pImpByName=(PIMAGE_IMPORT_BY_NAME)(mempe +
                pOftThunk[j].u1.AddressOfData);
            if((size_t)funcname < MAXWORD) // ordinary
            {
                WORD funcord = LOWORD(funcname);
                if(pImpByName->Hint == funcord)
                    return &pFtThunk[j];
            }
            else
            {
                if(_inl_stricmp(pImpByName->Name, funcname)==0) 
                    return &pFtThunk[j];
            }
        }
    }
    return 0;
}

WINPEDEF WINPE_EXPORT 
inline void* STDCALL winpe_memfindexp(
    void *mempe, LPCSTR funcname)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)mempe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
    PIMAGE_DATA_DIRECTORY pExpEntry =  
        &pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY  pExpDescriptor =  
        (PIMAGE_EXPORT_DIRECTORY)(mempe + pExpEntry->VirtualAddress);

    WORD *ordrva = mempe + pExpDescriptor->AddressOfNameOrdinals;
    DWORD *namerva = mempe + pExpDescriptor->AddressOfNames;
    DWORD *funcrva = mempe + pExpDescriptor->AddressOfFunctions;
    if((size_t)funcname <= MAXWORD) // find by ordnial
    {
        WORD ordbase = LOWORD(pExpDescriptor->Base) - 1;
        WORD funcord = LOWORD(funcname);
        return (void*)(mempe + funcrva[ordrva[funcord-ordbase]]);
    }
    else
    {
        for(int i=0;i<pExpDescriptor->NumberOfNames;i++)
        {
            LPCSTR curname = (LPCSTR)(mempe+namerva[i]);
            if(_inl_stricmp(curname, funcname)==0)
            {
                return (void*)(mempe + funcrva[ordrva[i]]);
            }       
        }
    }
    return 0;
}

WINPEDEF WINPE_EXPORT
inline void *winpe_memforwardexp(
    void *mempe, size_t exprva, 
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress)
{
    size_t dllbase = (size_t)mempe;
    while (1)
    {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllbase;
        PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
            ((void*)dllbase + pDosHeader->e_lfanew);
        PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
        PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
        PIMAGE_DATA_DIRECTORY pExpEntry =  
            &pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if(exprva>=pExpEntry->VirtualAddress && 
            exprva<= pExpEntry->VirtualAddress + pExpEntry->Size)
        {
            char namebuf[MAX_PATH];
            char *dllname = (char *)(dllbase + exprva);
            char *funcname = dllname;
            int i=0, j=0;
            while(dllname[i]!=0)
            {
                if(dllname[i]=='.')
                {
                    namebuf[j] = dllname[i];
                    namebuf[++j] = 'd';
                    namebuf[++j] = 'l';
                    namebuf[++j] = 'l';
                    namebuf[++j] = '\0';
                    funcname = namebuf + j + 1;
                }
                else
                {
                    namebuf[j]=dllname[i];
                }
                i++;
                j++;
            }
            namebuf[j] = '\0';
            dllname = namebuf;
            dllbase = (size_t)pfnLoadLibraryA(dllname);
            exprva = (size_t)pfnGetProcAddress((HMODULE)dllbase, funcname);
            exprva -= dllbase;
        }
        else
        {
            return (void*)(dllbase + exprva);
        } 
    }
    return NULL;
}

// PE setting function
WINPEDEF WINPE_EXPORT
inline void winpe_noaslr(void *pe)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)pe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    pOptHeader->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}

WINPEDEF WINPE_EXPORT
inline DWORD winpe_oepval(void *pe, DWORD newoeprva)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)pe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    DWORD orgoep = pOptHeader->AddressOfEntryPoint;
    if(newoeprva) pOptHeader->AddressOfEntryPoint = newoeprva;
    return orgoep;
}

WINPEDEF WINPE_EXPORT
inline size_t winpe_imagebaseval(void *pe, size_t newimagebase)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)pe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    size_t imagebase = pOptHeader->ImageBase;
    if(newimagebase) pOptHeader->ImageBase = newimagebase;
    return imagebase; 
}

WINPEDEF WINPE_EXPORT 
inline size_t winpe_appendsecth(void *pe, 
    PIMAGE_SECTION_HEADER psecth)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)pe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)
        ((void*)pOptHeader + pFileHeader->SizeOfOptionalHeader);
    WORD sectNum = pFileHeader->NumberOfSections;
    PIMAGE_SECTION_HEADER pLastSectHeader = &pSectHeader[sectNum-1];
    DWORD addr, align;

    // check the space to append section
    if(pFileHeader->SizeOfOptionalHeader 
        + sizeof(IMAGE_SECTION_HEADER)
     > pSectHeader[0].PointerToRawData) return 0;

    // fill rva addr
    align = pOptHeader->SectionAlignment;
    addr = pLastSectHeader->VirtualAddress + pLastSectHeader->Misc.VirtualSize;
    if(addr % align) addr += align - addr%align;
    psecth->VirtualAddress = addr;

    // fill file offset
    align = pOptHeader->FileAlignment;
    addr =  pLastSectHeader->PointerToRawData+ pLastSectHeader->SizeOfRawData;
    if(addr % align) addr += align - addr%align;
    psecth->PointerToRawData = addr;

    // adjust the section and imagesize 
    pFileHeader->NumberOfSections++;
    _inl_memcpy(&pSectHeader[sectNum], psecth, sizeof(IMAGE_SECTION_HEADER));
    align = pOptHeader->SectionAlignment;
    addr = psecth->VirtualAddress + psecth->Misc.VirtualSize;
    if(addr % align) addr += align - addr%align;
    pOptHeader->SizeOfImage = addr; 
    return pOptHeader->SizeOfImage;
}

#endif
#endif