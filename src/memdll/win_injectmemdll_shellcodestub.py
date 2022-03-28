"""
this file is for automaticly generate some shellcodes stub informations
    v0.3.3, developed by devseed
"""
import re
import sys
import lief
from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64

def gen_oepinit_code32():
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    code_str = f"""
    // for relative address, get the base of addr
    call getip; 
    lea ebx, [eax-5];

    // get the imagebase
    mov eax, 0x30; // to avoid relative addressing
    mov edi, dword ptr fs:[eax]; //peb
    mov edi, [edi + 0ch]; //ldr
    mov edi, [edi + 14h]; //InMemoryOrderLoadList, this
    mov edi, [edi -8h + 18h]; //this.DllBase

    // get loadlibrarya, getprocaddress
    mov eax, [ebx + findloadlibrarya];
    add eax, edi;
    call eax;
    mov [ebx + findloadlibrarya], eax;
    mov eax, [ebx + findgetprocaddress];
    add eax, edi;
    call eax;
    mov [ebx + findgetprocaddress], eax;

    // reloc
    mov eax, [ebx + dllrva];
    add eax, edi;
    push eax;
    push eax;
    mov eax, [ebx + memrelocrva];
    add eax, edi;
    call eax;

    // bind iat
    mov eax, [ebx + findgetprocaddress]; 
    push eax; // arg3, getprocaddress
    mov eax, [ebx + findloadlibrarya]; 
    push eax; // arg2, loadlibraryas
    mov eax, [ebx + dllrva]; 
    add eax, edi; 
    push eax; // arg1, dllbase value
    mov eax, [ebx + membindiatrva];
    add eax, edi
    call eax;

    // bind tls
    xor eax, eax;
    inc eax; 
    push eax; // arg2, reason for tls
    mov eax, [ebx + dllrva] 
    add eax, edi; 
    push eax; // arg1, dllbase
    mov eax, [ebx + membindtlsrva];
    add eax, edi;
    call eax;

    // call dll oep, for dll entry
    xor eax, eax; 
    push eax; // lpvReserved
    inc eax; 
    push eax; // fdwReason, DLL_PROCESS_ATTACH
    mov eax, [ebx + dllrva]; 
    add eax, edi; 
    push eax; // hinstDLL
    mov eax, [ebx + dlloeprva];
    add eax, edi; 
    call eax;

    // jmp to origin oep
    mov eax, [ebx+exeoeprva];
    add eax, edi;
    jmp eax;

    getip:
    mov eax, [esp]
    ret

    exeoeprva: nop;nop;nop;nop;
    dllrva: nop;nop;nop;nop;
    dlloeprva: nop;nop;nop;nop;
    memrelocrva: nop;nop;nop;nop;
    membindiatrva: nop;nop;nop;nop;
    membindtlsrva: nop;nop;nop;nop;
    findloadlibrarya: nop;nop;nop;nop;
    findgetprocaddress: nop;nop;nop;nop;
    """
    print("gen_oepinit_code32", code_str)
    payload, _ = ks.asm(code_str)
    print("payload: ", [hex(x) for x in payload])
    return payload

def gen_oepinit_code64():
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    code_str = f"""
    // for relative address, get the base of addr
    call getip; 
    lea rbx, [rax-5];
    push rcx;
    push rdx;
    push r8;
    push r9;
    sub rsp, 0x28; // this is for memory 0x10 align

    // get the imagebase
    mov rax, 0x60; // to avoid relative addressing
    mov rdi, qword ptr gs:[rax]; //peb
    mov rdi, [rdi + 18h]; //ldr
    mov rdi, [rdi + 20h]; //InMemoryOrderLoadList, this
    mov rdi, [rdi -10h + 30h]; //this.DllBase

    // get loadlibrarya, getprocaddress
    mov rax, [rbx + findloadlibrarya];
    add rax, rdi;
    call rax;
    mov [rbx + findloadlibrarya], rax;
    mov rax, [rbx + findgetprocaddress];
    add rax, rdi;
    call rax;
    mov [rbx + findgetprocaddress], rax;

    // reloc
    mov rcx, [rbx + dllrva];
    add rcx, rdi;
    mov rdx, rcx;
    mov rax, [rbx + memrelocrva];
    add rax, rdi;
    call rax;

    // bind iat
    mov r8, [rbx + findgetprocaddress]; // arg3, getprocaddress
    mov rdx, [rbx + findloadlibrarya]; // arg2, loadlibraryas
    mov rcx, [rbx + dllrva]; 
    add rcx, rdi; // arg1, dllbase value
    mov rax, [rbx + membindiatrva];
    add rax, rdi
    call rax;

    // bind tls
    xor rdx, rdx;
    inc rdx; // argc, reason for tls
    mov rcx, [rbx + dllrva] 
    add rcx, rdi; // arg1, dllbase
    mov rax, [rbx + membindtlsrva];
    add rax, rdi;
    call rax;
    
    // call dll oep, for dll entry
    xor r8, r8; // lpvReserved
    xor rdx, rdx; 
    inc rdx; // fdwReason, DLL_PROCESS_ATTACH
    mov rcx, [rbx + dllrva]; 
    add rcx, rdi; // hinstDLL
    mov rax, [rbx + dlloeprva];
    add rax, rdi; 
    call rax;

    // jmp to origin oep
    add rsp, 0x28;
    pop r9;
    pop r8;
    pop rdx;
    pop rcx;
    mov rax, [rbx+exeoeprva];
    add rax, rdi;
    jmp rax;

    getip:
    mov rax, [rsp]
    ret

    exeoeprva: nop;nop;nop;nop;nop;nop;nop;nop;
    dllrva: nop;nop;nop;nop;nop;nop;nop;nop;
    dlloeprva: nop;nop;nop;nop;nop;nop;nop;nop;
    memrelocrva: nop;nop;nop;nop;nop;nop;nop;nop;
    membindiatrva: nop;nop;nop;nop;nop;nop;nop;nop;
    membindtlsrva: nop;nop;nop;nop;nop;nop;nop;nop;
    findloadlibrarya: nop;nop;nop;nop;nop;nop;nop;nop;
    findgetprocaddress: nop;nop;nop;nop;nop;nop;nop;nop;
    """
    print("gen_oepinit_code64", code_str)
    payload, _ = ks.asm(code_str)
    print("payload: ", [hex(x) for x in payload])
    return payload

def inject_shellcodestubs(srcpath, libwinpepath, targetpath):
    pedll = lief.parse(libwinpepath)
    pedll_oph = pedll.optional_header

    # generate oepint shellcode
    if pedll_oph.magic == lief.PE.PE_TYPE.PE32_PLUS:
        oepinit_code = gen_oepinit_code64()
        pass
    elif pedll_oph.magic == lief.PE.PE_TYPE.PE32:
        oepinit_code = gen_oepinit_code32()
        pass
    else:
        print("error invalid pe magic!", pedll_oph.magic)
        return
    # if len(oepinit_code) < 0x200: oepinit_code.extend([0x00] * (0x200 - len(oepinit_code)))

    # find necessary functions
    FUNC_SIZE =0x400
    codes = {"winpe_memreloc": 0, 
        "winpe_membindiat": 0, 
        "winpe_membindtls": 0,
        "winpe_findloadlibrarya": 0, 
        "winpe_findgetprocaddress": 0}
    for k in codes.keys():
        func = next(filter(lambda e : e.name == k, 
            pedll.exported_functions))
        codes[k] = pedll.get_content_from_virtual_address(
            func.address, FUNC_SIZE)
    codes['winpe_oepinit'] = oepinit_code

    # write shellcode to c source file
    with open(srcpath, "rb") as fp:
        srctext = fp.read().decode('utf8')
    for k, v in codes.items():
        k = k.replace("winpe_", "")
        _codetext = ",".join([hex(x) for x in v])
        srctext = re.sub("g_" + k + r"_code(.+?)(\{0x90\})", 
            "g_" + k  +  r"_code\1{" + _codetext +"}", srctext)
    with open(targetpath, "wb") as fp:
        fp.write(srctext.encode('utf8'))

def debug():
    inject_shellcodestubs("win_injectmemdll.c", 
        "./bin/libwinpe64.dll", 
        "./bin/_64win_injectmemdll.c")
    pass

def main():
    if len(sys.argv) < 4:
        print("win_injectmemdll_shellcodestub srcpath libwinpedllpath outpath")
        return
    inject_shellcodestubs(sys.argv[1], 
        sys.argv[2].replace("d.dll", ".dll"), sys.argv[3])
    pass

if __name__ == "__main__":
    # debug()
    main()
    pass

"""
history:
v0.1, initial version
v0.2, add more function for shellcode
v0.3, x86 and x64 no need to use exe's LoadLibraryA
v0.3.1, fix x64 attach dll crash by align stack with 0x10
v0.3.2, add support for ordinal iat and tls 
v0.3.3, add support for aslr
"""