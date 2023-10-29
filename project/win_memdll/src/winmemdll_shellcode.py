import sys
from keystone import *

sys.path.append("../../depend/reversetool/src/py")
import libshellcode as shellcode

def gen_oepinit_code32():
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    code_str = f"""
    // for relative address, get the base of addr
    push ebx;
    call getip; 
    lea ebx, [eax-6];

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
    mov eax, [ebx + exeoeprva];
    add eax, edi;
    pop ebx;
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
    # print("gen_oepinit_code32", code_str)
    payload, _ = ks.asm(code_str)
    # print("payload: ", [hex(x) for x in payload])
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
    # print("gen_oepinit_code64", code_str)
    payload, _ = ks.asm(code_str)
    # print("payload: ", [hex(x) for x in payload])
    return payload

def gen_oepinitstatic_code32():
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    code_str = f"""
    push eax
    push ebx
    call getip; 
    lea ebx, [eax-7];
    mov eax, [ebx + dllnameva];
    push eax;
    mov eax, [ebx + loadlibraryva]
    call eax;
    mov eax, [ebx + retva];
    mov edi, eax;
    pop ebx;
    pop eax;
    jmp edi;

    getip:
    mov eax, [esp]
    ret
    
    retva:nop;nop;nop;nop;
    dllnameva:nop;nop;nop;nop;
    loadlibraryva:nop;nop;nop;nop;
    """
    payload, _ = ks.asm(code_str)
    return payload

def gen_oepinitstatic_code64():
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    code_str = f"""
    push rax;
    push rbx;
    push rcx;
    push rdx;
    call getip; 
    lea rbx, [rax-9];
    sub rsp, 0x28;
    mov rcx, [rbx + dllnameva];
    mov rax, [rbx + loadlibraryva]
    call rax;
    add rsp, 0x28;
    mov rax, [rbx + retva];
    mov r15, rax;
    pop rdx;
    pop rcx;
    pop rbx;
    pop rax;
    jmp r15;

    getip:
    mov rax, [rsp];
    ret;
    
    retva:nop;nop;nop;nop;nop;nop;nop;nop;
    dllnameva:nop;nop;nop;nop;nop;nop;nop;nop;
    loadlibraryva:nop;nop;nop;nop;nop;nop;nop;nop;
    """
    payload, _ = ks.asm(code_str)
    return payload

def make_winpe_shellcode(libwinpepath, postfix):
    codes = dict()
    libwinpe = shellcode.extract_coff(libwinpepath)
    # for static inject dll into exe oepinit code
    codes[f'g_oepinit_code{postfix}'] = eval(f'gen_oepinit_code{postfix}()')
    # for dynamic inject dll into exe oepint code 
    codes[f'g_oepinitstatic_code{postfix}'] = eval(f'gen_oepinitstatic_code{postfix}()')
    for name, code in libwinpe.items():
        newname = f"g_{name.replace('winpe_', '').lower()}_code{postfix}"
        codes[newname] = code
    return codes

def debug():
    gen_oepinitstatic_code64()
    codes = shellcode.extract_coff("./bin/winpe_shellcode32.obj")
    pass

def main():
    codes = dict()
    codes.update(make_winpe_shellcode(sys.argv[1], '32'))
    codes.update(make_winpe_shellcode(sys.argv[2], '64')) 
    shellcode.write_shellcode_header(codes, outpath=sys.argv[3])

if __name__ == '__main__':
    # debug()
    main()
    pass