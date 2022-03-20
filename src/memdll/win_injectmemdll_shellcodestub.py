"""
   this file is for automaticly generate some shellcodes stub informations
   v0.3, developed by devseed
   
   history:
      v0.1, initial version
      v0.2, add more function for shellcode
      v0.3, x86 and x64 no need to use exe's LoadLibraryA
      v0.3.1, fix x64 attach dll crash by align stack with 0x10
"""
import re
import sys
import lief
from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64

def gen_oepinit_code32():
   ks = Ks(KS_ARCH_X86, KS_MODE_32)
   code_str = f"""
      // for relative address, get the base of addr
      call geteip; 
      lea ebx, [eax-5];

      // bind iat
      lea eax, [ebx + getprocessaddress];
      mov eax, [eax];
      push eax; 
      lea eax, [ebx + findloadlibrarya];
      call [eax]; 
      push eax;
      lea eax, [ebx + dllbase]; // dllbase addr
      mov eax, [eax]; // dllbase value
      push eax;
      call [ebx + memiatbind];
      add esp, 0xc;
      
      // call dll oep, for dll entry
      xor eax, eax; 
      push eax; // lpvReserved
      inc eax;
      push eax; // fdwReason, DLL_PROCESS_ATTACH
      lea eax, [ebx + dllbase];
      mov eax, [eax];
      push eax; // hinstDLL
      call [ebx+dlloepva];

      // jmp to origin oep
      jmp [ebx+exeoepva];

      geteip:
      mov eax, [esp]
      ret

      exeoepva: nop;nop;nop;nop;
      dllbase: nop;nop;nop;nop;
      dlloepva: nop;nop;nop;nop;
      memiatbind: nop;nop;nop;nop;
      findloadlibrarya: nop;nop;nop;nop;
      getprocessaddress: nop;nop;nop;nop;
      """
   print("gen_oepinit_code32", code_str)
   payload, _ = ks.asm(code_str)
   print("payload: ", [hex(x) for x in payload])
   return payload

def gen_oepinit_code64():
   ks = Ks(KS_ARCH_X86, KS_MODE_64)
   code_str = f"""
      // for relative address, get the base of addr
      call geteip; 
      lea rbx, [rax-5];
      push rcx;
      push rdx;
      push r8;
      push r9;
      sub rsp, 0x28; // this is for memory 0x10 align

      // bind iat
      lea rdx, [rbx + findloadlibrarya];
      call [rdx]; 
      mov rdx, rax; // arg2, loadlibraryas
      lea r8, [rbx + getprocessaddress];
      mov r8, [r8]; // arg3, getprocaddress
      lea rcx, [rbx + dllbase];
      mov rcx, [rcx]; // arg1, dllbase value
      call [rbx + memiatbind];
      
      // call dll oep, for dll entry
      xor r8, r8; // lpvReserved
      xor rdx, rdx; 
      inc rdx; // fdwReason, DLL_PROCESS_ATTACH
      lea rcx, [rbx + dllbase];
      mov rcx, [rcx]; // hinstDLL
      call [rbx+dlloepva];

      // jmp to origin oep
      add rsp, 0x28;
      pop r9;
      pop r8;
      pop rdx;
      pop rcx;
      jmp [rbx+exeoepva];

      geteip:
      mov rax, [rsp]
      ret

      exeoepva: nop;nop;nop;nop;nop;nop;nop;nop;
      dllbase: nop;nop;nop;nop;nop;nop;nop;nop;
      dlloepva: nop;nop;nop;nop;nop;nop;nop;nop;
      memiatbind: nop;nop;nop;nop;nop;nop;nop;nop;
      findloadlibrarya: nop;nop;nop;nop;nop;nop;nop;nop;
      getprocessaddress: nop;nop;nop;nop;nop;nop;nop;nop;
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
      "winpe_findloadlibrarya": 0, 
      "winpe_memGetProcAddress": 0}
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