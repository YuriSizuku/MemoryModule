"""
   this file is for automaticly generate some shellcodes stub informations
   v0.1, developed by devseed
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
      push eax; // rvaaddr = 0
      lea eax, [ebx + exegetprocessaddress];
      mov eax, [eax]; // iat
      mov eax, [eax]; // iat->addr
      push eax; 
      lea eax, [ebx + exeloadlibrarya];
      mov eax, [eax]; // iat
      mov eax, [eax]; // iat->addr
      push eax;
      lea eax, [ebx + dllbase]; // dllbase addr
      mov eax, [eax]; // dllbase value
      push eax;
      call [ebx + memiatbind];
      add esp, 0x10;
      
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
      exeloadlibrarya: nop;nop;nop;nop;
      exegetprocessaddress: nop;nop;nop;nop;
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

      // bind iat
      lea r8, [rbx + exegetprocessaddress];
      mov r8, [r8]; // winpe_memfindexp
      lea rdx, [rbx + exeloadlibrarya];
      mov rdx, [rdx]; // iat
      mov rdx, [rdx]; // iat->addr
      lea rcx, [rbx + dllbase]; // dllbase addr
      mov rcx, [rcx]; // dllbase value
      call [rbx + memiatbind];
      
      // call dll oep, for dll entry
      xor r8, r8; // lpvReserved
      xor rdx, rdx; 
      inc rdx; // fdwReason, DLL_PROCESS_ATTACH
      lea rcx, [rbx + dllbase];
      mov rcx, [rcx]; // hinstDLL
      call [rbx+dlloepva];

      // jmp to origin oep
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
      exeloadlibrarya: nop;nop;nop;nop;nop;nop;nop;nop;
      exegetprocessaddress: nop;nop;nop;nop;nop;nop;nop;nop;
      """
   print("gen_oepinit_code64", code_str)
   payload, _ = ks.asm(code_str)
   print("payload: ", [hex(x) for x in payload])
   return payload
   pass

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
   membindiat_func = next(filter(
      lambda e : e.name == "winpe_membindiat", 
      pedll.exported_functions))
   membindiat_code = \
      pedll.get_content_from_virtual_address(
         membindiat_func.address, 0x200)
   # memiatshellcode = memiatshellcode[:memiatshellcode.index(0xC3)+1] # retn
   try: 
      memfindexp_func = next(filter(
         lambda e : e.name == "winpe_memfindexp", # x64 stdcall name
         pedll.exported_functions))
   except StopIteration:
      memfindexp_func = next(filter(
         lambda e : e.name == "_winpe_memfindexp@8", # x86 stdcall name
         pedll.exported_functions))
   memfindexp_code = \
      pedll.get_content_from_virtual_address(
         memfindexp_func.address, 0x200)

   # write shellcode to c source file
   with open(srcpath, "rb") as fp:
      srctext = fp.read().decode('utf8')
   _codetext = ",".join([hex(x) for x in oepinit_code])
   srctext = re.sub(r"g_oepinit_code(.+?)(\{0x90\})", 
      r"g_oepinit_code\1{" + _codetext +"}", srctext)
   _codetext = ",".join([hex(x) for x in membindiat_code])
   srctext = re.sub(r"g_membindiat_code(.+?)(\{0x90\})", 
      r"g_membindiat_code\1{" + _codetext +"}", srctext)
   _codetext = ",".join([hex(x) for x in memfindexp_code])
   srctext = re.sub(r"g_memfindexp_code(.+?)(\{0x90\})", 
      r"g_memfindexp_code\1{" + _codetext +"}", srctext)
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
   #debug()
   main()
   pass