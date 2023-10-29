# memdll project, v0.2, developed by devseed
# you can use clang, gcc or tcc to compile
# recommond to use clang for better compatibile 
# usage: 
# make winpe_shellcode
# make ARCH=i686 CC=clang && make ARCH=i686 CC=clang DEBUG=1
# make ARCH=x86_64 CC=clang && make ARCH=x86_64 CC=clang DEBUG=1
# make ARCH=i686 CC=tcc && make ARCH=i686 CC=tcc DEBUG=1
# make ARCH=x86_64 CC=tcc && make ARCH=x86_64 CC=tcc DEBUG=1
# make ARCH=i686 CC=gcc && make ARCH=i686 CC=gcc DEBUG=1

# main config
ARCH?=i686
PREFIX?=./build

CC:=clang
INCS:=-I../../src/include -I../../depend/reversetool/src/c/include
LIBDIRS:=
LIBS:=-luser32 -lgdi32
CFLAGS:=-ffunction-sections\
	-fdata-sections -std=c99
LDFLAGS:=

# arch config
ifeq ($(ARCH), x86_64) 
ARCH_POSTFIX:=64
CFLAGS+=-D_WIN64
ifdef DEBUG
BUILD_POSTFIX:=64d
else
BUILD_POSTFIX:=64
endif 
else # x86
ARCH_POSTFIX:=32
ifdef DEBUG
BUILD_POSTFIX:=32d
else
BUILD_POSTFIX:=32
endif 
endif

# compiler config
ifneq (,$(findstring clang, $(CC)))
CFLAGS+=-target $(ARCH)-pc-windows-msvc \
	-D_CRT_SECURE_NO_DEPRECATE 
LDFLAGS+= -Wl,/OPT:REF\
	-Wno-undefined-inline
else  # mingw 
CFLAGS+=-m$(ARCH_POSTFIX) \
	-fPIC\
	-fvisibility=hidden\
	-fgnu89-inline\
	-DWINPE_NOASM 
ifneq (,$(findstring gcc, $(CC)))
LDFLAGS+=-lwinpthread \
	-static-libgcc \
	-static-libstdc++ \
	-Wl,-Bstatic,--whole-archive \
	-Wl,--no-whole-archive\
	-Wl,--gc-sections\
	-Wl,--enable-stdcall-fixup\
	-Wl,--kill-at
endif
endif

# optimization config
ifdef DEBUG
CFLAGS+=-g -D_DEBUG
else
CFLAGS+=-Os
endif 
LIBDIRS+=-L$(PREFIX) 

# system config
ifeq ($(shell echo ${OS}), Windows_NT)
DLL_EXT=.dll
EXE_EXT=.exe
else
DLL_EXT?=.dll
EXE_EXT?=.exe
endif

# other config
ifneq (,$(findstring clang, $(CC)))
else
ifneq (,$(findstring gcc, $(CC)))
endif
endif

all: prepare\
	winmemdll\
	winmemdll_test

clean:
	rm -rf $(PREFIX)/*win_injectmemdll*

prepare:
	@if ! [ -d $(PREFIX) ]; then mkdir -p $(PREFIX); fi

winmemdll: src/winmemdll.c
	@echo \#\#building $@ ...
	$(CC) $< -o $(PREFIX)/$@$(BUILD_POSTFIX)$(EXE_EXT) \
		$(LIBWINPE_DEF) $(CFLAGS) $(LDFLAGS) $(INCS) $(LIBS) $(LIBDIRS)

winmemdll_test: src/winmemdll_test.c
	@echo \#\#building $@ ...
	$(CC) $< -o $(PREFIX)/$@$(BUILD_POSTFIX)$(EXE_EXT) \
		$(LIBWINPE_DEF) $(CFLAGS) $(LDFLAGS) $(INCS) $(LIBS) $(LIBDIRS) 

# this function only support clang
winmemdll_shellcode: ..\..\depend\reversetool\project\windll_winpe\src\libwinpe.c
	@echo \#\#building $@ ...
	clang -c -Os $< \
		-o $(PREFIX)/$@32.obj \
		-target i686-pc-windows-msvc \
		-D _CRT_SECURE_NO_DEPRECATE\
		-ffunction-sections\
		-fdata-sections\
		-Wno-undefined-inline\
		$(INCS)
	clang -c -Os $< \
		-o $(PREFIX)/$@64.obj \
		-target x86_64-pc-windows-msvc \
		-D _CRT_SECURE_NO_DEPRECATE\
		-D_WIN64\
		-ffunction-sections\
		-fdata-sections\
		-Wno-undefined-inline\
		$(INCS)
	python src\winmemdll_shellcode.py \
		$(PREFIX)/$@32.obj \
		$(PREFIX)/$@64.obj \
		src\winmemdll_shellcode.h

.PHONY: all clean prepare winmemdll winmemdll_test winmemdll_shellcode