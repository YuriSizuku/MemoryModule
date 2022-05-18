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
LIBPREFIX?=./../../
ARCH?=i686
PREFIX?=./bin

CC:=clang
INCS:=-I$(LIBPREFIX)util/include
LIBDIRS:=
LIBS:=-luser32 -lgdi32
CFLAGS:=-ffunction-sections\
	-fdata-sections -std=c99
LDFLAGS:=

# arch config
ifeq ($(ARCH), x86_64) 
ARCH_POSTFIX:=64
LIBDIRS+=-L$(LIBPREFIX)thirdparty/lib64
CFLAGS+=-D_WIN64
ifdef DEBUG
BUILD_POSTFIX:=64d
else
BUILD_POSTFIX:=64
endif 
else # x86
ARCH_POSTFIX:=32
LIBDIRS+=-L$(LIBPREFIX)thirdparty/lib32
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
LIBWINPE_DEF:=-Wl,/DEF:libwinpe.def
else
ifneq (,$(findstring gcc, $(CC)))
LIBWINPE_DEF:=libwinpe.def 
endif
LIBWINPE_DEF:= 
endif

all: prepare\
	libwinpe\
	win_injectmemdll

clean:
	rm -rf $(PREFIX)/*libwinpe*
	rm -rf $(PREFIX)/*win_injectmemdll*

prepare:
	@if ! [ -d $(PREFIX) ]; then mkdir -p $(PREFIX); fi

libwinpe: libwinpe.c
	@echo \#\#building $@ ...
	$(CC) -shared $< $(LIBWINPE_DEF) \
		-o $(PREFIX)/$@$(BUILD_POSTFIX)$(DLL_EXT) \
		$(CFLAGS) $(LDFLAGS) $(INCS) $(LIBS) $(LIBDIRS)

win_injectmemdll: libwinpe
	@echo \#\#building $@ ...
	$(CC) $@.c \
		-o $(PREFIX)/$@$(BUILD_POSTFIX)$(EXE_EXT)\
		-llibwinpe$(BUILD_POSTFIX) $(LIBWINPE_DEF)\
		$(CFLAGS) $(LDFLAGS) $(INCS) $(LIBS) $(LIBDIRS) 

# this function only support clang
winpe_shellcode: libwinpe.c
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
	python winpe_shellcode.py \
		$(PREFIX)/$@32.obj \
		$(PREFIX)/$@64.obj \
		winpe_shellcode.h

.PHONY: all clean prepare libwinpe win_injectmemdll