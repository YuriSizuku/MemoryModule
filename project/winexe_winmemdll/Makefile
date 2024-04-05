# build example
# make winmemdll_shellcode CC=x86_64-w64-mingw32-gcc
# make winmemdll winmemdll_test CC=i686-w64-mingw32-gcc BUILD_TYPE=32d
# make winmemdll winmemdll_test CC=x86_64-w64-mingw32-gcc BUILD_TYPE=64d

# general config
CC:=gcc # clang (llvm-mingw), gcc (mingw-w64), tcc (x86 stdcall name has problem)
BUILD_TYPE:=32# 32, 32d, 64, 64d
BUILD_DIR:=build
INCS:=-I../../depend/reversetool/src
LIBS:=-luser32 -lgdi32 -lpsapi
CFLAGS:=-fPIC -std=c99 \
	-fvisibility=hidden \
	-ffunction-sections -fdata-sections
LDFLAGS:=-Wl,--enable-stdcall-fixup \
		 -Wl,--kill-at \
		 -Wl,--gc-sections \
		 -D_WIN32_WINNT=0X0400 \
		 -Wl,--subsystem,console:4.0 # compatible for xp

# build config
ifneq (,$(findstring 64, $(BUILD_TYPE)))
CFLAGS+=-m64
else
CFLAGS+=-m32
endif
ifneq (,$(findstring d, $(BUILD_TYPE)))
CFLAGS+=-g -D_DEBUG
else
CFLAGS+=-Os
endif
ifneq (,$(findstring tcc, $(CC)))
LDFLAGS= # tcc can not remove at at stdcall in i686
else
endif

all: prepare winmemdll

clean:
	@rm -rf $(BUILD_DIR)/*winmemdll*

prepare:
	@if ! [ -d $(BUILD_DIR) ]; then mkdir -p $(BUILD_DIR); fi

winmemdll: src/winmemdll.c
	@echo "## $@"
	$(CC) $< -o $(BUILD_DIR)/$@$(BUILD_TYPE).exe \
		$(INCS) $(LIBS) \
		$(CFLAGS) $(LDFLAGS) 

winmemdll_test: src/winmemdll_test.c
	@echo "## $@"
	$(CC) $< -o $(BUILD_DIR)/$@$(BUILD_TYPE).exe \
		$(INCS) $(LIBS) \
		$(CFLAGS) $(LDFLAGS) 

# only support llvm-mingw (tested 18.1), for building coff format
# sometimes nested force inline function might cause problems
winmemdll_shellcode: ../../depend/reversetool/project/windll_winpe/src/libwinpe.c
	@echo "## $@"
	# use -mno-sse for not making string as constant, sse makes array assign with ds:
	$(CC) -c -O3 -m32 -mno-sse $< -o $(BUILD_DIR)/$@32.o \
		-fPIC -ffunction-sections -fdata-sections \
		-Wno-undefined-inline \
		$(INCS)
	# mingw-w64 in linux, failed for findloadlibrarya, as make rax to fill string at wrong position
	$(CC) -c -O3 -m64 -mno-sse $< -o $(BUILD_DIR)/$@64.o \
		-fPIC -ffunction-sections -fdata-sections \
		-Wno-undefined-inline \
		$(INCS)
	python src/winmemdll_shellcode.py \
		$(BUILD_DIR)/$@32.o \
		$(BUILD_DIR)/$@64.o \
		src/winmemdll_shellcode.h

.PHONY: all clean prepare winmemdll winmemdll_test winmemdll_shellcode