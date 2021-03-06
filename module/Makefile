TARGET   = vpfs
OBJS     = module.o

LIBS = -ltaihen_stub -ltaihenForKernel_stub -ltaihenModuleUtils_stub \
  -lSceCpuForKernel_stub -lSceCpuForDriver_stub \
  -lSceSysmemForKernel_stub  -lSceSysmemForDriver_stub \
  -lSceSysclibForDriver_stub -lSceSblSsMgrForDriver_stub \
  -lSceIofilemgrForDriver_stub -lSceThreadmgrForDriver_stub \
  -lSceModulemgrForKernel_stub -lSceKernelSuspendForDriver_stub \
  -lSceNpDrmForDriver_stub

PREFIX  = arm-vita-eabi
CC      = $(PREFIX)-gcc
CFLAGS  = -Wl,-q -Wall -O3 -Wno-unused-variable -Wno-unused-but-set-variable -Wno-format -Wno-strict-aliasing -Wno-attributes -Wno-stringop-overflow -std=gnu99 -iquote -DNO_DYNAMIC_LINKER_STUFF -DNO_PTHREADS
LDFLAGS = -nostdlib -Wl,-z,nocopyreloc
ASFLAGS = $(CFLAGS)

all: $(TARGET).skprx

debug: CFLAGS += -DSHOW_DEBUG=1
debug: all

%.skprx: %.velf
	vita-make-fself -c $< $@

%.velf: %.elf
	vita-elf-create -e exports.yml $< $@

$(TARGET).elf: $(OBJS)
	$(CC) $(CFLAGS) $^ $(LIBS) -o $@ $(LDFLAGS)

install: $(TARGET).skprx
	@rm -f /g/data/vpfs.log
	@cp -v $(TARGET).skprx /g/tai/

clean:
	@rm -rf $(TARGET).skprx $(TARGET).velf $(TARGET).elf $(OBJS)
