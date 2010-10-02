B2HTARGET = tools/bin2header
CFLAGS = -Wall -O3

CC = gcc
PPU_CC = ppu-gcc
PPU_OBJCOPY = ppu-objcopy
PPU_CFLAGS =

# This isn't enough, you must also add rules for the filename_fw with the -D define
SUPPORTED_FIRMWARES = 3.41 3.15 3.01

PAYLOADS = shellcode_egghunt.bin \
	shellcode_panic.bin \
	dump_lv2.bin

FW_PAYLOADS = \
	default_payload.bin \
	payload_dump_elfs.bin

FIRMWARES_2=$(SUPPORTED_FIRMWARES:2.%=2_%)
FIRMWARES=$(FIRMWARES_2:3.%=3_%)
FW_PAYLOADS_EXT = $(foreach fw,$(FIRMWARES), \
	$(foreach pl,$(FW_PAYLOADS),$(pl:%.bin=%_$(fw).bin)))
ALL_PAYLOADS = $(PAYLOADS) $(FW_PAYLOADS_EXT)

HEADERS = $(ALL_PAYLOADS:%.bin=%.h)

all: tools $(ALL_PAYLOADS) $(HEADERS)

tools:
	$(MAKE) -C tools

$(ALL_PAYLOADS): *.h.S config.h

%_3_01.o : %.S
	$(PPU_CC) $(PPU_CFLAGS) -DFIRMWARE_3_01 -c $< -o $@

%_3_15.o : %.S
	$(PPU_CC) $(PPU_CFLAGS) -DFIRMWARE_3_15 -c $< -o $@

%_3_41.o : %.S
	$(PPU_CC) $(PPU_CFLAGS) -DFIRMWARE_3_41 -c $< -o $@

%.o : %.S
	$(PPU_CC) $(PPU_CFLAGS) -c $< -o $@
%.bin : %.o
	$(PPU_OBJCOPY) -O binary $< $@
%.h : %.bin $(B2HTARGET)
	$(PWD)/$(B2HTARGET) $< $@ $(*F)

# Target: clean project.
clean:
	$(MAKE) -C tools/ clean
	rm -f *~ *.bin $(ALL_PAYLOADS) $(HEADERS) $(B2HTARGET)

.PHONY: all clean tools
