B2HTARGET = tools/bin2header
CFLAGS = -Wall -O3

CC = gcc
PPU_CC = ppu-gcc
PPU_OBJCOPY = ppu-objcopy
PPU_CFLAGS = -DUSE_JIG


HEADERS = default_shellcode.h \
	default_payload.h \
	dump_lv2.h

PAYLOADS = default_shellcode.bin \
	shellcode_panic.bin \
	default_payload.bin \
	dump_lv2.bin

all: tools $(PAYLOADS) $(HEADERS)

tools:
	$(MAKE) -C tools

$(PAYLOADS): *.h.S

%.o : %.S
	$(PPU_CC) $(PPU_CFLAGS) -c $< -o $@
%.bin : %.o
	$(PPU_OBJCOPY) -O binary $< $@
%.h : %.bin $(B2HTARGET)
	$(PWD)/$(B2HTARGET) $< $@ $(*F)

# Target: clean project.
clean:
	$(MAKE) -C tools/ clean
	rm -f *~ $(PAYLOADS) $(HEADERS) $(B2HTARGET)

.PHONY: all clean tools