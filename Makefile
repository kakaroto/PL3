B2HTARGET = bin2header
CFLAGS = -Wall -O3

CC = gcc
PPU_CC = ppu-gcc
PPU_OBJCOPY = ppu-objcopy


HEADERS = default_shellcode.h \
	default_payload.h

PAYLOADS = default_shellcode.bin \
	shellcode_panic.bin \
	default_payload.bin \

all: $(PAYLOADS) $(HEADERS)

$(B2HTARGET): $(B2HTARGET).c

$(PAYLOADS): *.h.S

%.o : %.S
	$(PPU_CC) -c $< -o $@
%.bin : %.o
	$(PPU_OBJCOPY) -O binary $< $@
%.h : %.bin $(B2HTARGET)
	$(PWD)/$(B2HTARGET) $< $@ $(*F)

# Target: clean project.
clean:
	rm -f *~ $(PAYLOADS) $(HEADERS) $(B2HTARGET)

.PHONY: all clean