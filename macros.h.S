/*
 * macros.h -- PS3 Jailbreak payload macros
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 * Copyright (C) Aaron Lindsay (Aaron')
 * Copyright (C) (subdub)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */


/* Common Symbols */
#define memcpy 			0x7c01c
#define memset 			0x4d144
#define strcpy 			0x4d2f0
#define strncmp	 		0x4d344
#define strlen			0x4d318
#define strdup			0x1b3b3c // FIXME: unsure of the name!
#define alloc 			0x62088
#define free 			0x624c8
#define add_kernel_module 	0xd22d8
#define syscall_table		0x2eb128
#define get_device_descriptor	0xd2998 // FIXME: unsure of the name!
#define unknown_func1		0xd29c4 // FIXME
#define unknown_func2		0xd292c // FIXME

#define PAGE_SIZE 		0x1000
#define PAYLOAD_OFFSET_IN_PAGE 	0x20
#define PAYLOAD_SIZE		ADDR_IN_PAGE(payload_end)
#define RESIDENT_PAYLOAD_OFFSET	(overwritten_kernel_function)
#define RESIDENT_PAYLOAD_SIZE   (payload_end - RESIDENT_PAYLOAD_OFFSET)
#define ADDR_IN_PAGE(target) 	(PAYLOAD_OFFSET_IN_PAGE + (target) - payload_start)
#define ADDR_IN_MEM1(target) 	(ADDR_IN_PAGE(target))
#define ADDR_IN_MEM2(target) 	((target) - RESIDENT_PAYLOAD_OFFSET)

/* Addressing Macros */
// Payload bases
#define MEM_BASE1 		(0x700000)
#define MEM_BASE2 		(0x50B3C)

// Absolute branching
#define ABSOLUTE_MEM1(target)	(target - (MEM_BASE1 + ADDR_IN_MEM1(.)))
#define ABSOLUTE_MEM2(target)	(target - (MEM_BASE2 + ADDR_IN_MEM2(.)))

// Dynamic macros to load a label into a register
#define MEM_BASE(dest) \
	li dest, 1; \
	rldicr dest, dest, 63, 0;
#define LOAD_LABEL(base, dest, source, address) \
	oris	dest, source, ((base) + (address))@h; \
	ori	dest, dest, ((base) + (address))@l;
#define LOAD_LABEL1(dest, source, address) \
	LOAD_LABEL(MEM_BASE1, dest, source, ADDR_IN_MEM1 (address))
#define LOAD_LABEL2(dest, source, address) \
	LOAD_LABEL(MEM_BASE2, dest, source, ADDR_IN_MEM2 (address))
#define LOADI_LABEL1(dest, address) \
	LOAD_LABEL1(dest, dest, address)
#define LOADI_LABEL2(dest, address) \
	LOAD_LABEL2(dest, dest, address)

#define LOAD_MEM_BASE1(dest) \
	MEM_BASE (dest) \
	oris	dest, dest, MEM_BASE1@h;
#define LOAD_MEM_BASE2(dest) \
	MEM_BASE (dest) \
	LOAD_LABEL (MEM_BASE2, dest, dest, 0)

// Add system calls. Use only in exploit_main because of registers used...
#define ADD_SYSCALL(ptr, num) \
	LOAD_LABEL2 (%r3, %r31, ptr) \
	LOAD_ABS (%r4, %r31, syscall_table) \
	std	%r3, 0x08*num(%r4) \


// For loading an absolute value
#define LOAD_ABS(dest, source, address) LOAD_LABEL(0, dest, source, address)
#define LOADI_ABS(dest, address) LOAD_ABS(dest, dest, address)

// Absolute .quads
// HACK ALERT: the open toolchain bugs during compilation when trying to add
// a 'bignum' with address or MEM_BASE1.. so we split it here into two .long
// makes it easy since PPC is big endian.
#define QUAD_MEM1(address) \
	.long 0x80000000; \
	.long MEM_BASE1 + ADDR_IN_MEM1(address);
#define QUAD_MEM2(address) \
	.long 0x80000000; \
	.long MEM_BASE2 + ADDR_IN_MEM2(address);

/* Patch Table Macros */
#define PATCH_INST(offset, instruction...) .long offset; instruction
#define PATCH_DATA(offset, data...) .long offset; .long data
#define PATCH_BRANCH(offset, op, target) .long offset; op (target - offset)
#define PATCH_BRANCH_MEM2(offset, op, target) \
	PATCH_BRANCH (offset, op, MEM_BASE2 + ADDR_IN_MEM2(target))
