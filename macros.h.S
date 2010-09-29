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

#include "config.h"

#ifdef FIRMWARE_3_41

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
#define patch_func1		0x0490AC
#define patch_func1_offset	0x34
#define patch_func2		0x04F07C
#define patch_func2_offset	0x2C
#define patch_func3		0x2aafc8
#define patch_func3_offset	0x0
#define patch_func4		0x04ed18
#define patch_func4_offset	0x0
#define patch_func5		0x0505d0
#define patch_func5_offset	0x0
#define patch_data1		0x3ba890
#define rtoc_entry_1		0xf08
#define rtoc_entry_2		-0x6a00

// Payload bases
#define MEM_BASE2 		(0x50B3C)
	
#define RESIDENT_PAYLOAD_MAXSIZE   (1296)
	
#elif defined(FIRMWARE_3_01)

#define memcpy 			0x77E84
#define memset 			
#define strcpy 			0x4AAC4	
#define strncmp	 		0x4AB18
#define strlen			0x4AAEC
#define strdup			 // FIXME: unsure of the name!
#define alloc 			0x5DF4C
#define free 			0x5E38C
#define add_kernel_module 	
#define syscall_table		0x2CFB40
#define get_device_descriptor	 // FIXME: unsure of the name!
#define unknown_func1		 // FIXME
#define unknown_func2		 // FIXME

#define patch_func1		0x468C4
#define patch_func1_offset	0x34
#define patch_func2		0x04C824
#define patch_func2_offset	0x2C
#define patch_func3		0x291DEC
#define patch_func3_offset	0x0
#define patch_func4		0x4C4C0
#define patch_func4_offset	0x0
#define patch_func5		0x04DCA8
#define patch_func5_offset	0x0
#define patch_data1		0x39C010
#define rtoc_entry_1		0xD00
#define rtoc_entry_2		-0x6B30
	
#define MEM_BASE2 		(0x04E214)
	
#define RESIDENT_PAYLOAD_MAXSIZE   (1296)
	
#endif

	
#define PAGE_SIZE 		0x1000

#ifdef USE_JIG
#define PAYLOAD_OFFSET_IN_PAGE 	0x20
#else
#define PAYLOAD_OFFSET_IN_PAGE 	0x38
#endif

#define PAYLOAD_SIZE		ADDR_IN_PAGE(payload_end)
#define RESIDENT_PAYLOAD_OFFSET	(overwritten_kernel_function)
#define RESIDENT_PAYLOAD_SIZE   (payload_end - RESIDENT_PAYLOAD_OFFSET)
#define ADDR_IN_PAGE(target) 	(PAYLOAD_OFFSET_IN_PAGE + (target) - payload_start)
#define ADDR_IN_MEM2(target) 	((target) - RESIDENT_PAYLOAD_OFFSET)

/* Addressing Macros */

// Absolute branching
#define ABSOLUTE_MEM2(target)	(target - (MEM_BASE2 + ADDR_IN_MEM2(.)))

// Dynamic macros to load a label into a register
#define MEM_BASE(dest) \
	li dest, 1; \
	rldicr dest, dest, 63, 0;
#define LOAD_LABEL(base, dest, source, address) \
	oris	dest, source, ((base) + (address))@h; \
	ori	dest, dest, ((base) + (address))@l;
#define LOAD_LABEL2(dest, source, address) \
	LOAD_LABEL(MEM_BASE2, dest, source, ADDR_IN_MEM2 (address))
#define LOADI_LABEL2(dest, address) \
	LOAD_LABEL2(dest, dest, address)

#define LOAD_MEM_BASE2(dest) \
	MEM_BASE (dest) \
	LOAD_LABEL (MEM_BASE2, dest, dest, 0)

// Add system calls. Use only in exploit_main because of registers used...
#define ADD_SYSCALL(source, ptr, num)			\
	LOAD_LABEL2 (%r3, source, ptr); 		\
	LOAD_ABS (%r4, source, syscall_table); 		\
	std	%r3, 0x08*num(%r4); 			\


// For loading an absolute value
#define LOAD_ABS(dest, source, address) LOAD_LABEL(0, dest, source, address)
#define LOADI_ABS(dest, address) LOAD_ABS(dest, dest, address)

// Absolute .quads
// HACK ALERT: the open toolchain bugs during compilation when trying to add
// a 'bignum' with address or MEM_BASE1.. so we split it here into two .long
// makes it easy since PPC is big endian.
#define QUAD_MEM2(address) \
	.long 0x80000000; \
	.long MEM_BASE2 + ADDR_IN_MEM2(address);

/* Patch Table Macros */
#define PATCH_INST(offset, instruction...) 		\
	.long offset; 					\
	instruction;
#define PATCH_DATA(offset, data...) 			\
	.long offset; 					\
	.long data;
#define PATCH_BRANCH(offset, op, target) 		\
	.long offset; 					\
	op ((target) - (offset));
#define PATCH_BRANCH_MEM2(offset, op, target) 		\
	PATCH_BRANCH (offset, op, (MEM_BASE2 + ADDR_IN_MEM2(target)));

#define BRANCH_ABSOLUTE(dest, target) 	\
	MEM_BASE (dest);		\
	oris	dest, dest, target@h; 	\
	ori	dest, dest, target@l; 	\
	mtctr	dest;			\
	bctrl
	
#define GET_CURRENT_PAGE(temp, dest)	\
	bl	get_current_page;	\
	b	got_current_page;	\
get_current_page:			\
	mflr	dest;			\
	blr;				\
got_current_page:			\
	li	temp, 0xfff;		\
	nor	temp, temp, temp;	\
	and	dest, dest, temp;

#define PANIC()				\
        li      %r3, 0;			\
        li      %r11, 255;		\
        sc      1;
