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

#ifndef __MACRO_H_S__
#define __MACRO_H_S__

#include "config.h"

#include "firmware_symbols.h.S"
	
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
	bctrl;
	
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

// Allocate new memory and copy a function to it. R3 to R11 will be lost
// pl3_memcpy must be included!
#define ALLOC_AND_COPY_PROC(base_reg, function, size)	\
	li	%r3, size;				\
	li	%r4, 0x27;				\
	BRANCH_ABSOLUTE (%r6, alloc);			\
	mr	%r7, %r3;				\
	addi	%r4, base_reg, ADDR_IN_PAGE(function);	\
	li	%r5, size;				\
	bl	pl3_memcpy;				\
	mr	%r3, %r7;

#endif /* __MACRO_H_S */
