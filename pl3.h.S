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

#ifndef __PL3_H_S__
#define __PL3_H_S__

#include "config.h"

#include "firmware_symbols.h.S"
	
#define PAGE_SIZE 		0x1000

#ifdef USE_JIG
#define PAYLOAD_OFFSET_IN_PAGE 	0x20
#else
#define PAYLOAD_OFFSET_IN_PAGE 	0x38
#endif

#define RESIDENT_AREA_OFFSET	(resident_area_start)
#define RESIDENT_AREA_SIZE	(resident_area_end - resident_area_start)
#define ADDR_IN_PAGE(target) 	(PAYLOAD_OFFSET_IN_PAGE + (target) - payload_entry)
#define ADDR_IN_MEM2(target) 	((target) - RESIDENT_AREA_OFFSET)

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

#define DEFINE_FUNC_PTR(function)				\
function##_ptr:							\
	.quad	0;						\
function:							\
	mflr	%r0;						\
	stdu	%r1, -0x80(%r1);				\
	std	%r31, 0x70(%r1);				\
	std	%r0, 0x90(%r1);					\
	BRANCH_FUNC_PTR(%r31, function);			\
	ld	%r31, 0x70(%r1);				\
	ld	%r0, 0x90(%r1);					\
	addi	%r1, %r1, 0x80;					\
	mtlr	%r0;						\
	blr;

#define BRANCH_FUNC_PTR(dest, function)				\
	MEM_BASE (dest);					\
	LOAD_LABEL2 (dest, dest, function ##_ptr);		\
	ld	dest, 0(dest);					\
	mtctr	dest;						\
	bctrl;

#define LOAD_FUNC_PTR(function)						\
	ALLOC_AND_COPY_PROC(%r31, function ##_start, 			\
				(function ## _end - function##_start));	\
	LOAD_LABEL2 (%r6, %r30, function ##_ptr);			\
	std	%r3, 0(%r6);

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

#define ALLOCATE_BUFFER(base, variable, size)	\
	li      %r3, size;			\
	li      %r4, 0x27;			\
	BRANCH_ABSOLUTE(%r5, alloc);		\
	LOAD_LABEL2 (%r4, base, variable);	\
	std     %r3, 0(%r4);

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

// Copy functions that need to stay resident in memory to MEM_BASE2
#define COPY_RESIDENT_AREA(base, page)					\
	LOAD_LABEL (MEM_BASE2, %r3, base, 0);				\
	addi	%r4, page, ADDR_IN_PAGE(RESIDENT_AREA_OFFSET);		\
	li	%r5, RESIDENT_AREA_SIZE;				\
	bl	pl3_memcpy;						\

#define RESIDENT_AREA_START()				\
.align 4;						\
resident_area_start:					\
	li	%r3, 1;					\
	blr;

#define RESIDENT_AREA_END()				\
resident_area_end:					\
.org RESIDENT_AREA_OFFSET + RESIDENT_AREA_MAXSIZE

.org 0
// Position 0x20 in the page
payload_entry:
	b	payload_main

#include "pl3_memcpy.h.S"

#endif /* __PL3_H_S__ */
