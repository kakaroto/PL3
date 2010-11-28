/*
 * print_debug.h.s -- PL3: Print debug string to eth.
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#ifndef __PRINT_DEBUG_H_S__
#define __PRINT_DEBUG_H_S__

#include "trace_helpers.h.S"

/*
print_tty_desc:
	QUAD_MEM2 (print_tty)
	
print_tty:
	mflr	%r0
	stdu	%r1, -0x90(%r1)
	std	%r24, 0x70(%r1)
	std	%r25, 0x78(%r1)
	//	0x80(%r1) == local buffer
	std	%r0, 0xA0(%r1)
	mr	%r24, %r4
	mr	%r25, %r5

	stw	%r5, 0x80(%r1)
	addi	%r3, %r1, 0x80
	mr	%r4, %r6
	li	%r5, 4
	bl	ABSOLUTE_MEM2(copy_to_user)	// Store 'written' = size

	mr	%r3, %r24
	addi	%r4, %r1, 0x80
	mr	%r5, %r25
	bl	ABSOLUTE_MEM2(alloc_and_copy_from_user)	// Alloc and copy buffer
	
	ld	%r3, 0x80(%r1)
	mr	%r4, %r25
	bl	send_eth		// send kernel-space buffer

	ld	%r3, 0x80(%r1)
	li	%r4, 0x27
	bl	ABSOLUTE_MEM2(free)			// Free the allocated buffer
	
	li	%r3, 0
	ld	%r0, 0xA0(%r1)
	ld	%r24, 0x70(%r1)
	ld	%r25, 0x78(%r1)
	addi	%r1, %r1, 0x90
	mtlr	%r0
	blr*/

print_hvsc107:
	mflr	%r0
	stdu	%r1, -0x100(%r1)
	std	%r29, 0xC0(%r1)
	std	%r30, 0xC8(%r1)
	std	%r31, 0xD0(%r1)
	std	%r0, 0xF0(%r1)

	bl	store_regs
	mr	%r30, %r11
	li	%r12, 0x10
	bl	send_trace
	bl	load_regs

	sc	1

	ld	%r29, 0xC0(%r1)
	ld	%r30, 0xC8(%r1)
	ld	%r31, 0xD0(%r1)
	ld	%r0, 0xF0(%r1)
	addi	%r1, %r1, 0x100
	mtlr	%r0
	blr
/*
print_debug:
	mflr	%r0
	stdu	%r1, -0x70(%r1)
	std	%r0, 0x80(%r1)

	bl	send_eth

	li	%r3, 0
	ld	%r0, 0x80(%r1)
	addi	%r1, %r1, 0x70
	mtlr	%r0
	blr
*/	
#endif /* __PRINT_DEBUG_H_S__ */
