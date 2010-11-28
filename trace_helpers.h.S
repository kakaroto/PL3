/*
 * trace_helpers.S -- PS3 Jailbreak payload : helper functions for tracing hv/sc
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#ifndef __TRACE_HELPERS_H_S__
#define __TRACE_HELPERS_H_S__

store_regs:
	std	%r3, 0x70(%r1)
	std	%r4, 0x78(%r1)
	std	%r5, 0x80(%r1)
	std	%r6, 0x88(%r1)
	std	%r7, 0x90(%r1)
	std	%r8, 0x98(%r1)
	std	%r9, 0xA0(%r1)
	std	%r10, 0xA8(%r1)
	std	%r11, 0xB0(%r1)
	std	%r12, 0xB8(%r1)
	blr

load_regs:
	ld	%r3, 0x70(%r1)
	ld	%r4, 0x78(%r1)
	ld	%r5, 0x80(%r1)
	ld	%r6, 0x88(%r1)
	ld	%r7, 0x90(%r1)
	ld	%r8, 0x98(%r1)
	ld	%r9, 0xA0(%r1)
	ld	%r10, 0xA8(%r1)
	ld	%r11, 0xB0(%r1)
	ld	%r12, 0xB8(%r1)
	blr

send_trace:
	mflr	%r0
	stdu	%r1, -0x80(%r1)
	std	%r0, 0x70(%r1)
	std	%r31, 0x78(%r1)
	
	MEM_BASE (%r31)
	LOAD_LABEL2 (%r31, %r31, buf)
	std	%r3, 0x00(%r31)
	std	%r4, 0x08(%r31)
	std	%r5, 0x10(%r31)
	std	%r6, 0x18(%r31)
	std	%r7, 0x20(%r31)
	std	%r8, 0x28(%r31)
	std	%r9, 0x30(%r31)
	std	%r10, 0x38(%r31)
	std	%r11, 0x40(%r31)
	std	%r12, 0x48(%r31)

	MEM_BASE (%r31)
	LOAD_LABEL2 (%r3, %r31, buf)
	li	%r4, 0x50
	bl	send_eth
	
	ld	%r31, 0x78(%r1)
	ld	%r0, 0x70(%r1)
	addi	%r1, %r1, 0x80
	mtlr	%r0
	blr
buf:
	.space 0x50

#endif /* __TRACE_HELPERS_H_S__ */
