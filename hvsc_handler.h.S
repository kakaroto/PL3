/*
 * hvsc_handler.S -- PS3 Jailbreak payload : hook for tracing hypercalls
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

hvsc_hook:
	mflr	%r0
	stdu	%r1, -0x100(%r1)
	std	%r3, 0x70(%r1)
	std	%r4, 0x78(%r1)
	std	%r5, 0x80(%r1)
	std	%r6, 0x88(%r1)
	std	%r7, 0x90(%r1)
	std	%r8, 0x98(%r1)
	std	%r9, 0xA0(%r1)
	std	%r10, 0xA8(%r1)
	std	%r11, 0xB0(%r1)
	std	%r25, 0xB8(%r1)
	std	%r31, 0xC0(%r1)
	std	%r0, 0xF0(%r1)

	/* do not log the pause hypercall, floods the network */
	cmplwi	%r11, 9
	beq	l_hvsc_done

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
	li	%r3, 1
	std	%r3, 0x48(%r31)

	MEM_BASE (%r31)
	LOAD_LABEL2 (%r3, %r31, eth_dma_region)
	ld	%r3, 0(%r3)
	LOAD_LABEL2 (%r4, %r31, buf)
	li	%r5, 0x50
	LOAD_LABEL2 (%r6, %r31, eth_proc)
	ld	%r6, 0(%r6)
	mtctr	%r6
	bctrl
	
l_hvsc_done:
	ld	%r3, 0x70(%r1)
	ld	%r4, 0x78(%r1)
	ld	%r5, 0x80(%r1)
	ld	%r6, 0x88(%r1)
	ld	%r7, 0x90(%r1)
	ld	%r8, 0x98(%r1)
	ld	%r9, 0xA0(%r1)
	ld	%r10, 0xA8(%r1)
	ld	%r11, 0xB0(%r1)
	ld	%r25, 0xB8(%r1)
	ld	%r31, 0xC0(%r1)

hvsc_call:
	sc	1
	
	ld	%r0, 0xF0(%r1)
	addi	%r1, %r1, 0x100
	mtlr	%r0
	blr