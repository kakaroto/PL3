/*
 * trace_helpers.S -- PS3 Jailbreak payload : helper functions for tracing hv/sc
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */
	
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
	LOAD_LABEL2 (%r3, %r31, eth_dma_region)
	ld	%r3, 0(%r3)
	LOAD_LABEL2 (%r4, %r31, buf)
	li	%r5, 0x50
	LOAD_LABEL2 (%r6, %r31, eth_proc)
	ld	%r6, 0(%r6)
	mtctr	%r6
	bctrl
	
	ld	%r31, 0x78(%r1)
	ld	%r0, 0x70(%r1)
	addi	%r1, %r1, 0x80
	mtlr	%r0
	blr
buf:
	.space 0x50


send_buffer:
	mflr	%r0
	stdu	%r1, -0xA0(%r1)
	std	%r0, 0x70(%r1)
	std	%r28, 0x78(%r1)
	std	%r29, 0x80(%r1)
	std	%r30, 0x88(%r1)
	std	%r31, 0x90(%r1)
	
	mr	%r30, %r3
	mr	%r29, %r4

	li	%r28, 0x100

l_send_buffer_next:
	// Switch to realmode
        mfmsr %r0
        li %r10, 0x10
        andc %r0, %r0, %r10
        mtmsrd %r0, 0

	MEM_BASE (%r31)
	LOAD_LABEL2 (%r31, %r31, buf)
	ld	%r3, 0x00(%r30)
	std	%r3, 0x00(%r31)
	ld	%r3, 0x08(%r30)
	std	%r3, 0x08(%r31)
	ld	%r3, 0x10(%r30)
	std	%r3, 0x10(%r31)
	ld	%r3, 0x18(%r30)
	std	%r3, 0x18(%r31)
	ld	%r3, 0x20(%r30)
	std	%r3, 0x20(%r31)
	ld	%r3, 0x28(%r30)
	std	%r3, 0x28(%r31)
	ld	%r3, 0x30(%r30)
	std	%r3, 0x30(%r31)
	ld	%r3, 0x38(%r30)
	std	%r3, 0x38(%r31)
	
	std	%r29, 0x40(%r31)
	std	%r28, 0x48(%r31)

	// Remove realmode
        ori %r0, %r0, 0x10
        mtmsrd %r0, 0
	
	MEM_BASE (%r31)
	LOAD_LABEL2 (%r3, %r31, eth_dma_region)
	ld	%r3, 0(%r3)
	LOAD_LABEL2 (%r4, %r31, buf)
	li	%r5, 0x50
	LOAD_LABEL2 (%r6, %r31, eth_proc)
	ld	%r6, 0(%r6)
	mtctr	%r6
	bctrl

	addi	%r28, %r28, 1
	addi	%r30, %r30, 0x40
	cmpldi	%r29, 0x40
	addi	%r29, %r29, -0x40
	bgt	l_send_buffer_next
	
	ld	%r28, 0x78(%r1)
	ld	%r29, 0x80(%r1)
	ld	%r30, 0x88(%r1)
	ld	%r31, 0x90(%r1)
	ld	%r0, 0x70(%r1)
	addi	%r1, %r1, 0xA0
	mtlr	%r0
	blr
