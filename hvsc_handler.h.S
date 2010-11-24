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
	std	%r30, 0xC0(%r1)
	std	%r31, 0xC8(%r1)
	// Some functions calling hvsc do not modify the stack, so writing to
	// 0x10(%r1) means we overwrite their own stored LR. So we need to store
	// our LR inside the allocated stack. It breaks the 'backtrace' but
	// we have no choice
	std	%r0, 0xF0(%r1)

	li	%r31, 0

	/* do not log some hypercall that just flood the network */
	cmplwi	%r11, 9		// lv1_pause
	beq	hvsc_call
	cmplwi	%r11, 30	// lv1_end_of_interrupt_ext
	beq	hvsc_call
	cmplwi	%r11, 31	// lv1_did_update_interrupt_mask
	beq	hvsc_call
	cmplwi	%r11, 24	// lv1_send_event_locally
	beq	hvsc_call

	li	%r31, 1

	bl	store_regs
	mr	%r30, %r11
	li	%r12, 0x10
	bl	send_trace
	bl	load_regs
	
hvsc_call:
	sc	1

	cmplwi	%r31, 0
	beq	l_hvsc_return
	
	bl	store_regs
	mr	%r11, %r30
	li	%r12, 0x11
	bl	send_trace
	bl	load_regs

l_hvsc_return:
	ld	%r30, 0xC0(%r1)
	ld	%r31, 0xC8(%r1)
	ld	%r0, 0xF0(%r1)
	addi	%r1, %r1, 0x100
	mtlr	%r0
	blr


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
