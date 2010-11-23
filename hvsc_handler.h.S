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
	bl	store_regs
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
	beq	l_hvsc_done
	cmplwi	%r11, 24	// lv1_send_event_locally
	beq	l_hvsc_done
	cmplwi	%r11, 30	// lv1_end_of_interrupt_ext
	beq	l_hvsc_done
	cmplwi	%r11, 31	// lv1_did_update_interrupt_mask
	beq	l_hvsc_done

	li	%r31, 1

	li	%r12, 0x10
	bl	send_trace
	
l_hvsc_done:
	bl	load_regs
	mr	%r30, %r11
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