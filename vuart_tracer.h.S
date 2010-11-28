/*
 * vuart_tracer.S -- PS3 Jailbreak payload : tracing read/write vuart hypercalls
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#ifndef __VUART_TRACER_H_S__
#define __VUART_TRACER_H_S__

#include "trace_helpers.h.S"

hvsc_handler:
	mflr	%r0
	stdu	%r1, -0x100(%r1)
	std	%r29, 0xC0(%r1)
	std	%r30, 0xC8(%r1)
	std	%r31, 0xD0(%r1)
	// Some functions calling hvsc do not modify the stack, so writing to
	// 0x10(%r1) means we overwrite their own stored LR. So we need to store
	// our LR inside the allocated stack. It breaks the 'backtrace' but
	// we have no choice
	std	%r0, 0xF0(%r1)

	li	%r31, 0

	
	cmplwi	%r11, 162		// lv1_read_virtual_uart
	beq	l_hvsc_handler_read_uart
	cmplwi	%r11, 163		// lv1_write_virtual_uart
	beq	l_hvsc_handler_write_uart
	b	hvsc_call

l_hvsc_handler_write_uart:
	bl	store_regs
	mr	%r3, %r4
	mr	%r4, %r5
	bl	send_buffer
	bl	load_regs
	b	l_hvsc_handler_continue
l_hvsc_handler_read_uart:
	mr	%r29, %r4
l_hvsc_handler_continue:
	li	%r31, 1

	bl	store_regs
	mr	%r30, %r11
	li	%r12, 0x10
	cmplwi	%r11, 162
	bl	send_trace
	bl	load_regs
	
hvsc_call:
	sc	1

	cmplwi	%r31, 0
	beq	l_hvsc_handler_return
	
	bl	store_regs
	mr	%r11, %r30
	li	%r12, 0x11
	bl	send_trace
	bl	load_regs
	
	cmplwi	%r30, 162
	bne	l_hvsc_handler_return
	
	bl	store_regs
	mr	%r3, %r29
	bl	send_buffer
	bl	load_regs

l_hvsc_handler_return:
	ld	%r29, 0xC0(%r1)
	ld	%r30, 0xC8(%r1)
	ld	%r31, 0xD0(%r1)
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
	LOAD_LABEL2 (%r3, %r31, buf)
	li	%r4, 0x50
	bl	send_eth

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

#endif /* __VUART_TRACER_H_S__ */
