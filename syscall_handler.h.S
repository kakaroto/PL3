/*
 * syscall_handler.S -- PS3 Jailbreak payload : hook for tracing syscalls
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#ifndef __SYSCALL_HANDLER_H_S__
#define __SYSCALL_HANDLER_H_S__

syscall_handler:
	mflr	%r0
	stdu	%r1, -0x100(%r1)
	std	%r30, 0xC0(%r1)
	std	%r31, 0xC8(%r1)
	std	%r0, 0x110(%r1)

	li	%r31, 0

	/* do not log the mutex lock/unlock syscalls, floods the network */
	cmplwi	%r11, 102*8			// lock
	beq	l_syscall_handler_done
	cmplwi	%r11, 104*8			// unlock
	beq	l_syscall_handler_done
	cmplwi	%r11, 103*8			// trylock
	beq	l_syscall_handler_done

	li	%r31, 1

	bl	store_regs
	rldicl	%r11, %r11, 61, 3		// r11 is the sc_num*8
	mr	%r30, %r11
	li	%r12, 0
	bl	send_trace
	bl	load_regs

l_syscall_handler_done:
	mtctr	%r13
	bctrl

	cmplwi	%r31, 0
	beq	l_syscall_handler_return

	bl	store_regs
	mr	%r11, %r30
	li	%r12, 1
	bl	send_trace
	bl	load_regs

l_syscall_handler_return:
	ld	%r30, 0xC0(%r1)
	ld	%r31, 0xC8(%r1)
	ld	%r0, 0x110(%r1)
	addi	%r1, %r1, 0x100
	mtlr	%r0
	blr

#endif /* __SYSCALL_HANDLER_H_S__ */
