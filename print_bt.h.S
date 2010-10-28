/*
 * print_bt.h.S -- Print the backtrace of a function
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#ifndef __PRINT_BT_H_S__
#define __PRINT_BT_H_S__

/*
 * print_backtrace:
 * @buffer: %r3 must contain a pointer to a buffer to be filled with the BT
 * @len: %r4 must contain the max size of the buffer
 *
 * This will use the stack to look for the call chain and print the backtrace
 * in @buffer up to the top of the backtrace or until @buffer is filled with
 * @len bytes
 * The format will be a packed list of 64bit pointers to the previous callers
 * in the backtrace, in reverse order (first pointer is the function calling
 * you, etc..)
 * The backtrace does not include the function that called print_backtrace.
 *
 */
print_backtrace:
	mr	%r5, %r1
l_print_backtrace_next:
	ld	%r5, 0(%r5)
	cmpldi	%r5, 0
	beq	l_print_backtrace_done
	ld	%r6, 0x10(%r5)
	std	%r6, 0(%r3)
	addi	%r3, %r3, 0x08
	addi	%r4, %r4, -0x08
	cmpldi	%r4, 0
	bne	l_print_backtrace_next
l_print_backtrace_done:
	blr

#endif /* __PRINT_BT_H_S__ */
