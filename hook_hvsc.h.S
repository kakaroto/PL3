/*
 * hook_hvsc.h.s -- PL3 - Hooks all hvsc instructions 
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#ifndef __HOOK_HVSC_H_S__
#define __HOOK_HVSC_H_S__

hook_hvsc:
	mflr	%r0
	stdu	%r1, -0x80(%r1)
	std	%r31, 0x70(%r1)
	std	%r0, 0x90(%r1)

	MEM_BASE(%r31)
	mr	%r3, %r31		// start of memory
	lis	%r4, 0x4400
	ori	%r4, %r4, 0x0022 	// load 0x44000022 (hvsc instruction)
	oris	%r5, %r31, 0x30		// end of memory (0x300000)
	LOAD_LABEL2 (%r7, %r31, hvsc_handler)	// load our handler in %r7
l_hook_hvsc_loop:
	lwz	%r6, 0(%r3)
	cmpw	%r6, %r4
	bne	l_hook_hvsc_incr	// Found an hvsc instruction
	LOAD_LABEL2 (%r8, %r31, hvsc_call)
	cmpw	%r3, %r8		// Make sure it's not our handler's hvsc
	beq	l_hook_hvsc_incr
	// Build a branch instruction
	li	%r8, 18			// bits 0-5='18' means 'b/bl/ba/bla'
	rldicr	%r8, %r8, 26, 37
	subf	%r9, %r3, %r7		// relative address = target - current
	rldicl	%r9, %r9, 0, 38		// Clear the sign extension of the 24bit
					// address to avoid ORing the 0-5 bits
	or	%r8, %r8, %r9		// or the instruction with the address
	ori	%r8, %r8, 1		// or the link bit == 'bl' instruction
	stw	%r8, 0(%r3)		// replace the hvsc instruction
l_hook_hvsc_incr:
	addi	%r3, %r3, 4
	cmpw	%r3, %r5		// loop until the end of the memory
	bne	l_hook_hvsc_loop

	ld	%r31, 0x70(%r1)
	ld	%r0, 0x90(%r1)
	addi	%r1, %r1, 0x80
	mtlr	%r0
	blr

#endif /* __HOOK_HVSC_H_S__ */
