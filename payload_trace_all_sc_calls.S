/*
 * payload_dump_syscalls.S -- PS3 Jailbreak payload - hook syscall handler and
 *                            dump the syscall arguments over ethernet
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 * Copyright (C) Aaron Lindsay (Aaron')
 * Copyright (C) (subdub)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 * This payload is a modified version of the original PSJailbreak's payload.
 * The people behing PSJailbrak are the original authors and copyright holders
 * of the code they wrote.
 */


#include "pl3.h.S"

#include "send_eth.h.S"
#include "memory_patching.h.S"

RESIDENT_AREA_START()
#include "memory_patching_res.h.S"
#include "send_eth_res.h.S"
#include "hvsc_handler.h.S"
#include "syscall_handler.h.S"
#include "send_eth_res.h.S"
RESIDENT_AREA_END()

#include "patch_table.h.S"
	
payload_main:
	// epilog
	mflr	%r0
	stdu	%r1, -0xa0(%r1)
	std	%r30, 0x90(%r1)
	std	%r31, 0x98(%r1)
	std	%r0, 0xb0(%r1)

	GET_CURRENT_PAGE(%r3, %r31)
	MEM_BASE (%r30)			// Load 0x8000000000000000 in %r30

	COPY_RESIDENT_AREA(%r30, %r31)

	LOAD_FUNC_PTR(memory_patching)
	LOAD_FUNC_PTR(send_eth)
	INIT_SEND_ETH(%r30)

	APPLY_PATCHES(%r30, %r31)
	// Replace hvsc after we copy our handler to the resident area
	// because another thread might be running at the same time
	// and if it calls hvsc and we're not yet ready, then we're
	// screwed
	mr	%r3, %r30		// start of memory
	lis	%r4, 0x4400
	ori	%r4, %r4, 0x0022 	// load 0x44000022 (hvsc instruction)
	oris	%r5, %r30, 0x30		// end of memory (0x300000)
	LOAD_LABEL2 (%r7, %r30, hvsc_hook)	// load our handler in %r7
l_patch_hvsc_loop:
	lwz	%r6, 0(%r3)
	cmpw	%r6, %r4
	bne	l_patch_hvsc_incr	// Found an hvsc instruction
	LOAD_LABEL2 (%r8, %r30, hvsc_call)
	cmpw	%r3, %r8		// Make sure it's not our handler's hvsc
	beq	l_patch_hvsc_incr
	// Build a branch instruction
	li	%r8, 18			// bits 0-5='18' means 'b/bl/ba/bla'
	rldicr	%r8, %r8, 26, 37
	subf	%r9, %r3, %r7		// relative address = target - current
	rldicl	%r9, %r9, 0, 38		// Clear the sign extension of the 24bit
					// address to avoid ORing the 0-5 bits
	or	%r8, %r8, %r9		// or the instruction with the address
	ori	%r8, %r8, 1		// or the link bit == 'bl' instruction
	stw	%r8, 0(%r3)		// replace the hvsc instruction
l_patch_hvsc_incr:
	addi	%r3, %r3, 4
	cmpw	%r3, %r5		// loop until the end of the memory
	bne	l_patch_hvsc_loop

	// prolog
	ld	%r30, 0x90(%r1)
	ld	%r31, 0x98(%r1)
	ld	%r0, 0xb0(%r1)
	addi	%r1, %r1, 0xa0
	mtlr	%r0
	blr
