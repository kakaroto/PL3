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


#include "macros.h.S"

.org 0
// Position 0x20 in the page
payload_start:

/**
 * payload_entry:
 * @payload_block: Pointer to the memory page containing our payload
 *
 * This is the entry point to the payload, it gets branched to form the injected
 * shellcode in the JIG response. 
 * This is the main function of the exploit, its code is position
 * indedependent. It copies the actual payload to a safe-from-overwrite memory,
 * while it overwrites an existing function from the kernel.
 * It will also add necessary syscalls and patch some areas of the kernel before
 * returning the control back to it
 *
 * exploit_main ():
 * {
 *   memcpy(MEM_BASE2, RESIDENT_PAYLOAD_OFFSET, RESIDENT_PAYLOAD_SIZE)
 *   add_kernel_module (kernel_module_struct);
 *   syscall_table[36] = syscall36_desc;
 *   ptr = patch_table;
 *   while (ptr[0] != NULL)
 *     *ptr[0] = ptr[1];
 *  }
 */
payload_entry:
	// epilog
	mflr	%r0
	stdu	%r1, -0xa0(%r1)
	std	%r30, 0x90(%r1)
	std	%r31, 0x98(%r1)
	std	%r0, 0xb0(%r1)

	GET_CURRENT_PAGE(%r3, %r31)
	
	MEM_BASE (%r30)			// Load 0x8000000000000000 in %r30

	// Copy functions that need to stay resident in memory to MEM_BASE2
	LOAD_LABEL (MEM_BASE2, %r3, %r30, 0)
	addi	%r4, %r31, ADDR_IN_PAGE(RESIDENT_PAYLOAD_OFFSET)
	li	%r5, RESIDENT_PAYLOAD_SIZE
	bl	pl3_memcpy
	
	addi	%r5, %r31, ADDR_IN_PAGE (patch_table)
l_apply_patches_loop:
	lwz	%r3, 0(%r5)	// If entry in patch table is NULL, we're done
	cmplwi	%r3, 0
	beq	l_patches_applied
	lwz	%r4, 4(%r5)
	add	%r3, %r3, %r30
	stw	%r4, 0(%r3)
	addi	%r5, %r5, 8
	b	l_apply_patches_loop
l_patches_applied:

	li	%r3, 0x400
	li	%r4, 0x27
 	BRANCH_ABSOLUTE(%r5, alloc)
	LOAD_LABEL2 (%r4, %r30, eth_proc)
	std	%r3, 0(%r4)
	
	addi	%r4, %r31, ADDR_IN_PAGE(send_eth)
	li	%r5, 0x400
	bl	pl3_memcpy

	bl	send_eth_init
	LOAD_LABEL2 (%r5, %r30, eth_dma_region)
	std	%r4, 0(%r5)

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

/**
 * patch_table:
 *
 * The patch table used by exploit_main to patch the kernel
 * it format is .long address, .long new_value
 *
 * it will patch its content until the destination address is 0
 *
 */
patch_table:
	PATCH_DATA(patch_data1, 0x01000000)
	PATCH_INST(patch_func1 + patch_func1_offset, ld %r4, rtoc_entry_1(%r2)) //hang
	PATCH_INST(patch_func1 + patch_func1_offset + 4, ld %r3, 0x20(%r28))
	PATCH_INST(patch_func1 + patch_func1_offset + 8, std %r3, 0(%r4))
	PATCH_INST(patch_func4 + patch_func4_offset, li %r4, 0)
	PATCH_INST(patch_func4 + patch_func4_offset + 4, stw %r4, 0(%r3))
	PATCH_INST(patch_func4 + patch_func4_offset + 8, blr)
	PATCH_INST(patch_func5 + patch_func5_offset, li %r3, 1)
	PATCH_INST(patch_func5 + patch_func5_offset + 4, blr)
	.long	0


#include "send_eth.h.S"
#include "pl3_memcpy.h.S"
	
/**
 * overwritten_kernel_function:
 *
 * For now noone knows what the original kernel function did, but
 * this just patches it up to just return 1, and also replaces its
 * content with our own payload
 *
 */
.align 4
overwritten_kernel_function:
	li	%r3, 1
	blr

eth_proc:
	.quad	0
eth_dma_region:	
	.quad	0

#include "trace_helpers.h.S"
#include "vuart_tracer.h.S"

payload_end:
.org RESIDENT_PAYLOAD_OFFSET + RESIDENT_PAYLOAD_MAXSIZE 
