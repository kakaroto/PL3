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
	//PATCH_BRANCH_MEM2 (patch_func2 + patch_func2_offset, bl, memory_patching)
	PATCH_INST(patch_func4 + patch_func4_offset, li %r4, 0)
	PATCH_INST(patch_func4 + patch_func4_offset + 4, stw %r4, 0(%r3))
	PATCH_INST(patch_func4 + patch_func4_offset + 8, blr)
	PATCH_INST(patch_func5 + patch_func5_offset, li %r3, 1)
	PATCH_INST(patch_func5 + patch_func5_offset + 4, blr)
	PATCH_BRANCH_MEM2 (0x28F660, bl, syscall_handler)
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

#include "memory_patching.h.S"

eth_proc:
	.quad	0
eth_dma_region:	
	.quad	0

syscall_handler:
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
	std	%r0, 0x110(%r1)

	rldicl	%r11, %r11, 61, 3

	/* do not log the mutex lock/unlock syscalls, floods the network */
	cmplwi	%r11, 104
	bgt	l_gt_104
	cmplwi	%r11, 100
	blt	l_lt_100
	b	l_syscall_handler_done
l_gt_104:
l_lt_100:
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

	MEM_BASE (%r31)
	LOAD_LABEL2 (%r3, %r31, eth_dma_region)
	ld	%r3, 0(%r3)
	LOAD_LABEL2 (%r4, %r31, buf)
	li	%r5, 0x48
	LOAD_LABEL2 (%r6, %r31, eth_proc)
	ld	%r6, 0(%r6)
	mtctr	%r6
	bctrl

l_syscall_handler_done:	
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
	ld	%r0, 0x110(%r1)
	addi	%r1, %r1, 0x100
	mtlr	%r0
	mtctr	%r13
	bctr
buf:
	.space 0x48
payload_end:
.org RESIDENT_PAYLOAD_OFFSET + RESIDENT_PAYLOAD_MAXSIZE 
