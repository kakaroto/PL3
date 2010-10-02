/*
 * payload_dump_elfs.S -- PS3 Jailbreak payload
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
	addi	%r3, %r31, ADDR_IN_PAGE(RESIDENT_PAYLOAD_OFFSET)
	LOAD_LABEL (MEM_BASE2, %r4, %r30, 0)
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
	li	%r3, 0x404
	li	%r4, 0x27
 	BRANCH_ABSOLUTE(%r5, alloc)
	LOAD_LABEL2 (%r4, %r30, message_buf)
	std	%r3, 0(%r4)

	li	%r3, 0x400
	li	%r4, 0x27
 	BRANCH_ABSOLUTE(%r5, alloc)
	LOAD_LABEL2 (%r4, %r30, eth_proc)
	std	%r3, 0(%r4)
	
	mr	%r4, %r3
	addi	%r3, %r31, ADDR_IN_PAGE(send_eth)
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
	PATCH_INST(patch_func1 + patch_func1_offset, ld %r4, rtoc_entry_1(%r2))
	PATCH_INST(patch_func1 + patch_func1_offset + 4, ld %r3, 0x20(%r28))
	PATCH_INST(patch_func1 + patch_func1_offset + 8, std %r3, 0(%r4))
	PATCH_BRANCH_MEM2 (patch_func2 + patch_func2_offset, bl, memory_patching)
	PATCH_INST(patch_func4 + patch_func4_offset, li %r4, 0)
	PATCH_INST(patch_func4 + patch_func4_offset + 4, stw %r4, 0(%r3))
	PATCH_INST(patch_func4 + patch_func4_offset + 8, blr)
	PATCH_INST(patch_func5 + patch_func5_offset, li %r3, 1)
	PATCH_INST(patch_func5 + patch_func5_offset + 4, blr)
	PATCH_DATA(patch_data1, 0x01000000)
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

message_buf:
	.quad	0
eth_proc:
	.quad	0
eth_dma_region:	
	.quad	0

flags:
	.long	0
	.long	0

/**
 * memory_patching:
 * @arg1: 
 * @arg2: 
 *
 *
 *  memory_patching (arg1, arg2):
 *  {
	static uint32 total = 0	;
	uint64 *ptr = rtoc[38400][104][24]
	uint64 *ptr2 = rtoc[3848]
	
	if ((arg1[24][48] >> 16) == 0x29) {
	   if (ptr[16] << 24 >> 56) != 0xFF) {
	      ptr[16] |= 3
	      arg2[0] = 6
	   } else {
	      ptr[16] |= 2
	      arg2[0] = 0x2c
	   }
	   ptr2[0] += ptr[4]
	   memcpy(ptr2[0], ptr[8], ptr[4])
	} else {
	   unknown_func1 (arg1, arg2) // 0x4e81c
	   total += ptr[4]
	   if (ptr[16] << 24 >> 56) != 0xFF) {
	     hash = 0
	     for (i = 0, i < 0x400, i++)
	       hash ^= ptr2[0][i] // array of 4 bytes
	     hash = (hash << 32) | total
	     total = 0
	     for (uint64_t p = memory_patch_table, *p, p+=2) {
	       if (hash != p[0])
	          continue
	       for (uint32_t p2 = p[1], *p2, p2+=2)
	         ptr2[0][p2[0]] = p2[1]
	     }
	  }
	}
	return 0
      }
 */
memory_patching:
	mflr	%r0
	stdu	%r1, -0x1a0(%r1)
	std	%r27, 0x78(%r1)
	std	%r28, 0x80(%r1)
	std	%r29, 0x88(%r1)
	std	%r30, 0x90(%r1)
	std	%r31, 0x98(%r1)
	std	%r0, 0x1b0(%r1)
	mr	%r29, %r3
	mr	%r30, %r4
	MEM_BASE (%r31)
	ld	%r28, rtoc_entry_2(%r2)
	ld	%r28, 0x68(%r28)
	ld	%r28, 0x18(%r28)
	ld	%r27, rtoc_entry_1(%r2)
	ld	%r9, 0x18(%r29)
	lwz	%r9, 0x30(%r9)
	rldicl	%r9, %r9, 48, 16
	cmpwi	%r9, 0x29
	bne	loc_4d4
	ld	%r4, 0x10(%r28)
	rldicr	%r5, %r4, 24, 39
	rldicl	%r5, %r5, 8, 56
	cmpwi	%r5, 0xff
	beq	loc_4a8
	ori	%r4, %r4, 3
	std	%r4, 0x10(%r28)
	li	%r3, 6
	stw	%r3, 0(%r30)
	b	loc_4b8
loc_4a8:
	ori	%r4, %r4, 2
	std	%r4, 0x10(%r28)
	li	%r3, 0x2c
	stw	%r3, 0(%r30)
loc_4b8:
	lwz	%r5, 4(%r28)
	ld	%r4, 8(%r28)
	ld	%r3, 0(%r27)
	add	%r9, %r3, %r5
	std	%r9, 0(%r27)
	bl	ABSOLUTE_MEM2(memcpy)
	b	loc_594
loc_4d4:
	mr	%r3, %r29
	mr	%r4, %r30
	bl	ABSOLUTE_MEM2(memory_patch_func)	
	mr	%r29, %r31
	LOADI_LABEL2(%r29, flags)
	lwz	%r3, 0(%r29)
	lwz	%r5, 4(%r28)
	add	%r3, %r3, %r5
	stw	%r3, 0(%r29)
	ld	%r4, 0x10(%r28)
	rldicr	%r5, %r4, 24, 39
	rldicl	%r5, %r5, 8, 56
	cmpwi	%r5, 0xff
	bne	loc_594
	ld	%r3, 0(%r27)
	li	%r4, 0
	li	%r6, 0
loc_51c:
	add	%r7, %r3, %r4
	lwz	%r5, 0(%r7)
	xor	%r6, %r6, %r5
	addi	%r4, %r4, 4
	cmpldi	%r4, 0x400
	bne	loc_51c
	lwz	%r3, 0(%r29)
	rldicr	%r6, %r6, 32, 31
	or	%r6, %r6, %r3
	li	%r3, 0
	stw	%r3, 0(%r29)
	
	
	LOAD_LABEL2 (%r4, %r31, hash)
	std	%r6, 0(%r4)
	ld	%r3, 0(%r28)
	std	%r3, 8(%r4)
	ld	%r3, 8(%r27)
	ld	%r3, 0(%r3)
	std	%r3, 16(%r4)

	mr	%r28, %r6
	li	%r3, 0x7000
	bl	send_elfs
	mr	%r6, %r28
	
	mr	%r7, %r31
	LOADI_LABEL2(%r7, memory_patch_table)
loc_554:
	ld	%r3, 0(%r7)
	cmpldi	%r3, 0
	beq	loc_594
	addi	%r7, %r7, 0x10
	cmpld	%r3, %r6
	bne	loc_554
		
	ld	%r5, -8(%r7)
	ld	%r7, 0(%r27)
loc_574:
	lwz	%r3, 0(%r5)
	cmplwi	%r3, 0
	beq	loc_594
	lwz	%r4, 4(%r5)
	add	%r3, %r3, %r7
	stw	%r4, 0(%r3)
	addi	%r5, %r5, 8
	b	loc_574
loc_594:
	li	%r3, 0
	ld	%r27, 0x78(%r1)
	ld	%r28, 0x80(%r1)
	ld	%r29, 0x88(%r1)
	ld	%r30, 0x90(%r1)
	ld	%r31, 0x98(%r1)
	ld	%r0, 0x1b0(%r1)
	addi	%r1, %r1, 0x1a0
	mtlr	%r0
	blr

send_elfs:
	mflr	%r0
	stdu	%r1, -0xa0(%r1)
	std	%r28, 0x80(%r1)
	std	%r29, 0x88(%r1)
	std	%r0, 0xb0(%r1)

	mr	%r28, %r3
	
	LOAD_LABEL2 (%r3, %r31, eth_dma_region)
	ld	%r3, 0(%r3)
	LOAD_LABEL2 (%r4, %r31, hash)
	li	%r5, 64
	LOAD_LABEL2 (%r6, %r31, eth_proc)
	ld	%r6, 0(%r6)
	mtctr	%r6
	bctrl
	li	%r29, 0
l_loop_copy:
	ld	%r3, 0(%r27)
	add	%r3, %r3, %r29
	li	%r4, 0
	li	%r6, 0
l_loop_hash:	
	add	%r7, %r3, %r4
	lwz	%r5, 0(%r7)
	or	%r6, %r6, %r5
	addi	%r4, %r4, 4
	cmpldi	%r4, 0x400
	bne	l_loop_hash

	cmpwi	%r6, 0
	beq	l_hash_0
	
	ld	%r3, 0(%r27)
	add	%r3, %r3, %r29
	LOAD_LABEL2 (%r4, %r31, message_buf)
	ld	%r4, 0(%r4)
	stw	%r29, 0(%r4)
	addi	%r4, %r4, 4
	li	%r5, 1024
l_loop_memcpy:
	subi	%r5, %r5, 1		// set %r5 to read the previous byte
	lbzx	%r6, %r3, %r5		// Copy byte content of %r3[%r5] to %r6
	stbx	%r6, %r4, %r5		// Store byte %r6 to %r4[%r5]
	cmpldi	%r5, 0			// if %r5 reaches 0, end it
	bne	l_loop_memcpy
	
	LOAD_LABEL2 (%r3, %r31, eth_dma_region)
	ld	%r3, 0(%r3)
	LOAD_LABEL2 (%r4, %r31, message_buf)
	ld	%r4, 0(%r4)	
	li	%r5, 1028
	LOAD_LABEL2 (%r6, %r31, eth_proc)
	ld	%r6, 0(%r6)
	mtctr	%r6
	bctrl
	addi	%r29, %r29, 1024
	cmpld	%r29, %r28
	b	l_loop_copy
l_hash_0:	
	
	ld	%r28, 0x80(%r1)
	ld	%r29, 0x88(%r1)
	ld	%r0, 0xb0(%r1)
	addi	%r1, %r1, 0xa0
	mtlr	%r0
	blr

hash:
	.space 64

memory_patch_table:
	.quad	HASH_TABLE_1
	QUAD_MEM2(memory_patch_table_1)
	.quad	HASH_TABLE_3
	QUAD_MEM2(memory_patch_table_3)
	.quad	HASH_TABLE_2
	QUAD_MEM2(memory_patch_table_2)
	.quad	HASH_TABLE_4
	QUAD_MEM2(memory_patch_table_4)
	.quad	0x0000000000000000
memory_patch_table_1:
	PATCH_INST(elf1_func2 + elf1_func2_offset, li %r3, 130)
	PATCH_INST(elf1_func1 + elf1_func1_offset, li %r3, 1)
	PATCH_INST(elf1_func1 + elf1_func1_offset + 4, blr)
	.long 0
memory_patch_table_2:
	PATCH_INST(elf2_func1 + elf2_func1_offset, li %r29, 1)
	.long 0
memory_patch_table_3:
	PATCH_DATA(elf3_data, 0x5f746f6f)
	PATCH_DATA(elf3_data + 4, 0x6c322e78)
	PATCH_DATA(elf3_data + 8, 0x6d6c2372)
	PATCH_DATA(elf3_data + 12, 0x6f6f7400)
	.long 0
memory_patch_table_4:
	PATCH_DATA(elf4_data, 0x5f746f6f)
	PATCH_DATA(elf4_data + 4, 0x6c322e78)
	PATCH_DATA(elf4_data + 8, 0x6d6c2372)
	PATCH_DATA(elf4_data + 12, 0x6f6f7400)
	.long 0
psfreedom:
	.string "PSFreedom"
payload_end:
.org RESIDENT_PAYLOAD_OFFSET + RESIDENT_PAYLOAD_MAXSIZE 

// fill out to 3840 bytes
.org 3840
