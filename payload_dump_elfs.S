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


#include "pl3.h.S"

#include "send_eth.h.S"
#include "pl3_memcpy.h.S"

RESIDENT_AREA_START()
#include "send_eth_res.h.S"

message_buf:
	.quad	0

flags:
	.long	0
	.long	0
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
	
	LOAD_LABEL2 (%r3, %r31, hash)
	li	%r4, 64
	bl	send_eth

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
	
	LOAD_LABEL2 (%r3, %r31, message_buf)
	ld	%r3, 0(%r3)	
	li	%r4, 1028
	bl	send_eth

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

RESIDENT_AREA_END()

// HACK: the patch_table won't include the bl memory_patching without this
#define __MEMORY_PATCHING_H_S__
#include "patch_table.h.S"

payload_main:
	// prolog
	mflr	%r0
	stdu	%r1, -0xa0(%r1)
	std	%r30, 0x90(%r1)
	std	%r31, 0x98(%r1)
	std	%r0, 0xb0(%r1)

	GET_CURRENT_PAGE(%r3, %r31)
	MEM_BASE (%r30)			// Load 0x8000000000000000 in %r30

	COPY_RESIDENT_AREA(%r30, %r31)

	ALLOCATE_BUFFER(%r30, message_buf, 0x404)

	LOAD_FUNC_PTR(send_eth)
	INIT_SEND_ETH(%r30)

	APPLY_PATCHES(%r30, %r31)
	// epilog
	ld	%r30, 0x90(%r1)
	ld	%r31, 0x98(%r1)
	ld	%r0, 0xb0(%r1)
	addi	%r1, %r1, 0xa0
	mtlr	%r0
	blr
