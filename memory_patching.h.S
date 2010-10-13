/*
 * memory_patching.S -- PS3 Jailbreak payload : patch the memory on the fly
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

counter:
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
	LOADI_LABEL2(%r29, counter)
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
	
memory_patch_table:
	.quad	HASH_TABLE_1
	QUAD_MEM2(memory_patch_table_1)	// Play unsigned apps
	.quad	HASH_TABLE_3
	QUAD_MEM2(memory_patch_table_3) // Add 'install package files' menu in XMB
	.quad	HASH_TABLE_2
	QUAD_MEM2(memory_patch_table_2)	// Allow the installation of debug .pkg files
	.quad	HASH_TABLE_4
	QUAD_MEM2(memory_patch_table_4) // adds 'install package files' for ingame XMB
	.quad	0x0000000000000000
memory_patch_table_1:
	PATCH_INST(elf1_func1 + elf1_func1_offset, li %r3, 1)
	PATCH_INST(elf1_func1 + elf1_func1_offset + 4, blr)
	PATCH_INST(elf1_func2 + elf1_func2_offset, nop)
	.long 0
memory_patch_table_2:
	PATCH_INST(elf2_func1 + elf2_func1_offset, nop)
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
