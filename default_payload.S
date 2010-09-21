/*
 * default_payload.S -- PS3 Jailbreak payload
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
 * shellcode in the JIG response. it will copy the payload to
 * a specific memory location (MEM_BASE1) then jump to the main in it.
 * This is necessary because all branches and calls are position dependent and
 * writing position independent code is very hard, so this makes it easier.
 *
 * payload_entry (next_block):
 * {
 *   current_block = next_block - PAGE_SIZE;
 *
 *   for (i = PAGE_SIZE - sizeof(uint64); i >= 0; i -= sizeof(uint64)
 *     MEM_BASE1[i] = current_block[i];
 *   goto MEM_BASE1 + exploit_main;
 *  }
 */
payload_entry:
	li	%r5, PAGE_SIZE		// Set %r5 to the end of this page
	LOAD_MEM_BASE1(%r4)		// Load 0x8000000000700000 into %r4
l_payload_copy:
	subi	%r5, %r5, 8		// set %r5 to read the previous quad
	ldx	%r6, %r3, %r5		// Copy quad content of %r3[%r5] to %r6
	stdx	%r6, %r4, %r5		// Store quad %r6 to %r4[%r5]
	cmpldi	%r5, 0			// if %r5 reaches our block, end it
	bne	l_payload_copy
	addi	%r4, %r4, ADDR_IN_PAGE(exploit_main)	// Jump to exploit_main
	mtctr	%r4
	bctr

/**
 * exploit_main:
 *
 * This is the main function of the exploit, its code is position
 * dependent on MEM_BASE1 and it gets executed from there. It copies
 * the rest of the payload to a safe-from-overwrite memory, while it
 * overwrites an apparently useless/unused function from the kernel.
 * It will also add necessary syscalls and patch the kernel before
 * memsetting the code in MEM_BASE1 to 0 and returning the control
 * back to the kernel
 *
 * exploit_main ():
 * {
 *   memcpy(MEM_BASE2, RESIDENT_PAYLOAD_OFFSET, RESIDENT_PAYLOAD_SIZE)
 *   add_kernel_module (kernel_module_struct);
 *   syscall_table[36] = syscall36_desc;
 *   ptr = patch_table;
 *   while (ptr[0] != NULL)
 *     *ptr[0] = ptr[1];
 *   memset(MEM_BASE1, 0, PAYLOAD_SIZE);
 *  }
 */
exploit_main:
	mflr	%r0
	stdu	%r1, -0xa0(%r1)
	std	%r27, 0x78(%r1)
	std	%r28, 0x80(%r1)
	std	%r29, 0x88(%r1)
	std	%r30, 0x90(%r1)
	std	%r31, 0x98(%r1)
	std	%r0, 0xb0(%r1)
	MEM_BASE (%r31)			// Load 0x8000000000000000 in %r31

	// Copy the content of the originally removed function
	li	%r3, RESIDENT_PAYLOAD_SIZE
	li	%r4, 0x27
	b	ABSOLUTE_MEM1(alloc)
	mr	%r30, %r3
	LOAD_LABEL (MEM_BASE2, %r4, %r31, 0)	// Load MEM_BASE2 in %r3
	li	%r5, RESIDENT_PAYLOAD_SIZE
	bl	ABSOLUTE_MEM1(memcpy)

	LOAD_LABEL1 (%r4, %r31, RESIDENT_PAYLOAD_OFFSET)
	LOAD_LABEL (MEM_BASE2, %r3, %r31, 0)	// Load MEM_BASE2 in %r3
	// Copy functions that need to stay resident in memory to MEM_BASE2
	LOAD_LABEL1 (%r4, %r31, RESIDENT_PAYLOAD_OFFSET)
	li	%r5, RESIDENT_PAYLOAD_SIZE
	bl	ABSOLUTE_MEM1(memcpy)

	LOAD_LABEL2 (%r3, %r31, orig_sub_data)
	std	%r30, 0(%r3)

	// Add kernel module for device6
	LOAD_LABEL2 (%r3, %r31, kernel_module_struct)
	bl	ABSOLUTE_MEM1(add_kernel_module)
	// Add system call 36 for backup manager
	ADD_SYSCALL (syscall_6_peek_desc, 6)
	ADD_SYSCALL (syscall_7_poke_desc, 7)
	ADD_SYSCALL (syscall_8_alloc_desc, 8)
	ADD_SYSCALL (syscall_9_free_desc, 9)
	ADD_SYSCALL (syscall_10_exec_desc, 10)
	ADD_SYSCALL (syscall_36_map_bdvd_desc, 36)
	LOAD_LABEL1 (%r5, %r31, patch_table)
l_apply_patches_loop:
	lwz	%r3, 0(%r5)	// If entry in patch table is NULL, we're done
	cmplwi	%r3, 0
	beq	l_patches_applied
	lwz	%r4, 4(%r5)
	add	%r3, %r3, %r31
	stw	%r4, 0(%r3)
	addi	%r5, %r5, 8
	b	l_apply_patches_loop
l_patches_applied:
	ld	%r27, 0x78(%r1)
	ld	%r28, 0x80(%r1)
	ld	%r29, 0x88(%r1)
	ld	%r30, 0x90(%r1)
	ld	%r31, 0x98(%r1)
	ld	%r0, 0xb0(%r1)
	addi	%r1, %r1, 0xa0
	mtlr	%r0
	LOAD_MEM_BASE1(%r3)
	li	%r4, 0
	li	%r5, PAYLOAD_SIZE
	b	ABSOLUTE_MEM1(memset)

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
	PATCH_INST(0x0490e0, ld %r4, 0xf08(%r2))
	PATCH_INST(0x0490e4, ld %r3, 0x20(%r28))
	PATCH_INST(0x0490e8, std %r3, 0(%r4))
	PATCH_BRANCH_MEM2 (0x04f0a8, bl, memory_patching_desc)
	PATCH_BRANCH_MEM2 (0x2aafc8, b, hook_open)
	PATCH_INST(0x04ed18, li %r4, 0)
	PATCH_INST(0x04ed1c, stw %r4, 0(%r3))
	PATCH_INST(0x04ed20, blr)
	PATCH_DATA(0x3ba890, 0x01000000)
	PATCH_INST(0x0505d0, li %r3, 1)
	PATCH_INST(0x0505d4, blr)
	.long	0

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

	// Pointers to various functions
memory_patching_desc:
	b	memory_patching
hook_open_desc:
	b	hook_open
//#include "hook_open_psjb.h.S"

#include "syscall36.h.S"
#include "device6_kmod.h.S"

orig_sub_data:
	.quad	0
game_path:
	.quad	0
game_path_end:
	.quad	0
flags:
	.long	0
	.long	0


// need to -1 to not count trailing \x00 from hook_path
#define HOOK_PATH_LEN (hook_path_end - hook_path - 1)

/**
 * hook_open:
 * @path: The path to open
 * @mode: The mode to use for opening the file
 *
 * This hook replaces the open syscall and will replace the path used
 * for file open when the game_path is set to allow for bdvd emulation
 *
 *  hook_open (path, mode):
 *  {
 *    if (strncmp(path, "/dev_bdvd", 9) == 0 && game_path != NULL) {
 *      strcpy (game_path_end, path + 9)
 *      path = game_path;
 *    }
 *
 *    return original_open (path, mode);
 *  }
 */
hook_open:
	// This is a copy from the original hook function, setting up the stack
	stdu	%r1, -0xa0(%r1)
	mflr	%r0
	std	%r28, 0x80(%r1)
	std	%r29, 0x88(%r1)
	std	%r31, 0x98(%r1)
	std	%r26, 0x70(%r1)
	std	%r27, 0x78(%r1)
	std	%r0, 0xb0(%r1)
	mr	%r28, %r4
	mr	%r29, %r3

	// Actual payload code
	MEM_BASE (%r31)
	LOAD_LABEL2 (%r4, %r31, hook_path)
	li	%r5, HOOK_PATH_LEN
	bl	ABSOLUTE_MEM2(strncmp)
	cmpldi	%r3, 0
	bne	l_proceed
	LOAD_LABEL2(%r31, %r31, game_path)
	ld	%r3, 0(%r31)
	cmpldi	%r3, 0
	beq	l_proceed
	ld	%r3, 8(%r31)
	addi	%r4, %r29, HOOK_PATH_LEN
	bl	ABSOLUTE_MEM2(strcpy)
	ld	%r29, 0(%r31)
l_proceed:
	mr	%r3, %r29
	b	ABSOLUTE_MEM2(0x2aaff0)

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
	ld	%r28, -0x6a00(%r2)
	ld	%r28, 0x68(%r28)
	ld	%r28, 0x18(%r28)
	ld	%r27, 0xf08(%r2)
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
	bl	ABSOLUTE_MEM2(0x4e81c)
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
	.quad	0xa0556f3d002cb8fd
	QUAD_MEM2(memory_patch_table_1)
	.quad	0x8c0a948c000d99b1
	QUAD_MEM2(memory_patch_table_3)
	.quad	0xa2bc1a5600052adc
	QUAD_MEM2(memory_patch_table_4)
	.quad	0x6b70280200020017
	QUAD_MEM2(memory_patch_table_2)
	.quad	0x0000000000000000
memory_patch_table_1:
	.quad	0x0030535438600082
	.quad	0x005f3fc038600001
	.quad	0x005f3fc44e800020
	.long	0x00000000
memory_patch_table_2:
	.quad	0x0002ed0c3ba00001
	.long	0x00000000
memory_patch_table_3:
	.quad	0x0022b8885f746f6f
	.quad	0x0022b88c6c322e78
	.quad	0x0022b8906d6c2372
	.quad	0x0022b8946f6f7400
	.long	0x00000000
memory_patch_table_4:
	.quad	0x000d68b85f746f6f
	.quad	0x000d68bc6c322e78
	.quad	0x000d68c06d6c2372
	.quad	0x000d68c46f6f7400
	.long	0x00000000

hook_path:
	.string "PSFreedom"
hook_path_end:
payload_end:
	// fill out to 3840 bytes
.org 3840