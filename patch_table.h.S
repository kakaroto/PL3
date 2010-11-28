/*
 * patch_table.h.S -- PL3: patch table for the kernel
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#ifndef __PATCH_TABLE_H_S__
#define __PATCH_TABLE_H_S__

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
#ifdef __MEMORY_PATCHING_H_S__
	PATCH_BRANCH_MEM2 (patch_func2 + patch_func2_offset, bl, memory_patching)
#endif
#ifdef __OPEN_HOOK_H_S__
	PATCH_BRANCH_MEM2 (patch_func3 + patch_func3_offset, b, hook_open)
#endif
	PATCH_INST(patch_func4 + patch_func4_offset, li %r4, 0) //80010009 error
	PATCH_INST(patch_func4 + patch_func4_offset + 4, stw %r4, 0(%r3))
	PATCH_INST(patch_func4 + patch_func4_offset + 8, blr)
#ifndef NO_UNAUTH_SYSCALL
	PATCH_INST(patch_func5 + patch_func5_offset, li %r3, 1) //check feature?
	PATCH_INST(patch_func5 + patch_func5_offset + 4, blr)
	PATCH_INST(patch_func6 + patch_func6_offset, li %r3, 0)
	PATCH_INST(patch_func7 + patch_func7_offset, li %r3, 0)
#endif
	// force lv2open return 0
	PATCH_INST(patch_func8 + patch_func8_offset1, li %r3, 0)
	// disable calls in lv2open to lv1_send_event_locally which makes
	// the system crash
	PATCH_INST(patch_func8 + patch_func8_offset2, nop)
	PATCH_INST(patch_func9 + patch_func9_offset, nop)
#ifdef __SYSCALL_HANDLER_H_S__
	PATCH_BRANCH_MEM2 (patch_syscall_func, bl, syscall_handler)
#endif
	.long	0



#define APPLY_PATCHES(base, page)				\
	addi	%r5, page, ADDR_IN_PAGE (patch_table);		\
l_apply_patches_loop:						\
	lwz	%r3, 0(%r5);					\
	cmplwi	%r3, 0;						\
	beq	l_apply_patches_done;				\
	lwz	%r4, 4(%r5);					\
	add	%r3, %r3, %r30;					\
	stw	%r4, 0(%r3);					\
	addi	%r5, %r5, 8;					\
	b	l_apply_patches_loop;				\
l_apply_patches_done:

#endif /* __PATCH_TABLE_H_S__ */