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

#ifndef __MEMORY_PATCHING_RES_H_S__
#define __MEMORY_PATCHING_RES_H_S__

DEFINE_FUNC_PTR(memory_patching)

#ifndef STANDALONE
counter:
	.long	0

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

#endif /* !STANDALONE */

#endif /* __MEMORY_PATCHING_RES_H_S__ */
