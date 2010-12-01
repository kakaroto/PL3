/*
 * open_hook.h.S -- PS3 Jailbreak payload : open hook
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#ifndef __OPEN_HOOK_H_S__
#define __OPEN_HOOK_H_S__

/* Pointer to :
 * struct {
 *    struct path old
 *    struct path new
 * }
 *
 * struct path {
 *    int size
 *    char path[404]
 * }
 */
	.set	MAX_TABLE_ENTRIES, 16
open_mapping_table:
	.quad	0

syscall_map_open_desc:
	QUAD_MEM2 (syscall_map_open)

DEFINE_FUNC_PTR(map_open_path)
DEFINE_FUNC_PTR(syscall_map_open)

/**
 * hook_open:
 * @path: The path to open
 * @mode: The mode to use for opening the file
 *
 * This hook replaces the open syscall and will replace the path used
 * for file open when a new path if there is a mapping for it
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
.align 4
hook_open:
	// The overwritten instruction
	mr	%r29, %r3

	// load the mapping_table in %r26
	MEM_BASE (%r26)
	LOAD_LABEL2 (%r26, %r26, open_mapping_table)
	ld	%r26, 0(%r26)
	cmpldi	%r26, 0
	beq	l_hook_open_proceed

	addi	%r27, %r26, 0x10*MAX_TABLE_ENTRIES	// Set our limit
l_hook_open_next_table_entry:
	cmpld	%r26, %r27
	beq	l_hook_open_proceed		// If we reached our limit, we're done
	ld	%r3, 0(%r26)			// Load the old path structure
	addi	%r26, %r26, 0x10		// skip to the next entry
	cmpldi	%r3, 0
	beq	l_hook_open_next_table_entry	// if empty entry, then try next
	addi	%r4, %r3, 4			// Load the path
	lwz	%r5, 0(%r3)			// Load the size of this path
	cmplwi	%r5, 0
	beq	l_hook_open_next_table_entry	// if size is 0, then try next
	mr	%r3, %r29			// Load the path to compare in %r3
	mr	%r31, %r5			// Store the size in %r31
	bl	ABSOLUTE_MEM2(strncmp)
	cmpldi	%r3, 0
	bne	l_hook_open_next_table_entry	// If different, then go to next entry

	// We found the entry we wanted
	ld	%r3, -0x08(%r26)
	lwz	%r4, 0(%r3)			// Load the size of the new path
	addi	%r3, %r3, 4			// Load the new path
	cmpldi	%r3, 0
	beq	l_hook_open_proceed		// If the new path is NULL, skip
	add	%r3, %r3, %r4			// set dest = new_path + new_size
	add	%r4, %r29, %r31			// set src = old_path + old_size
	bl	ABSOLUTE_MEM2(strcpy)
	ld	%r3, -0x08(%r26)
	addi	%r29, %r3, 4			// reload the new_path into %r29
l_hook_open_proceed:
	mr	%r3, %r29
	b       ABSOLUTE_MEM2(patch_func3 + patch_func3_offset + 4)

#endif /* __OPEN_HOOK_H_S__ */
