/*
 * open_hook.h.S -- PS3 Jailbreak payload : open hook
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

.align 4
	
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

map_open_path_ptr:
	.quad	0

/**
 * syscall_map_open:
 * @old_path: The path to map
 * @new_path: The new path to map it to (or NULL to remove the mapping)
 *
 * This new syscall will redirect all file access from @old_path to
 * @new_path or if @new_path is #NULL, it will remove the mapping
 */
syscall_map_open:
	// epilog
	mflr	%r0
	stdu	%r1, -0xc0(%r1)
	std	%r26, 0x70(%r1)
	std	%r0, 0xd0(%r1)
	mr	%r26, %r4

	cmpldi	%r3, 0
	beq	l_syscall_map_open_error
	addi	%r4, %r1, 0xa0			// old path
	bl	ABSOLUTE_MEM2(strdup_from_user)	// strdup %r3 from userspace
	mr	%r29, %r3

	mr	%r3, %r26
	cmpldi	%r3, 0
	beq	l_syscall_map_open_unset
	addi	%r4, %r1, 0xb0			// new path
	bl	ABSOLUTE_MEM2(strdup_from_user)	// strdup %r4 from userspace
	b	l_syscall_map_open_call
l_syscall_map_open_unset:
	std	%r3, 0xb0(%r1)
l_syscall_map_open_call:
	ld	%r3, 0xa0(%r1)			// old path
	ld	%r4, 0xb0(%r1)			// new path
	// Call map_open_path
	MEM_BASE (%r6)
	LOAD_LABEL2 (%r6, %r6, map_open_path_ptr)
	ld	%r6, 0(%r6)
	mtctr	%r6
	bctrl
	mr	%r26, %r3
	ld	%r3, 0xa0(%r1)
	li	%r4, 0x27
	bl	ABSOLUTE_MEM2(free)
	ld	%r3, 0xb0(%r1)
	cmpldi	%r3, 0
	beq	l_syscall_map_open_return
	li	%r4, 0x27
	bl	ABSOLUTE_MEM2(free)
l_syscall_map_open_return:
	mr	%r3, %r26			// return result of add_open_path_map
l_syscall_map_open_return_r3:
	// epilog
	ld	%r26, 0x70(%r1)
	ld	%r0, 0xd0(%r1)
	addi	%r1, %r1, 0xc0
	mtlr	%r0
	blr
l_syscall_map_open_error:
	nor	%r3, %r3, %r3			// r3 is already 0 here, so make it -1
	b	l_syscall_map_open_return_r3	


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

	mr	%r27, %r26
	addi	%r27, %r27, 0x10*MAX_TABLE_ENTRIES	// Set our limit
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

