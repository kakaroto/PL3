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
 *    int old_size
 *    char *old_path
 *    int new_size
 *    char *new_path
 * }
 */
open_mapping_table:
	.quad	0
	
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
	LOAD_LABEL2 (%r26, %r31, open_mapping_table)
	cmpldi	%r26, 0
	bne	l_hook_open_proceed

	// load the mapping_table in %r26
	ld	%r26, 0(%r26)
	mr	%r27, %r26
	addi	%r27, %r27, 0x1000		// Set our limit
l_hook_open_next_table_entry:
	cmpldi	%r26, %r27
	beq	l_hook_open_proceed		// If we reached our limit, we're done
	lwz	%r5, 0(%r26)			// Load the size of this path
	ld	%r4, 4(%r26)			// Load the path
	addi	%r26, %r26, (4 + 8 + 4 + 8)	// skip to the next entry
	cmplwi	%r5, 0
	beq	l_hook_open_next_table_entry	// if empty entry, then try next
	mr	%r3, %r29			// Load the path to compare in %r3
	mr	%r30, %r5			// Store the size %r30
	bl	ABSOLUTE_MEM2(strncmp)
	cmpldi	%r3, 0
	bne	l_hook_open_next_table_entry	// If different, then go to next entry
	// We found the entry we wanted
	ld	%r3, -8(%r26)
	lwz	%r4, -(4 + 8)(%r26)
	cmpldi	%r3, 0
	beq	l_hook_open_proceed		// If the new path is NULL, skip
	add	%r3, %r3, %r4			// set dest = new_path + new_size
	addi	%r4, %r29, %r30			// set src = old_path + old_size
	bl	ABSOLUTE_MEM2(strcpy)
	ld	%r29, -8(%r26)			// reload the new_path into %r29
l_hook_open_proceed:
	mr	%r3, %r29
	b       ABSOLUTE_MEM2(patch_func3 + 0x28)

