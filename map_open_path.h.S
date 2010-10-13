/*
 * map_open_path.h.S -- PS3 Jailbreak payload : function to map the open path
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

/**
 * map_open_path:
 * @old_path: The path to map
 * @new_path: The new path to map it to (or NULL to remove the mapping)
 *
 * This position independent function will redirect all file access from @old_path to
 * @new_path or if @new_path is #NULL, it will remove the mapping
 *
 * pseudo-code :
 * map_open_path(old_path, new_path) {
 *	int old_len, new_len
 *	struct path_mapping_s *ptr
 *
 *	if (old_path == NULL)
error:
 *	  return -1
 *	old_len = strlen(old_path)
 *	if (new_path)
 *	  new_len = strlen(new_path)
 *	else
unset:
 *	  new_len = 0
 *	if (open_mapping_table == NULL) {
 *	  open_mapping_table = alloc (MAX_TABLE_ENTRIES * sizeof(struct path_mapping_s))
memset:
 *	  for (int i = MAX_TABLE_ENTRIES * sizeof(struct path_mapping_s) - 8; i >= 0; i -= 8)
 *	    open_mapping_table[i] = 0
 *	  ptr = open_mapping_table
 *	  goto new_entry
 * 	} else {
no_alloc:
 *	  ptr = open_mapping_table
next_table_entry:
 *	  while (ptr != open_mapping_table + MAX_TABLE_ENTRIES * sizeof(...)) {
 *	    if (ptr.old == NULL)
 *	      continue
 *	    if (ptr.old->size != old_size)
 *	      continue
 *	    if (strncmp(ptr.old->path, old_path, old_size) != 0)
 *	      continue
 *	    if (new_path)
 *	      goto set_new_path
 *	    free (ptr.old)
 *	    free (ptr.new)
 *	    ptr.old = ptr.new = 0
 *	    return 0
 *	  }
not_found:
 *	  ptr = open_mapping_table
next_table_entry2:
 *	  while (ptr != open_mapping_table + MAX_TABLE_ENTRIES * sizeof(...)) {
 *	    if (ptr.old != NULL)
 *	      continue
 *	    goto new_entry
 *	  }
full:
 *	  return -2
 *	}
 *
new_entry:
 *	if (new_path == NULL)
 *	  return 0
 *	ptr.old = alloc (sizeof(int) + old_size + 1)
 *	ptr.old->size = old_size
 *	strcpy (ptr.old->path, old_path)
 *	ptr.new = alloc (sizeof (int) + MAX_PATH_SIZE + 1)
set_new_path:
 *	ptr.new->size = new_size
 *	strcpy(ptr.new->path, new_path)
 *
 *	return 0
 *  }
 *
 */
.align 4
map_open_path:
	// epilog
	mflr	%r0
	stdu	%r1, -0xc0(%r1)
	std	%r24, 0x70(%r1)
	std	%r25, 0x78(%r1)
	std	%r26, 0x80(%r1)
	std	%r27, 0x88(%r1)
	std	%r28, 0x90(%r1)
	std	%r29, 0x98(%r1)
	std	%r30, 0xa0(%r1)
	std	%r31, 0xa8(%r1)
	std	%r0, 0xd0(%r1)
	mr	%r24, %r3
	mr	%r25, %r4

	cmpldi	%r3, 0
	beq	l_map_open_error
	BRANCH_ABSOLUTE(%r6, strlen)
	mr	%r29, %r3

	mr	%r3, %r25
	cmpldi	%r3, 0
	beq	l_map_open_unset
	BRANCH_ABSOLUTE(%r6, strlen)
l_map_open_unset:
	mr	%r30, %r3

	// check the map table
	MEM_BASE (%r31)
	LOAD_LABEL2 (%r26, %r31, open_mapping_table)
	ld	%r3, 0(%r26)
	cmpldi	%r3, 0
	bne	l_map_open_no_alloc

	li	%r3, 0x10*MAX_TABLE_ENTRIES
	li	%r4, 0x27
	BRANCH_ABSOLUTE(%r6, alloc)		// allocate the table
	std	%r3, 0(%r26)
	mr	%r26, %r3
	mr	%r28, %r26
	li	%r4, 0
	li	%r5, 0x10*MAX_TABLE_ENTRIES
l_map_open_memset:			// set all the data to 0
	subi	%r5, %r5, 8		// set %r5 to read the previous quad
	stdx	%r4, %r3, %r5		// Store byte %r6 to %r4[%r5]
	cmpldi	%r5, 0			// if %r5 reaches 0, end it
	bne	l_map_open_memset
	b	l_map_open_new_entry		// no need to scan it
l_map_open_no_alloc:
	// load the mapping_table in %r26
	ld	%r28, 0(%r26)
	mr	%r26, %r28
	addi	%r27, %r28, 0x10*MAX_TABLE_ENTRIES	// Set our limit
l_map_open_next_table_entry:
	cmpld	%r26, %r27
	beq	l_map_open_not_found	// If we reached our limit, we're done
	ld	%r3, 0(%r26)			// Load the old path structure
	cmplwi	%r3, 0
	beq	l_map_open_next_table_entry	// if empty entry, then try next
	addi	%r4, %r3, 4			// Load the path
	lwz	%r5, 0(%r3)			// Load the size of this path
	addi	%r26, %r26, 0x10		// skip to the next entry
	cmplw	%r5, %r29
	bne	l_map_open_next_table_entry	// if different size, then try next
	mr	%r3, %r24			// Load the old path to compare in %r3
	BRANCH_ABSOLUTE(%r6, strncmp)
	cmpldi	%r3, 0
	bne	l_map_open_next_table_entry	// If different, then go to next entry

	// We found the entry we wanted
	addi	%r26, %r26, -0x10		// Reset to the correct entry
	ld	%r3, 0x08(%r26)
	cmpwi	%r30, 0				// Check if we set or unset the entry
	bne	l_map_open_set_new_path		// Just overwrite the data in the
						// already allocated buffer

	ld	%r3, 0(%r26)			// free the entry if new path = NULL
	li	%r4, 0x27
	BRANCH_ABSOLUTE(%r6, free)
	ld	%r3, 8(%r26)
	li	%r4, 0x27
	BRANCH_ABSOLUTE(%r6, free)
	li	%r3, 0
	std	%r3, 0(%r26)
	std	%r3, 8(%r26)
	b	l_map_open_return_0
l_map_open_not_found:
	mr	%r26, %r28
l_map_open_next_table_entry2:
	cmpld	%r26, %r27
	beq	l_map_open_full			// If we reached our limit, we're done
	ld	%r3, 0(%r26)			// Load the path structure
	cmplwi	%r3, 0
	bne	l_map_open_next_table_entry2	// if empty entry, then try next
l_map_open_new_entry:
	cmpwi	%r30, 0
	beq	l_map_open_return_0		// If there is no new path, return
	addi	%r3, %r29, 5
	li	%r4, 0x27
	BRANCH_ABSOLUTE(%r6, alloc)		// allocate space for the old path
						// structure: size(4) + string + \x00
	std	%r3, 0(%r26)
	stw	%r29, 0(%r3)
	addi	%r3, %r3, 4
	mr	%r4, %r24
	BRANCH_ABSOLUTE(%r6, strcpy)

	li	%r3, 0x805
	li	%r4, 0x27
	BRANCH_ABSOLUTE(%r6, alloc)		// allocate space for the new path
						// structure: size(4) + 2048 + \x00
	std	%r3, 0x08(%r26)
l_map_open_set_new_path:
	stw	%r30, 0(%r3)
	addi	%r3, %r3, 4
	mr	%r4, %r25
	BRANCH_ABSOLUTE(%r6, strcpy)
	b	l_map_open_return_0
l_map_open_error:
	li	%r3, 0
	nor	%r3, %r3, %r3			// r3 is already 0 here, so make it -1
	b	l_map_open_return
l_map_open_full:
	li	%r3, 1
	nor	%r3, %r3, %r3			// return -2
	b	l_map_open_return
l_map_open_return_0:
	li	%r3, 0			// return 0
	b	l_map_open_return
l_map_open_return:
	// prolog
	ld	%r24, 0x70(%r1)
	ld	%r25, 0x78(%r1)
	ld	%r26, 0x80(%r1)
	ld	%r27, 0x88(%r1)
	ld	%r28, 0x90(%r1)
	ld	%r29, 0x98(%r1)
	ld	%r30, 0xa0(%r1)
	ld	%r31, 0xa8(%r1)
	ld	%r0, 0xd0(%r1)
	addi	%r1, %r1, 0xc0
	mtlr	%r0
	blr
map_open_path_end: