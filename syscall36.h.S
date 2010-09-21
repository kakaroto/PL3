/*
 * syscall36.S -- PS3 Jailbreak payload - Adds system call 36 code
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 * Copyright (C) Aaron Lindsay (Aaron')
 * Copyright (C) (subdub)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */



syscall_36_map_bdvd_desc:
	QUAD_MEM2 (syscall_36_map_bdvd)


/**
 * syscall_36_map_bdvd:
 * @path: The path to use for bdvd redirection
 *
 * This new syscall will redirect all file access from /dev_bdvd to
 * the path specified in argument here.
 *
 *  syscall_36 (path):
 *  {
 *    char *tmp = strdup(path);
 *
 *    if (game_path)
 *      free (game_path);
 *    game_path = malloc (2048);
 *    strcpy (game_path, tmp);
 *    free (tmp);
 *    game_path_end = game_path + strlen(game_path);
 *    return 0;
 *  }
 */
syscall_36_map_bdvd:
	stdu	%r1, -0xd0(%r1)
	mflr	%r0
	std	%r0, 0xe0(%r1)
	std	%r31, 0xc8(%r1)
	addi	%r4, %r1, 0x70
	bl	ABSOLUTE_MEM2(strdup)	// strdup %arg3 into %r1[0x70]
	MEM_BASE (%r31)
	LOADI_LABEL2 (%r31, game_path)
	ld	%r3, 0(%r31)
	cmpdi	%r3, 0			// if game_path != NULL: free(game_path)
	beq	l_game_path_null
	li	%r4, 0x27
	bl	ABSOLUTE_MEM2(free)
l_game_path_null:
	li	%r4, 0x27
	li	%r3, 0x800
	bl	ABSOLUTE_MEM2(alloc)	// alloc (2048)
	std	%r3, 0(%r31)
	ld	%r4, 0x70(%r1)
	bl	ABSOLUTE_MEM2(strcpy)
	ld	%r3, 0x70(%r1)
	li	%r4, 0x27
	bl	ABSOLUTE_MEM2(free)
	ld	%r3, 0(%r31)
	bl	ABSOLUTE_MEM2(strlen)
	ld	%r4, 0(%r31)
	add	%r3, %r4, %r3
	std	%r3, 8(%r31)
	li	%r3, 0			// return 0
	ld	%r31, 0xc8(%r1)
	ld	%r0, 0xe0(%r1)
	addi	%r1, %r1, 0xd0
	mtlr	%r0
	blr
