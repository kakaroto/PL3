/*
 * payload_dev.S -- PS3 Jailbreak payload : payload for developers (adds peek/poke)
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


/* pl3.h.S must always be included first!!! */
#include "pl3.h.S"

#include "map_open_path.h.S"
#include "memory_patching.h.S"

RESIDENT_AREA_START()
#include "dev_syscalls.h.S"
#include "open_hook.h.S"
#include "memory_patching_res.h.S"
RESIDENT_AREA_END()

// Include patch_table after all other includes so it picks up on what
// patches to include in the table depending on what was included
#include "patch_table.h.S"

payload_main:
	// epilog
	mflr	%r0
	stdu	%r1, -0xa0(%r1)
	std	%r30, 0x90(%r1)
	std	%r31, 0x98(%r1)
	std	%r0, 0xb0(%r1)

	GET_CURRENT_PAGE(%r3, %r31)
	MEM_BASE (%r30)			// Load 0x8000000000000000 in %r30

	COPY_RESIDENT_AREA(%r30, %r31)

	// Allocate memory and copy PIC functions to it
	LOAD_FUNC_PTR(memory_patching)
	LOAD_FUNC_PTR(map_open_path)

	ADD_SYSCALL (%r30, syscall_peek_desc, 6)
	ADD_SYSCALL (%r30, syscall_poke_desc, 7)
	ADD_SYSCALL (%r30, syscall_map_open_desc, 35)

	// Add default /app_home redirection
	addi	%r3, %r31, ADDR_IN_PAGE(path_app_home)
	addi	%r4, %r31, ADDR_IN_PAGE(path_usb_default_app_home)
	bl	map_open_path

	APPLY_PATCHES(%r30, %r31)

	// prolog
	ld	%r30, 0x90(%r1)
	ld	%r31, 0x98(%r1)
	ld	%r0, 0xb0(%r1)
	addi	%r1, %r1, 0xa0
	mtlr	%r0
	blr

path_app_home:
	.string "/app_home"
path_usb_default_app_home:
	.string "/dev_usb000/PS3/HOMEBREW/APP_HOME"
