/*
 * payload_dump_syscalls.S -- PS3 Jailbreak payload - hook syscall handler and
 *                            dump the syscall arguments over ethernet
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


#include "pl3.h.S"

#include "send_eth.h.S"
#include "memory_patching.h.S"
#include "hook_hvsc.h.S"

RESIDENT_AREA_START()
#include "memory_patching_res.h.S"
#include "send_eth_res.h.S"
#include "vuart_tracer.h.S"
RESIDENT_AREA_END()

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

	LOAD_FUNC_PTR(memory_patching)
	LOAD_FUNC_PTR(send_eth)
	INIT_SEND_ETH(%r30)

	APPLY_PATCHES(%r30, %r31)

	// Replace hvsc after we copy our handler to the resident area
	// because another thread might be running at the same time
	// and if it calls hvsc and we're not yet ready, then we're
	// screwed
	bl	hook_hvsc

	// prolog
	ld	%r30, 0x90(%r1)
	ld	%r31, 0x98(%r1)
	ld	%r0, 0xb0(%r1)
	addi	%r1, %r1, 0xa0
	mtlr	%r0
	blr
