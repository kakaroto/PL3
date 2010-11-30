/*
 * payload_trace_syscalls.S: PL3: hook syscall handler and trace the syscall
 *				  calls and arguments over ethernet
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

RESIDENT_AREA_START()
#include "memory_patching_res.h.S"
#include "send_eth_res.h.S"
#include "syscall_handler.h.S"
#include "print_debug.h.S"
RESIDENT_AREA_END()

#include "patch_table.h.S"

payload_main:
	// prolog
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

	// epilog
	ld	%r30, 0x90(%r1)
	ld	%r31, 0x98(%r1)
	ld	%r0, 0xb0(%r1)
	addi	%r1, %r1, 0xa0
	mtlr	%r0
	blr
