/*
 * dev_syscalls.S -- PS3 Jailbreak payload - Development system calls
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 * Copyright (C) Aaron Lindsay (Aaron')
 * Copyright (C) (subdub)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 */


syscall_6_peek_desc:
	QUAD_ABS2(syscall_6_peek)
syscall_7_poke_desc:
	QUAD_ABS2(syscall_7_poke)
syscall_8_alloc_desc:
	QUAD_ABS2(syscall_8_alloc)
syscall_9_free_desc:
	QUAD_ABS2(syscall_9_free)
syscall_10_peek_desc:
	QUAD_ABS2(syscall_10_exec)


syscall_6_peek:
	ld	%r3, 0x00(%r3)
	blr

syscall_7_poke:
	std	%r4, 0x00(%r3)
	blr	
	
syscall_8_alloc:
	li	%r4, 0x27
	b	ABSOLUTE_MEM2(alloc)
	
syscall_9_free:
	li	%r4, 0x27
	b	ABSOLUTE_MEM2(free)

syscall_10_exec:
	mtctr	%r3
	bctr