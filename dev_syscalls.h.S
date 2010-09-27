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
	QUAD_MEM2(syscall_6_peek)
syscall_7_poke_desc:
	QUAD_MEM2(syscall_7_poke)


syscall_6_peek:
	ld	%r3, 0x00(%r3)
	blr

syscall_7_poke:
	std	%r4, 0x00(%r3)
	blr	