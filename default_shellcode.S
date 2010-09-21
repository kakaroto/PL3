/*
 * default_payload.S -- PS3 Jailbreak payload
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 * Copyright (C) Aaron Lindsay (Aaron')
 * Copyright (C) (subdub)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 * This code is based in part on:
 * PSGroove
 *
 */

#include "macros.h.S"

.org 0
/**
 * shellcode:
 *
 * 
 */
/* JIG payload. Must not exceed 40 bytes */
shellcode:
	ld	%r4, -0x10(%r3)
	ld	%r3, -0x8(%r3)
l_loop:
	ld	%r5, 0x18(%r3)
	addi	%r3, %r3, PAGE_SIZE
	cmpw	%r4, %r5
	bne	l_loop
	subi	%r3, %r3, PAGE_SIZE
	addi	%r6, %r3, PAYLOAD_OFFSET_IN_PAGE
	mtctr	%r6
	bctr
.org 0x28
