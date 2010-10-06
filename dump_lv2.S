/*
 * dump_lv2.S -- PS3 Jailbreak payload - dump lv2 using only syscalls
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */


#include "macros.h.S"

.org 0
// Position 0x38 in the page
payload_start:

payload_entry:
	mflr	%r0
	stdu	%r1, -0xa0(%r1)
	std	%r27, 0x78(%r1)
	std	%r28, 0x80(%r1)
	std	%r29, 0x88(%r1)
	std	%r30, 0x90(%r1)
	std	%r31, 0x98(%r1)
	std	%r0, 0xb0(%r1)

	GET_CURRENT_PAGE(%r3, %r31)

	bl	send_eth_init

	cmpwi	%r3, 0
	bne	l_done

	mr	%r30, %r4

	MEM_BASE (%r28)
	MEM_BASE (%r29)
	oris	%r29, %r29, 0x80

l_send_lv2_dump:

	addi	%r3, %r31, ADDR_IN_PAGE(message_offset)
	stw	%r28, 0(%r3)

	// Copy the lv2 ram into the message
	addi	%r3, %r31, ADDR_IN_PAGE(message)
	mr	%r4, %r28
	li	%r5, 1024
	bl	pl3_memcpy

	// Increment our lv2 pointer
	addi	%r28, %r28, 1024

	mr	%r3, %r30
	addi	%r4, %r31, ADDR_IN_PAGE(message_offset)
	li	%r5, 1028
	bl	send_eth

	cmpwi	%r3, 0
	bne	l_done

	cmpd	%r28, %r29
	beq	panic
	b	l_send_lv2_dump

l_done:
	ld	%r27, 0x78(%r1)
	ld	%r28, 0x80(%r1)
	ld	%r29, 0x88(%r1)
	ld	%r30, 0x90(%r1)
	ld	%r31, 0x98(%r1)
	ld	%r0, 0xb0(%r1)
	addi	%r1, %r1, 0xa0
	mtlr	%r0
	blr

panic:
	PANIC()

.align 4
message_offset:
	.long	0
message:
	.space	1024

#include "pl3_memcpy.h.S"
#include "send_eth.h.S"

payload_end:
