/*
 * send_eth_res.h.s -- PS3 Jailbreak payload - Resident area for send_eth
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#ifndef __SEND_ETH_RES_H_S__
#define __SEND_ETH_RES_H_S__

send_eth_dma_region:	
	.quad	0

send_eth_ptr:
	.quad	0
send_eth_mutex:
	.long   0

send_eth:
	mflr	%r0
	stdu	%r1, -0x80(%r1)
	std	%r30, 0x70(%r1)
	std	%r31, 0x78(%r1)
	std	%r0, 0x90(%r1)
	
	LOAD_LABEL2 (%r31, %r31, send_eth_mutex)
	lwz     %r30, 0(%r31)
	cmpwi   %r30, 0
	bne     l_send_eth_locked
	li      %r30, -1
	stw     %r30, 0(%r31)

	mr	%r5, %r4
	mr	%r4, %r3
	
	MEM_BASE (%r31)
	LOAD_LABEL2 (%r31, %r31, send_eth_dma_region)
	ld	%r3, 0(%r31)

	BRANCH_FUNC_PTR(%r31, send_eth)

	MEM_BASE (%r31)
	LOAD_LABEL2 (%r31, %r31, send_eth_mutex)
	li      %r30, 0
	stw     %r30, 0(%r31)

l_send_eth_locked:
	ld	%r30, 0x70(%r1)
	ld	%r31, 0x78(%r1)
	ld	%r0, 0x90(%r1)
	addi	%r1, %r1, 0x80
	mtlr	%r0
	blr

	
#endif /* __SEND_ETH_RES_H_S */