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

DEFINE_FUNC_PTR(send_eth)

send_eth_res:
	mflr	%r0
	stdu	%r1, -0x80(%r1)
	std	%r31, 0x70(%r1)
	std	%r0, 0x90(%r1)

	mr	%r4, %r3
	mr	%r5, %r4
	
	MEM_BASE (%r31)
	LOAD_LABEL2 (%r31, %r31, send_eth_dma_region)
	ld	%r3, 0(%r31)

	bl	send_eth
	
	ld	%r31, 0x70(%r1)
	ld	%r0, 0x90(%r1)
	addi	%r1, %r1, 0x80
	mtlr	%r0
	blr

	
#endif /* __SEND_ETH_RES_H_S */