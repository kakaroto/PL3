/*
 * send_eth.h.s -- PS3 Jailbreak payload - Send data through ethernet
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#ifndef __SEND_ETH_H_S__
#define __SEND_ETH_H_S__

#include "macros.h.S"

	
.align 4
send_eth_init:
	mflr	%r0
	stdu	%r1, -0xa0(%r1)
	std	%r27, 0x78(%r1)
	std	%r28, 0x80(%r1)
	std	%r0, 0xb0(%r1)

	lis	%r3, 1		// size = 64K
	li	%r4, 16		// page_size_exp
	li	%r5, 0		// unknown
	li	%r6, 0		// flags
	li	%r11, 0		// lv1_allocate_memory
	sc	1		// lv1 syscall
	
	cmpwi	%r3, 0
	bne	l_send_eth_init_done

	mr	%r27, %r4	// rgn address
	
	li	%r3, 1		// bus_id = 1
	li	%r4, 0		// dev_id = 0
	lis	%r5, 1		// io_size = map_end - map_start
	li	%r6, 16		// io_page_size = 12
	li	%r7, 0		// flag = 0 == (32 bit mode)
	li	%r11, 174	// lv1_allocate_device_dma_region
	sc	1		// lv1 syscall
	
	cmpwi	%r3, 0
	bne	l_send_eth_init_done

	mr	%r28, %r4	// dma_region
	
	li	%r3, 1		// bus_id = 1
	li	%r4, 0		// dev_id = 0
	mr	%r5, %r27	// lpar_addr = map_start
	mr	%r6, %r28	// dma_region
	lis	%r7, 1		// io_size = map_end - map_start
	li	%r8, 0xF8;
	rldicr	%r8, %r8, 56, 7 // flags = 0xF800000000000000
	li	%r11, 176	// lv1_map_device_dma_region
	sc	1		// lv1 syscall
	
	cmpwi	%r3, 0
	bne	l_send_eth_init_done

	// vaddr = map_addr & ~0x8000000000000000
	MEM_BASE(%r3)
	oris	%r3, %r3, 0x1337
	clrldi	%r3, %r3, 1	// clear high bit of memory to give real mem

	
	// temp1 = vaddr >> 28
	rldicl	%r4, %r3, 36, 28
	// temp2 = vaddr & 0x0FFFFFFF
	lis	%r7, 0x0FFF
	ori	%r7, %r7, 0xFFFF
	and	%r7, %r3, %r7
	// hash = temp1 ^ (temp2 >> 12)
	rldicl	%r7, %r7, 52, 12
	xor	%r4, %r4, %r7

	// htab_hash_mask = ((256*1024)>>7)-1 = 0x7FF
	li	%r7, 0x7FF
	// hpte_group = (hash & htab_hash_mask) * 8
	and	%r4, %r4, %r7
	rldicr	%r4, %r4, 3, 60
	
	// hpte_v = (vaddr >> 23) << 7
	rldicl	%r5, %r3, 41, 23
	rldicr	%r5, %r5, 7, 56
	// hpte_v |= 0x01
	ori	%r5, %r5, 0x01

	// htpe_r = lpar | 0x38
	ori	%r6, %r27, 0x38
	
	li	%r3, 0		// htab_id = 0
	li	%r7, 0x10	// bolted_flag
	li	%r8, 0		// flags
	li	%r11, 158	// lv1_insert_htab_entry
	sc	1		// lv1 syscall

	cmpwi	%r3, 0
	bne	l_send_eth_init_done
	
	mr	%r4, %r28
	
l_send_eth_init_done:
	ld	%r27, 0x78(%r1)
	ld	%r28, 0x80(%r1)
	ld	%r0, 0xb0(%r1)
	addi	%r1, %r1, 0xa0
	mtlr	%r0
	blr

	
send_eth:
	mflr	%r0
	stdu	%r1, -0xa0(%r1)
	std	%r27, 0x78(%r1)
	std	%r28, 0x80(%r1)
	std	%r30, 0x90(%r1)
	std	%r31, 0x98(%r1)
	std	%r0, 0xb0(%r1)

	mr	%r30, %r3
	mr	%r27, %r4
	mr	%r28, %r5
		
	MEM_BASE(%r31)
	oris	%r31, %r31, 0x1337
	
	// store bus_addr
	addi	%r4, %r30, pkt_header
	stw	%r4, gelic_buf_addr(%r31)

	// Set cmd_status to CARDOWNED | IKE | NO_CHKSUM | TX_DMA_FRAME_TAIL
	lis	%r4, 0xa00C
	stw	%r4, gelic_dmac_cmd_status(%r31)

	// Set result_size and data_status to 0
	li	%r4, 0
	stw	%r4, gelic_result_size(%r31)
	stw	%r4, gelic_data_status(%r31)
	stw	%r4, gelic_next_desc_addr(%r31)
	stw	%r4, gelic_valid_size(%r31)
	stw	%r4, gelic_data_error(%r31)

	
	li	%r3, 1		// bus_id = 1
	li	%r4, 0		// dev_id = 0
	li	%r5, 1		// p1 = GELIC_NET_GET_MAC_ADDRESS
	li	%r6, 0		// p2 = 0
	li	%r7, 0		// p3 = 0
	li	%r8, 0		// p4 = 0
	li	%r11, 194	// lv1_net_control
	sc	1		// lv1 syscall
	
	cmpwi	%r3, 0
	bne	l_send_eth_done
	

	// Store mac address
	stw	%r4, (eth_src + 2)(%r31)
	rldicl	%r4, %r4, 32, 32
	sth	%r4, (eth_src)(%r31)

	li	%r4, 0
	nor	%r4, %r4, %r4
	sth	%r4, (eth_dest)(%r31)
	stw	%r4, (eth_dest + 2)(%r31)
	
	li	%r4, 0x81
	rldicr	%r4, %r4, 8, 55
	sth	%r4, eth_type(%r31)
	
	li	%r3, 1		// bus_id = 1
	li	%r4, 0		// dev_id = 0
	li	%r5, 4		// p1 = GELIC_NET_GET_MAC_VLAN_ID
	li	%r6, 2		// p2 = GELIC_NET_VLAN_TX_ETHERNET_0
	li	%r7, 0		// p3 = 0
	li	%r8, 0		// p4 = 0
	li	%r11, 194	// lv1_net_control
	sc	1		// lv1 syscall

	cmpwi	%r3, 0
	bne	l_send_eth_no_vlan

	// Store vlan id
	sth	%r4, vlan_id(%r31)
l_send_eth_no_vlan:
	li	%r4, 0x1337
	sth	%r4, vlan_type(%r31)

	addi	%r3, %r28, (eth_data - pkt_header)
        stw	%r3, gelic_buf_size(%r31)
	
	addi	%r4, %r31, eth_data
	
	// Copy the lv2 ram into the message
	mr	%r3, %r27
	mr	%r5, %r28
l_send_eth_memcpy:
	subi	%r5, %r5, 1		// set %r5 to read the previous byte
	lbzx	%r6, %r3, %r5		// Copy byte content of %r3[%r5] to %r6
	stbx	%r6, %r4, %r5		// Store byte %r6 to %r4[%r5]
	cmpldi	%r5, 0			// if %r5 reaches 0, end it
	bne	l_send_eth_memcpy

	// Start DMA transfer
	li	%r3, 1		// bus_id = 1
	li	%r4, 0		// dev_id = 0
	mr	%r5, %r30	// dma_region
	li	%r6, 0		// unknown = 0
	li	%r11, 187	// lv1_net_start_tx_dma
	sc	1		// lv1 syscall
	
	cmpwi	%r3, 0
	bne	l_send_eth_done

l_send_eth_wait_completion:	
	lwz	%r3, gelic_dmac_cmd_status(%r31)
	lis	%r4, 0xf000
	and	%r3, %r3, %r4
	lis	%r4, 0xa000
	cmpw	%r3, %r4
	beq	l_send_eth_wait_completion

	li	%r3, 0
l_send_eth_done:
	ld	%r27, 0x78(%r1)
	ld	%r28, 0x80(%r1)
	ld	%r30, 0x90(%r1)
	ld	%r31, 0x98(%r1)
	ld	%r0, 0xb0(%r1)
	addi	%r1, %r1, 0xa0
	mtlr	%r0
	blr
	
	.set	gelic_buf_addr, 0x00
	.set	gelic_buf_size, 0x04
	.set	gelic_next_desc_addr, 0x08
	.set	gelic_dmac_cmd_status, 0x0C
	.set	gelic_result_size, 0x10
	.set	gelic_valid_size, 0x14
	.set	gelic_data_status, 0x18
	.set	gelic_data_error, 0x1C
	.set	pkt_header, 0x100
	.set	eth_dest, 0x100
	.set	eth_src, 0x106
	.set	eth_type, 0x10C
	.set	vlan_id, 0x10E
	.set	vlan_type, 0x110
	.set	eth_data, 0x112

#endif /* __SEND_ETH_H_S__ */
