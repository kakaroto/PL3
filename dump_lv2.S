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
		
	lis	%r3, 1		// size = 64K
	li	%r4, 16		// page_size_exp
	li	%r5, 0		// unknown
	li	%r6, 0		// flags
	li	%r11, 0		// lv1_allocate_memory
	sc	1		// lv1 syscall
	
	cmpwi	%r3, 0
	bne	l_done

	mr	%r29, %r4	// rgn address
	
	li	%r3, 1		// bus_id = 1
	li	%r4, 0		// dev_id = 0
	lis	%r5, 1		// io_size = map_end - map_start
	li	%r6, 16		// io_page_size = 12
	li	%r7, 0		// flag = 0 == (32 bit mode)
	li	%r11, 174	// lv1_allocate_device_dma_region
	sc	1		// lv1 syscall
	
	cmpwi	%r3, 0
	bne	l_done

	mr	%r30, %r4	// dma_region
	
	li	%r3, 1		// bus_id = 1
	li	%r4, 0		// dev_id = 0
	mr	%r5, %r29	// lpar_addr = map_start
	mr	%r6, %r30	// dma_region
	lis	%r7, 1		// io_size = map_end - map_start
	li	%r8, 0xF8;
	rldicr	%r8, %r8, 56, 7 // flags = 0xF800000000000000
	li	%r11, 176	// lv1_map_device_dma_region
	sc	1		// lv1 syscall
	
	cmpwi	%r3, 0
	bne	l_done

	// vaddr = map_addr & ~0x8000000000000000
	li	%r27, 1
	rldicr	%r27, %r27, 63, 0;
	oris	%r27, %r27, 0x1337
	
	mr	%r3, %r27
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
	ori	%r6, %r29, 0x38
	

	li	%r3, 0		// htab_id = 0
	li	%r7, 0x10	// bolted_flag
	li	%r8, 0		// flags
	li	%r11, 158	// lv1_insert_htab_entry
	sc	1		// lv1 syscall
		
	cmpwi	%r3, 0
	bne	l_done
	
	// store bus_addr
	addi	%r3, %r31, ADDR_IN_PAGE(gelic_buf_addr)
	addi	%r4, %r30, 0x100
	stw	%r4, 0(%r3)


	li	%r3, 1		// bus_id = 1
	li	%r4, 0		// dev_id = 0
	li	%r5, 1		// p1 = GELIC_NET_GET_MAC_ADDRESS
	li	%r6, 0		// p2 = 0
	li	%r7, 0		// p3 = 0
	li	%r8, 0		// p4 = 0
	li	%r11, 194	// lv1_net_control
	sc	1		// lv1 syscall
	
	cmpwi	%r3, 0
	bne	l_done
	

	// Store mac address
	addi	%r3, %r31, ADDR_IN_PAGE(pkt_eth_src)
	stw	%r4, 2(%r3)
	rldicl	%r4, %r4, 32, 32
	sth	%r4, 0(%r3)
	
	li	%r3, 1		// bus_id = 1
	li	%r4, 0		// dev_id = 0
	li	%r5, 4		// p1 = GELIC_NET_GET_MAC_VLAN_ID
	li	%r6, 2		// p2 = GELIC_NET_VLAN_TX_ETHERNET_0
	li	%r7, 0		// p3 = 0
	li	%r8, 0		// p4 = 0
	li	%r11, 194	// lv1_net_control
	sc	1		// lv1 syscall

	cmpwi	%r3, 0
	bne	l_done

	// Store vlan id
	addi	%r3, %r31, ADDR_IN_PAGE(pkt_vlan_vlan)
	sth	%r4, 0(%r3)

	
	li	%r28, 1
	rldicr	%r28, %r28, 63, 0;
	
l_send_lv2_dump:	
	// Set cmd_status to CARDOWNED | IKE | NO_CHKSUM | TX_DMA_FRAME_TAIL
	lis	%r4, 0xa00C
	addi	%r3, %r31, ADDR_IN_PAGE(gelic_dmac_cmd_status)
	stw	%r4, 0(%r3)

	// Set result_size and data_status to 0
	li	%r4, 0
	addi	%r3, %r31, ADDR_IN_PAGE(gelic_result_size)
	stw	%r4, 0(%r3)
	addi	%r3, %r31, ADDR_IN_PAGE(gelic_data_status)
	stw	%r4, 0(%r3)

	// Copy the lv2 ram into the message
	mr	%r3, %r28
	addi	%r4, %r31, ADDR_IN_PAGE(message)
	stw	%r28, 0(%r4)
	addi	%r4, %r4, 4
	li	%r5, 1024
	bl	my_memcpy
	
	// Increment our lv2 pointer
	addi	%r28, %r28, 1024

	// Copy our block of data
	addi	%r3, %r31, ADDR_IN_PAGE(dma_block)
	mr	%r4, %r27
	li	%r5, (dma_block_end - dma_block)
	bl	my_memcpy
	
	// Start DMA transfer
	li	%r3, 1		// bus_id = 1
	li	%r4, 0		// dev_id = 0
	mr	%r5, %r30	// dma_region
	li	%r6, 0		// unknown = 0
	li	%r11, 187	// lv1_net_start_tx_dma
	sc	1		// lv1 syscall
	
	cmpwi	%r3, 0
	bne	l_done

l_wait_completion:	
	addi	%r3, %r27, (gelic_dmac_cmd_status - gelic_desc)
	lwz	%r3, 0(%r3)
	lis	%r4, 0xf000
	and	%r3, %r3, %r4
	lis	%r4, 0xa000
	cmpw	%r3, %r4
	beq	l_wait_completion

	li	%r3, 1
	rldicr	%r3, %r3, 63, 0;
	oris	%r3, %r3, 0x80
	cmpd	%r28, %r3
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
        li      %r3, 0
        li      %r11, 255
        sc      1

my_memcpy:
	subi	%r5, %r5, 8		// set %r5 to read the previous quad
	ldx	%r6, %r3, %r5		// Copy quad content of %r3[%r5] to %r6
	stdx	%r6, %r4, %r5		// Store quad %r6 to %r4[%r5]
	cmpldi	%r5, 0			// if %r5 reaches 0, end it
	bne	my_memcpy
	blr

.align 8
dma_block:
gelic_desc:	
gelic_buf_addr:	
	.long	0
gelic_buf_size:	
	.long	1046
gelic_next_desc_addr:	
	.long	0
gelic_dmac_cmd_status:
	.long	0xa00c0000
gelic_result_size:
	.long	0
gelic_valid_size:	
	.long	0
gelic_data_status:	
	.long	0
gelic_data_error:	
	.long	0
.org gelic_desc + 0x100
pkt:
pkt_eth:
pkt_eth_dest:
	.byte	0xFF
	.byte	0xFF
	.byte	0xFF
	.byte	0xFF
	.byte	0xFF
	.byte	0xFF
pkt_eth_src:
	.space	6
pkt_eth_type:
	.short	0x8100
pkt_vlan:
pkt_vlan_vlan:
	.short	0
pkt_vlan_subtype:
	.short	0x1337
message:
	.space 1028
.align 8
dma_block_end:
	
payload_end:
	// fill out to 3840 bytes
.org 3840