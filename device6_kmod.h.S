/*
 * device6_kmod.h.S -- PS3 Jailbreak payload - Device6 kernel module
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

kernel_module_name:
	.string "mod"
	
kernel_module_struct:
	QUAD_MEM2 (kernel_module_name)
	QUAD_MEM2 (device_match_desc)
	QUAD_MEM2 (device_connect_desc)
	QUAD_MEM2 (device_disconnect_desc)
device_match_desc:
	QUAD_MEM2 (device_match)
	.quad 0x800000000033E720
device_connect_desc:
	QUAD_MEM2 (device_connect)
	.quad 0x800000000033E720
device_disconnect_desc:
	QUAD_MEM2 (device_disconnect)
	.quad 0x800000000033E720
device_setup_response_desc:
	QUAD_MEM2 (device_setup_response)
	.quad 0x800000000033E720

/**
 * device_match:
 * @arg: Some unknown argument, maybe a driver structure
 *
 * This checks for new USB device insertion and validates the
 * vendorID/productID to match 0xaaaac0de (device 6).
 * returns 0 to handle it or -1 to refuse it.
 *
 * device_match(arg):
 * {
 *    char *descriptor = get_device_descriptor(arg, 0, 1);
 *
 *    if (*(uint32 *) (descriptor + 8)) == "0xAAAAC0DE)
 *      return 0;
 *    else
 *      return -1;
 *  }
 */
.align 4
device_match:
	stdu	%r1, -0x80(%r1)
	mflr	%r0
	std	%r0, 0x90(%r1)
	li	%r4, 0
	li	%r5, 1
	bl	ABSOLUTE_MEM2(get_device_descriptor)
	lwz	%r5, 8(%r3)
	li	%r3, 0
	lis	%r4, 0xaaaa
	ori	%r4, %r4, 0xc0de
	cmplw	%r4, %r5
	beq	l_device_found
	li	%r3, -1
l_device_found:
	extsw	%r3, %r3
	ld	%r0, 0x90(%r1)
	mtlr	%r0
	addi	%r1, %r1, 0x80
	blr

/**
 * device_connect:
 * @arg: Some unknown argument, maybe a driver structure
 *
 * This handles a connection of a USB device with the proper
 * productID/vendorID
 *
 * device_connect(arg):
 * {
 *    short buf[8];
 *
 *    unknown_func1(arg, 0);
 *    *((uint64_t *)buf) = 0;
 *    buf[0] = 0x21AA;
 *    buf[3] = 0;
 *    unknown_func2(arg, buf, 0, device_setup_response_desc, 0);
 *    return 0;
 *  }
 */
device_connect:
	stdu	%r1, -0x80(%r1)
	mflr	%r0
	std	%r0, 0x90(%r1)
	li	%r4, 0
	bl	ABSOLUTE_MEM2(unknown_func1)
	addi	%r4, %r1, 0x70		// Set %r4 to a pointer in the stack
	li	%r5, 0
	std	%r5, 0(%r4)		// %r4[0] = 0;
	li	%r6, 0x21aa
	sth	%r6, 0(%r4)		// %r4[0] = 0x21aa;
	li	%r6, 0
	sth	%r6, 6(%r4)		// %r4[6] = 0;
	MEM_BASE (%r6)
	LOADI_LABEL2 (%r6, device_setup_response_desc)
	li	%r7, 0
	bl	ABSOLUTE_MEM2(unknown_func2)
	li	%r3, 0
	ld	%r0, 0x90(%r1)
	mtlr	%r0
	addi	%r1, %r1, 0x80
	blr

/**
 * device_discconnect:
 * @arg: Some unknown argument, maybe a driver structure
 *
 * This handles a disconnection of a prviously handled USB device
 *
 *  device_discconnect(arg):
 *  {
 *  }
 */
device_disconnect:
	blr

/**
 * device_setup_response:
 * @arg: Some unknown argument, maybe a driver structure
 *
 * This seems to be a callback that gets called once the USB device
 * responds to a SETUP request.
 *
 *  device_setup_response(arg):
 *  {
 *  }
 */
device_setup_response:
	blr
