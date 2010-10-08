/*
 * pl3_memcpy.S -- PS3 Jailbreak payload : Memcpy function
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */


#ifndef __PL3_MEMCPY_H_S__
#define __PL3_MEMCPY_H_S__

	
.align 4
pl3_memcpy:
	cmpldi	%r5, 0			// if %r5 reaches 0, end it
	beq	l_pl3_memcpy_done
	subi	%r5, %r5, 1		// set %r5 to read the previous byte
	lbzx	%r6, %r4, %r5		// Copy byte content of %r3[%r5] to %r6
	stbx	%r6, %r3, %r5		// Store byte %r6 to %r4[%r5]
	b	pl3_memcpy
l_pl3_memcpy_done:
	blr

#endif /* __PL3_MEMCPY_H_S__ */

