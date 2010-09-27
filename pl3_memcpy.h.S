/*
 * pl3_memcpy.S -- PS3 Jailbreak payload : Memcpy function
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

	
pl3_memcpy:
	subi	%r5, %r5, 4		// set %r5 to read the previous quad
	lwzx	%r6, %r3, %r5		// Copy quad content of %r3[%r5] to %r6
	stwx	%r6, %r4, %r5		// Store quad %r6 to %r4[%r5]
	cmpldi	%r5, 0			// if %r5 reaches 0, end it
	bne	pl3_memcpy
	blr