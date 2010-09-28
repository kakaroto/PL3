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
	cmpldi	%r5, 8
	bge	pl3_memcpy_64
	cmpldi	%r5, 4
	bge	pl3_memcpy_32
	cmpldi	%r5, 2
	bge	pl3_memcpy_16
	cmpldi	%r5, 1
	bge	pl3_memcpy_8
	b	pl3_memcpy_done
pl3_memcpy_64:
	subi	%r5, %r5, 8		// set %r5 to read the previous quad
	ldx	%r6, %r3, %r5		// Copy quad content of %r3[%r5] to %r6
	stdx	%r6, %r4, %r5		// Store quad %r6 to %r4[%r5]
	b	pl3_memcpy_done
pl3_memcpy_32:
	subi	%r5, %r5, 4		// set %r5 to read the previous word
	lwzx	%r6, %r3, %r5		// Copy word content of %r3[%r5] to %r6
	stwx	%r6, %r4, %r5		// Store word %r6 to %r4[%r5]
	b	pl3_memcpy_done
pl3_memcpy_16:
	subi	%r5, %r5, 2		// set %r5 to read the previous half-word
	lhzx	%r6, %r3, %r5		// Copy half-word content of %r3[%r5] to %r6
	sthx	%r6, %r4, %r5		// Store half-word %r6 to %r4[%r5]
	b	pl3_memcpy_done
pl3_memcpy_8:
	subi	%r5, %r5, 1		// set %r5 to read the previous byte
	lbzx	%r6, %r3, %r5		// Copy byte content of %r3[%r5] to %r6
	stbx	%r6, %r4, %r5		// Store byte %r6 to %r4[%r5]
pl3_memcpy_done:
	cmpldi	%r5, 0			// if %r5 reaches 0, end it
	bne	pl3_memcpy
	blr