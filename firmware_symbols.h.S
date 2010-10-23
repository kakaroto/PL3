/*
 * firmware_symbols.h.S -- PS3 Jailbreak payload macros : firmware specific
 * function symbols offsets
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 * Copyright (C) Aaron Lindsay (Aaron')
 * Copyright (C) (subdub)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#ifndef __FIRMWARE_SYMBOLS_H_S__
#define __FIRMWARE_SYMBOLS_H_S__

#ifdef FIRMWARE_3_41

/* Common Symbols */
#define memcpy 			0x7c01c
#define memset 			0x4d144
#define strcpy 			0x4d2f0
#define strncmp	 		0x4d344
#define strlen			0x4d318
#define strdup_from_user	0x1b3b3c // FIXME: unsure of the name!
#define alloc 			0x62088
#define free 			0x624c8
#define add_kernel_module 	0xd22d8
#define syscall_table		0x2eb128
#define get_device_descriptor	0xd2998 // FIXME: unsure of the name!
#define unknown_func1		0xd29c4 // FIXME
#define unknown_func2		0xd292c // FIXME
#define memory_patch_func	0x4e81c
#define patch_func1		0x0490AC
#define patch_func1_offset	0x34
#define patch_func2		0x04F07C
#define patch_func2_offset	0x2C
#define patch_func3		0x2aafc8
#define patch_func3_offset	0x24
#define patch_func4		0x04ed18
#define patch_func4_offset	0x0
#define patch_func5		0x0505d0
#define patch_func5_offset	0x0
#define patch_func6		0x0234d0
#define patch_func6_offset	0x0
#define patch_func7		0x0e83d4
#define patch_func7_offset	0x0
#define patch_func8		0x057214 //lv2open update patch
#define patch_func8_offset1	0xA4 //lv2open update patch
#define patch_func8_offset2	0x208 //lv2open update patch
#define patch_func9		0x4FC2C // must upgrade error
#define patch_func9_offset	0x0
#define patch_data1		0x3ba890
#define rtoc_entry_1		0xf08
#define rtoc_entry_2		-0x6a00

// Payload bases
#define MEM_BASE2 		(0x50B3C)
	
#define RESIDENT_PAYLOAD_MAXSIZE   (1296)

#ifdef KIOSK
#define HASH_TABLE_1            0xA0577BB4002C8B20
#define HASH_TABLE_2            0x6B7028FE00020041
#define HASH_TABLE_3            0x8c0a948c000d93D3
#define HASH_TABLE_4            0xA2BC0C1E0004C6E2

#define elf1_func1              0x5F223C
#define elf1_func1_offset       0x00
#define elf1_func2              0x304F54
#define elf1_func2_offset       0x14
#define elf2_func1              0x2EB44
#define elf2_func1_offset       0x374

#define elf3_data               0x0022A758
#define elf4_data               0x000c86c8

#else /* KIOSK */

#define HASH_TABLE_1		0xa0556f3d002cb8fd
#define HASH_TABLE_2		0x6b70280200020017
#define HASH_TABLE_3		0x8c0a948c000d99b1
#define HASH_TABLE_4		0xa2bc1a5600052adc

#define elf1_func1		0x5f3fc0
#define elf1_func1_offset	0x00
#define elf1_func2		0x305354
#define elf1_func2_offset	0x14
#define elf2_func1		0x2eb7c
#define elf2_func1_offset	0x374
	
#define elf3_data		0x0022b888
#define elf4_data		0x000d68b8
#endif /* KIOSK */

#elif defined(FIRMWARE_3_15)

/* Common Symbols */
#define memcpy			0x7be9c
#define memset			0x4cc00
#define strcpy			0x4cdac
#define strncmp			0x4ce00
#define strlen			0x4cdd4
#define strdup_from_user	0x1b3d08 // FIXME: unsure of the name!
#define alloc			0x61cf0
#define free			0x62138
#define add_kernel_module	0x12A7AC // DONE
#define syscall_table		0x2ea820
#define get_device_descriptor	0x12A1B4 // DONE
#define unknown_func1		0xE0928 // DONE
#define unknown_func2		0xD3408 // DONE
#define memory_patch_func	0x4e310
#define patch_func1		0x048a64
#define patch_func1_offset	0x34
#define patch_func2		0x04eb48
#define patch_func2_offset	0x2C
#define patch_func3		0x2aabec
#define patch_func3_offset	0x24
#define patch_func4		0x04e7e4
#define patch_func4_offset	0x0
#define patch_func5		0x05009c
#define patch_func5_offset	0x0
#define patch_func6		0x237E0
#define patch_func6_offset	0x0
#define patch_func7		0xE8E98
#define patch_func7_offset	0x0
#define patch_func8		0x56C3C
#define patch_func8_offset1	0x68
#define patch_func8_offset2	0x1CC
#define patch_func9		0x4F6F8 // must upgrade error
#define patch_func9_offset	0x0
#define patch_data1		0x3B9910
#define rtoc_entry_1		0xd58
#define rtoc_entry_2		-0x6b08

// Payload bases
#define MEM_BASE2 		(0x50608)

#define RESIDENT_PAYLOAD_MAXSIZE   (1296)

#define HASH_TABLE_1		0xA06FF29B002C284A
#define HASH_TABLE_2		0x6B7028220001E53E
#define HASH_TABLE_3		0x8C0A948C000C7AA6
#define HASH_TABLE_4		0x7FE3F53F000508D5

#define elf1_func1		0x5e3aec
#define elf1_func1_offset	0x00
#define elf1_func2		0x2fb05c
#define elf1_func2_offset	0x14
#define elf2_func1		0xe518
#define elf2_func1_offset	0x374

#define elf3_data		0x00204048
#define elf4_data		0x000d3e10

#elif defined(FIRMWARE_3_10)

#define memcpy 			0x7BE98
#define memset 			0x4CBFC
#define strcpy 			0x4CDA8
#define strncmp	 		0x4CDFC
#define strlen			0x4CDD0
#define strdup_from_user	0x1b3d14 // FIXME: unsure of the name!
#define alloc 			0x61CEC
#define free 			0x62134
#define syscall_table		0x2EA820
#define memory_patch_func	0x4E30C

#define patch_func1		0x48A60
#define patch_func1_offset	0x34
#define patch_func2		0x4EB44
#define patch_func2_offset	0x2C
#define patch_func3		0x2AABF4
#define patch_func3_offset	0x24
#define patch_func4		0x4E7E0
#define patch_func4_offset	0x0
#define patch_func5		0x50098
#define patch_func5_offset	0x0
#define patch_func6		0
#define patch_func6_offset	0
#define patch_func7		0
#define patch_func7_offset	0
#define patch_func8		0
#define patch_func8_offset	0
#define patch_func9		0
#define patch_func9_offset	0
#define patch_data1		0x3B9990
#define rtoc_entry_1		0xD60
#define rtoc_entry_2		-0x6B08

#define MEM_BASE2 		(0x50604)

#define RESIDENT_PAYLOAD_MAXSIZE   (1296)

#define HASH_TABLE_1		0xA06F35DB002C221E
#define HASH_TABLE_2		0x6B7028220001E535
#define HASH_TABLE_3		0x8C0A948C000C79E5
#define HASH_TABLE_4		0x7FE3F5CF000508A4

#define elf1_func1		0x5E2C7C
#define elf1_func1_offset	0x00
#define elf1_func2		0x2FAA14
#define elf1_func2_offset	0x14
#define elf2_func1		0xe518
#define elf2_func1_offset	0x374

#define elf3_data	0x203e90
#define elf4_data	0xd3e28


#elif defined(FIRMWARE_3_01)

#define memcpy 			0x77E84
#define memset 			0x4A95C
#define strcpy 			0x4AAC4	
#define strncmp	 		0x4AB18
#define strlen			0x4AAEC
#define strdup_from_user	0x1ACAF4 // FIXME: unsure of the name!
#define alloc 			0x5DF4C
#define free 			0x5E38C
#define add_kernel_module 	
#define syscall_table		0x2CFB40
#define get_device_descriptor	 // FIXME: unsure of the name!
#define unknown_func1		 // FIXME
#define unknown_func2		 // FIXME
#define memory_patch_func	0x4BFF0

#define patch_func1		0x468C4
#define patch_func1_offset	0x34
#define patch_func2		0x04C824
#define patch_func2_offset	0x2C
#define patch_func3		0x291DEC
#define patch_func3_offset	0x24
#define patch_func4		0x4C4C0
#define patch_func4_offset	0x0
#define patch_func5		0x04DCA8
#define patch_func5_offset	0x0
#define patch_func6		0
#define patch_func6_offset	0
#define patch_func7		0
#define patch_func7_offset	0
#define patch_func8		0
#define patch_func8_offset	0
#define patch_func9		0
#define patch_func9_offset	0
#define patch_data1		0x39C010
#define rtoc_entry_1		0xD00
#define rtoc_entry_2		-0x6B30
	
#define MEM_BASE2 		(0x04E214)
	
#define RESIDENT_PAYLOAD_MAXSIZE   (1296)

#define HASH_TABLE_1		0xA00A6748002B0669
#define HASH_TABLE_2		0x6331A81B0001F7AC
#define HASH_TABLE_3		0x6A05EE84000BEBFC
#define HASH_TABLE_4		0xBF5574E70004FDD5

#define elf1_func1		0x5B009C
#define elf1_func1_offset	0x00
#define elf1_func2		0x219B44
#define elf1_func2_offset	0x14
#define elf2_func1		0xe578
#define elf2_func1_offset	0x374
	
#define elf3_data		0x001EAE98
#define elf4_data		0x000D1D00

#elif defined(FIRMWARE_2_76)

#define memcpy 			0x0007395C
#define memset 			0x00046850
#define strcpy 			0x000469B8
#define strncmp	 		0x00046A0C
#define strlen			0x000469E0
#define strdup			0x001A2270
#define alloc 			0x00059D54
#define free 			0x0005A194
#define add_kernel_module 	0x000CC6A0
#define syscall_table		0x002C4318
#define get_device_descriptor	0x000CCD2C
#define unknown_func1		0x000CCD58
#define unknown_func2		0x000CCCC0
#define memory_patch_func	0x00047EE4
#define patch_func1		0x00043828
#define patch_func1_offset	0x34
#define patch_func2		0x00048718
#define patch_func2_offset	0x2C
#define patch_func3		0x00286BDC
#define patch_func3_offset	0x0
#define patch_func4		0x000483B4
#define patch_func4_offset	0x0
#define patch_func5		0x00049AF0
#define patch_func5_offset	0x0
#define patch_func6		0x00022EE0
#define patch_func6_offset	0x80
#define patch_func7		0x000E1F04
#define patch_func7_offset	0x2C
#define patch_func8		0x000504BC // lv2open update patch
#define patch_func8_offset1	0x68
#define patch_func8_offset2	0x1CC
#define patch_func9		0x00048EDC // must upgrade patch
#define patch_func9_offset	0x3EC
#define patch_data1		0x0038E3E0
#define rtoc_entry_1		0x988
#define rtoc_entry_2		-0x6C50

// Payload bases
#define MEM_BASE2 		(0x4A05C)

#define RESIDENT_PAYLOAD_MAXSIZE   (1296)

#define HASH_TABLE_1		0xB35FF0D7002B53FF
#define HASH_TABLE_2		0xF662A7ED0001A3F8
#define HASH_TABLE_3		0x78D617A6000A25AB
#define HASH_TABLE_4		0x6CD46E1000044996

#define elf1_func1		0x5992D8
#define elf1_func1_offset	0x00
#define elf1_func2		0x160BC0
#define elf1_func2_offset	0x14
#define elf2_func1		0x2ed0c
#define elf2_func1_offset	0x00

#define elf3_data		0x001AA2C8
#define elf4_data		0x000B6BC0

#endif

#endif /* __FIRMWARE_SYMBOLS_H_S__ */