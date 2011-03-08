/*
 * lv2_dump_analyser.idc -- Analyzes a PS3 LV2 dump in IDA.
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 * Copyright (C) (makeclean)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#include <idc.idc>

#include "syscall_names.idh"


static NameHypercalls(void) {
  auto addr, ea, num, lookup, total;

  total=0;
  Message("Looking for hypercalls.. \n");
  Message("This will take some time, please wait... \n");

  for ( ea = 0x8000000000000000; ea != 0x8000000000800000 && ea != BADADDR;) {
    ea = FindBinary(ea, 1, "44 00 00 22");
    if (ea == BADADDR)
      break;

    num = -1;
    for (lookup = 1; lookup < 48 && num == -1; lookup++) {
      addr = ea - (lookup * 4);
      /* Verify if it's a 'li %r11, XX' instruction */
      if ((Dword(addr) & 0xFFFFFF00) == 0x39600000) {
	num = Dword(addr) & 255;
	break;
      }
    }

    if (num == -1) {
      Message("Failed to find hypercall id at offset 0x%06X\n", ea);
    } else {
      total++;
      MakeComm(ea, form("hvsc(%d): lv1_%s", num, get_hvcall_rawname(num)));
    }
    ea = ea + 4;
  }

  Message("\n*** Finished marking hypercalls. Found %d !\n", total);
}

static CreateOpdStructure(void) {
  auto id;

  Message("Creating structure OPD_s\n");

  id = GetStrucIdByName("OPD_s");
  if (id != -1) {
    Message("Structure OPD_s already exists. Renaming it\n");
    if (SetStrucName(id, "OPD_s_renamed") == 0) {
      Message("Structure OPD_s_renamed already exists. deleting existing structure\n");
      DelStruc(id);
    }
    id = -1;
  }
  id = AddStrucEx(-1, "OPD_s", 0);
  if (id == -1) {
    Message ("Error creating OPD_S structure\n");
    return 0;
  }
  AddStrucMember(id, "sub", 0x00, FF_QWRD | FF_0OFF, 0, 8);
  AddStrucMember(id, "toc", 0x08, FF_QWRD | FF_0OFF, 0, 8);
  AddStrucMember(id, "env", 0x10, FF_QWRD | FF_DATA, -1, 8);


  return 1;
}


static CreateOpd (toc_addr) {
  auto ea, func;

  CreateOpdStructure();

  MakeName(toc_addr, "TOC");

  Message("Defining OPD section entries\n");

  ea = toc_addr - 0x8000;
  /* Find last OPD entry */
  while (ea != BADADDR && Qword(ea - 0x10) != toc_addr) {
    ea = ea - 0x08;
  }

  while (ea != BADADDR && Qword(ea - 0x10) == toc_addr) {
    ea = ea - 0x18;
    MakeUnknown(ea, 0x18, DOUNK_SIMPLE);
    MakeStructEx (ea, 0x18, "OPD_s");
    func = Qword(ea);
    MakeFunction(func, BADADDR);
  }
}


static CreateTocStructure(void) {
  auto id;

  Message("Creating structure TOC_s\n");

  id = GetStrucIdByName("TOC_s");
  if (id != -1) {
    Message("Structure TOC_s already exists. Renaming it\n");
    if (SetStrucName(id, "TOC_s_renamed") == 0) {
      Message("Structure TOC_s_renamed already exists. deleting existing structure\n");
      DelStruc(id);
    }
    id = -1;
  }
  id = AddStrucEx(-1, "TOC_s", 0);
  if (id == -1) {
    Message ("Error creating TOC_S structure\n");
    return 0;
  }
  AddStrucMember(id, "toc", 0, FF_QWRD | FF_0OFF, 0, 8);

  return 1;
}


static CreateToc (toc_addr) {
  auto ea;

  CreateTocStructure();

  MakeName(toc_addr, "TOC");

  Message("Defining TOC entries\n");

  ea = toc_addr - 0x8000;
  while (ea != toc_addr + 0x8000) {
    MakeUnknown(ea, 0x08, DOUNK_SIMPLE);
    MakeStructEx (ea, 0x08, "TOC_s");
    ea = ea + 0x08;
  }
}


static isSyscallTable(addr) {
    if (Qword(addr + 8*1) != Qword(addr) &&
	Qword(addr + 8*2) != Qword(addr) &&
	Qword(addr + 8*3) != Qword(addr) &&
	Qword(addr + 8*14) != Qword(addr) &&
	Qword(addr + 8*15) == Qword(addr) &&
	Qword(addr + 8*16) == Qword(addr) &&
	Qword(addr + 8*17) == Qword(addr) &&
	Qword(addr + 8*18) != Qword(addr) &&
	Qword(addr + 8*19) != Qword(addr) &&
	Qword(addr + 8*20) == Qword(addr) &&
	Qword(addr + 8*21) != Qword(addr) &&
	Qword(addr + 8*32) == Qword(addr) &&
	Qword(addr + 8*33) == Qword(addr) &&
	Qword(addr + 8*41) != Qword(addr) &&
	Qword(addr + 8*42) == Qword(addr) &&
	Qword(addr + 8*43) != Qword(addr)) {
      return 1;
    } else {
      return 0;
    }
}


static FindSyscallTable(void) {
  auto ea, syscall_table;

  syscall_table = AskAddr(BADADDR, "If you know the location of the syscall table, "
			  "please enter it.\nOtherwise, press Cancel :");

  if (syscall_table != BADADDR) {
    if (isSyscallTable(syscall_table) == 1) {
      Message ("Entered syscall table seems valid, proceding..\n");
    } else {
      Message ("Entered syscall table seems invalid. Will search instead\n");
      syscall_table = BADADDR;
    }
  }
  if (syscall_table == BADADDR) {
    Message("Looking for syscall table.. \n");
    Message("This will take some time, please wait... \n");
    for (ea = 0x8000000000400000; ea != 0x8000000000000000 && ea != BADADDR; ea = ea - 8 ) {
      if ((ea & 0xffff) == 0)
	Message ("Currently at 0x%x\n", ea);
      if (isSyscallTable(ea)) {
	Message ("\n*** Found syscall table at offset 0x%X\n", ea);
	syscall_table = ea;
	break;
      }
    }
    if (syscall_table == BADADDR) {
      Message ("Could not find syscall table in the first 4MB, trying higher memory\n");
      for (ea = 0x8000000000400000; ea != 0x80000000800000 && ea != BADADDR; ea = ea + 8 ) {
	if ((ea & 0xffff) == 0)
	  Message ("Currently at 0x%x\n", ea);
	if (isSyscallTable(ea)) {
	  Message ("\n*** Found syscall table at offset 0x%X\n", ea);
	  syscall_table = ea;
	  break;
	}
      }
    }
  }

  return syscall_table;
}

static CreateSyscallTable(syscall_table) {
  auto i, name, syscall_desc, syscall;

  MakeName(syscall_table, "syscall_table");

  Message ("Naming syscall elements\n");

  /* Search last to first to get the not_implemented syscall named correctly as sc0 */
  for (i = 1023; i != -1; i-- )
  {
    name = get_lv2_rawname(i);

    MakeQword(syscall_table + 8 * i);
    MakeComm(syscall_table + 8 * i, form("Syscall %d", i));
    syscall_desc = Qword(syscall_table + 8 * i);

    MakeQword(syscall_desc);
    MakeName(syscall_desc, form("syscall_%s_desc", name));
    syscall = Qword(syscall_desc);
    MakeFunction (syscall, BADADDR);
    MakeName(syscall, form("syscall_%s", name));
  }
}

static main() {
  auto syscall_table, toc;

  syscall_table = FindSyscallTable();

  if (syscall_table == BADADDR) {
    Message ("Could not find the syscall table\n");
    return;
  }

  CreateSyscallTable(syscall_table);

  /* Each syscall entry is a TOC entry, so get the toc pointer stored in it */
  toc = Qword(Qword(syscall_table) + 0x08);

  if (toc == BADADDR) {
    Message ("Could not find the TOC\n");
    return;
  }

  Message (form("\n*** Found TOC at : 0x%X\n", toc));
  CreateToc(toc);
  CreateOpd(toc);

  NameHypercalls();

  Message ("\n*** All done!!\n");
  Message (form("*** Found syscall table at : 0x%X and labeled 'syscall_table'\n", syscall_table));
  Message (form("*** Found TOC at : 0x%X and labeled 'TOC'\n", toc));
  Message ("*** Don't forget to go to Options->General->Analys\n");
  Message ("*** Then click on the 'Processor specific analysis options' button\n");
  Message (form("*** And set the TOC address to 0x%X (or simply to the symbol 'TOC')\n", toc));

  return;
}
