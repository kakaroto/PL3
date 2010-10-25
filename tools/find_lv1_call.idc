/*
 * find_lv1_call.idc -- Searches for a specific LV1 call in an lv2 dump and
 *                      prints the offsets where the lv1 call is used.
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


static FindHypercalls(id) {
        
  auto addr, ea, num, lookup, total;

  total=0;
  Message("Looking for hypercalls.. \n");
  Message("This will take some time, please wait... \n");

  for ( ea = 0; ea != 0x800000 && ea != BADADDR;) {
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
    } else if (num == id) {
      total++;
      Message(form("Found hypercall %s(%d) at address 0x%X\n", get_hvcall_rawname(num), num, ea));
    }
    ea = ea + 4;
  }
 
  Message("\n*** Finished searching hypercalls. Found %d !\n", total);
}

static main() {
  auto id;

  id = AskLong (id, "Enter the lv1 call id you want to look for");
  if (id == -1) {
    Message ("Canceled\n");
    return;
  }
  FindHypercalls(id);

  Message ("Done\n");

  return;
}
