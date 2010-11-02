/*
 * find_stdu.idc -- Simply find 'stdu' instructions and make functions there.
 *                  Should be helpful to make IDA analyze raw elf chunks.
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#include <idc.idc>

static main() {
  auto ea;

  for ( ea = 0; ea != BADADDR;) {
    ea = FindBinary(ea, 1, "F8 21");
    if (ea == BADADDR)
      break;

    MakeFunction(ea, BADADDR);
    ea = ea + 4;
  }
}
