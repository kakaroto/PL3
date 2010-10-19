/*
 * dump_elfs_pcap_to_dir.h -- PS3 Jailbreak - dump ELFs pcap capture to directories
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>


typedef struct pcap_hdr_s {
  uint32_t magic_number;   /* magic number */
  uint16_t version_major;  /* major version number */
  uint16_t version_minor;  /* minor version number */
  int32_t  thiszone;       /* GMT to local correction */
  uint32_t sigfigs;        /* accuracy of timestamps */
  uint32_t snaplen;        /* max length of captured packets, in octets */
  uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
  uint32_t ts_sec;         /* timestamp seconds */
  uint32_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef struct ethernet_hdr_s {
  char dest[6];
  char src[6];
  uint16_t type;
} ethernet_hdr_t;

typedef struct vlan_hdr_s {
  uint16_t vlan_id;
  uint16_t type;
} vlan_hdr_t;

int main (int argc, char *argv[])
{
  FILE *in = NULL;
  FILE *out = NULL;
  pcaprec_hdr_t header;
  ethernet_hdr_t eth;
  vlan_hdr_t vlan;
  char path[1024];
  char buf[1028];
  int offset;
  int last_offset = -1;
  int ret;

  if (argc != 3) {
    printf ("Usage : %s in.pcap out_dir\n", argv[0]);
    return -1;
  }

  in = fopen (argv[1], "rb");
  if (in == NULL) {
    perror ("Could not open input file :");
    return -1;
  }

  ret = fread(buf, sizeof(pcap_hdr_t), 1, in);
  if (ret != 1) {
    printf ("Error reading pcap header\n");
    return -2;
  }

  if (mkdir (argv[2], 0777) == -1 && errno != EEXIST) {
    perror ("Error creating output directory ");
    return -3;
  }

  if (buf[0] != '\xd4' ||
      buf[1] != '\xc3' ||
      buf[2] != '\xb2' ||
      buf[3] != '\xa1') {
    printf ("Invalid file format : 0x%X\n", ((int *)buf)[0]);
    return -4;
  }

  while (1) {
    ret = fread(&header, sizeof(pcaprec_hdr_t), 1, in);
    if (ret != 1)
      break;
    ret = fread(&eth, sizeof(ethernet_hdr_t), 1, in);
    if (ret != 1)
      break;
    eth.type = ntohs (eth.type);
    header.incl_len -= sizeof(ethernet_hdr_t);
    /* check for VLAN packet type */
    if (eth.type == 0x8100) {
      ret = fread(&vlan, sizeof(vlan_hdr_t), 1, in);
      if (ret != 1)
        break;
      vlan.type = ntohs (vlan.type);
      header.incl_len -= sizeof(vlan_hdr_t);
    } else {
      vlan.type = 0;
    }
    /* If there's garbage, then ignore it */
    if (!(eth.type == 0x1337 || (eth.type == 0x8100 && vlan.type == 0x1337)) ||
        (header.incl_len != 64 && header.incl_len != 1028)) {
      char *temp = malloc (header.incl_len);
      if (temp == NULL) {
        printf ("memory allocation error: %d\n", header.incl_len);
        return -1;
      }
      ret = fread(temp, 1, header.incl_len, in);
      if (ret != header.incl_len)
        break;
      free (temp);
      continue;
    }

    ret = fread(buf, 1, header.incl_len, in);
    if (ret != header.incl_len)
      break;

    if (header.incl_len == 64) {
      char temp[17];
      uint32_t hash = ntohl (((uint32_t *)buf)[0]);
      uint32_t thingy = ntohl (((uint32_t *)buf)[1]);

      if (out) {
        printf ("File has %ld bytes\n", ftell (out));
        fclose (out);
        out = NULL;
      }

      snprintf (temp, sizeof(temp), "%08X%08X", hash, thingy);
      snprintf (path, sizeof(path), "%s/%s.bin", argv[2], temp);
      out = fopen (path, "wb");
      if (out == NULL) {
        perror ("Could not open output file :");
        fclose (in);
        return -1;
      }
      last_offset = 0;
      printf ("Now writing to file %s\n", path);
    } else if (out) {
      offset = ntohl (*((uint32_t *) buf));
      if (last_offset > 0 && offset != last_offset &&
          offset != last_offset + 1024) {
        printf ("WARNING: offset %X missing!!!\n", last_offset + 1024);
      }
      last_offset = offset;
      fseek (out, offset, SEEK_SET);
      fwrite (buf + 4, 1, 1024, out);
    }
  }

  fclose (in);
  if (out) {
    fseek (out, 0, SEEK_END);
    printf ("File has %ld bytes\n", ftell (out));
    fclose (out);
  }

  return 0;
}
