/*
 * dump_syscall.h -- PS3 Jailbreak - dump syscall trace
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

static const char *get_syscall_name(int num)
{
        if(     num ==   0) return "not_implemented";
        else if(num == 1) return "sys_process_getpid";
        else if(num == 2) return "sys_process_wait_for_child";
        else if(num == 4) return "sys_process_get_status";
        else if(num == 5) return "sys_process_detach_child";
        else if(num == 12) return "sys_process_get_number_of_object";
        else if(num == 13) return "sys_process_get_id";
        else if(num == 14) return "sys_process_is_spu_lock_line_reservation_address";
        else if(num == 18) return "sys_process_getppid";
        else if(num == 19) return "sys_process_kill";
        else if(num == 23) return "sys_process_wait_for_child2";
        else if(num == 25) return "sys_process_get_sdk_version";
        else if(num == 43) return "sys_ppu_thread_yield";
        else if(num == 44) return "sys_ppu_thread_join";
        else if(num == 45) return "sys_ppu_thread_detach";
        else if(num == 46) return "sys_ppu_thread_get_join_state";
        else if(num == 47) return "sys_ppu_thread_set_priority";
        else if(num == 48) return "sys_ppu_thread_get_priority";
        else if(num == 49) return "sys_ppu_thread_get_stack_information";
        else if(num == 56) return "sys_ppu_thread_rename";
        else if(num == 57) return "sys_ppu_thread_recover_page_fault";
        else if(num == 67) return "sys_trace_allocate_buffer";
        else if(num == 68) return "sys_trace_free_buffer";
        else if(num == 69) return "sys_trace_create2";
        else if(num == 70) return "sys_timer_create";
        else if(num == 71) return "sys_timer_destroy";
        else if(num == 72) return "sys_timer_get_information";
        else if(num == 73) return "_sys_timer_start";
        else if(num == 74) return "sys_timer_stop";
        else if(num == 75) return "sys_timer_connect_event_queue";
        else if(num == 76) return "sys_timer_disconnect_event_queue";
        else if(num == 80) return "sys_interrupt_tag_create";
        else if(num == 81) return "sys_interrupt_tag_destroy";
        else if(num == 84) return "_sys_interrupt_thread_establish";
        else if(num == 88) return "sys_interrupt_thread_eoi";
        else if(num == 89) return "_sys_interrupt_thread_disestablish";
        else if(num == 90) return "sys_semaphore_create";
        else if(num == 91) return "sys_semaphore_destroy";
        else if(num == 92) return "sys_semaphore_wait";
        else if(num == 93) return "sys_semaphore_trywait";
        else if(num == 94) return "sys_semaphore_post";
        else if(num == 100) return "sys_mutex_create";
        else if(num == 101) return "sys_mutex_destroy";
        else if(num == 102) return "sys_mutex_lock";
        else if(num == 103) return "sys_mutex_trylock";
        else if(num == 104) return "sys_mutex_unlock";
        else if(num == 105) return "sys_cond_create";
        else if(num == 106) return "sys_cond_destroy";
        else if(num == 107) return "sys_cond_wait";
        else if(num == 108) return "sys_cond_signal";
        else if(num == 109) return "sys_cond_signal_all";
        else if(num == 110) return "sys_cond_signal_to";
        else if(num == 114) return "sys_semaphore_get_value";
        else if(num == 120) return "sys_rwlock_create";
        else if(num == 121) return "sys_rwlock_destroy";
        else if(num == 122) return "sys_rwlock_rlock";
        else if(num == 123) return "sys_rwlock_tryrlock";
        else if(num == 124) return "sys_rwlock_runlock";
        else if(num == 125) return "sys_rwlock_wlock";
        else if(num == 126) return "sys_rwlock_trywlock";
        else if(num == 127) return "sys_rwlock_wunlock";
        else if(num == 128) return "sys_event_queue_create";
        else if(num == 129) return "sys_event_queue_destroy";
        else if(num == 130) return "sys_event_queue_receive";
        else if(num == 131) return "sys_event_queue_tryreceive";
        else if(num == 133) return "sys_event_queue_drain";
        else if(num == 134) return "sys_event_port_create";
        else if(num == 135) return "sys_event_port_destroy";
        else if(num == 136) return "sys_event_port_connect_local";
        else if(num == 137) return "sys_event_port_disconnect";
        else if(num == 138) return "sys_event_port_send";
        else if(num == 140) return "sys_event_port_connect_ipc";
        else if(num == 141) return "sys_timer_usleep";
        else if(num == 142) return "sys_timer_sleep";
        else if(num == 145) return "sys_time_get_current_time";
        else if(num == 147) return "sys_time_get_timebase_frequency";
        else if(num == 150) return "sys_raw_spu_create_interrupt_tag";
        else if(num == 151) return "sys_raw_spu_set_int_mask";
        else if(num == 152) return "sys_raw_spu_get_int_mask";
        else if(num == 153) return "sys_raw_spu_set_int_stat";
        else if(num == 154) return "sys_raw_spu_get_int_stat";
        else if(num == 156) return "sys_spu_image_open";
        else if(num == 160) return "sys_raw_spu_create";
        else if(num == 161) return "sys_raw_spu_destroy";
        else if(num == 163) return "sys_raw_spu_read_puint_mb";
        else if(num == 165) return "sys_spu_thread_get_exit_status";
        else if(num == 166) return "sys_spu_thread_set_argument";
        else if(num == 167) return "sys_spu_thread_group_start_on_exit";
        else if(num == 169) return "sys_spu_initialize";
        else if(num == 170) return "sys_spu_thread_group_create";
        else if(num == 171) return "sys_spu_thread_group_destroy";
        else if(num == 172) return "sys_spu_thread_initialize";
        else if(num == 173) return "sys_spu_thread_group_start";
        else if(num == 174) return "sys_spu_thread_group_suspend";
        else if(num == 175) return "sys_spu_thread_group_resume";
        else if(num == 176) return "sys_spu_thread_group_yield";
        else if(num == 177) return "sys_spu_thread_group_terminate";
        else if(num == 178) return "sys_spu_thread_group_join";
        else if(num == 179) return "sys_spu_thread_group_set_priority";
        else if(num == 180) return "sys_spu_thread_group_get_priority";
        else if(num == 181) return "sys_spu_thread_write_ls";
        else if(num == 182) return "sys_spu_thread_read_ls";
        else if(num == 184) return "sys_spu_thread_write_snr";
        else if(num == 185) return "sys_spu_thread_group_connect_event";
        else if(num == 186) return "sys_spu_thread_group_disconnect_event";
        else if(num == 187) return "sys_spu_thread_set_spu_cfg";
        else if(num == 188) return "sys_spu_thread_get_spu_cfg";
        else if(num == 190) return "sys_spu_thread_write_spu_mb";
        else if(num == 191) return "sys_spu_thread_connect_event";
        else if(num == 192) return "sys_spu_thread_disconnect_event";
        else if(num == 193) return "sys_spu_thread_bind_queue";
        else if(num == 194) return "sys_spu_thread_unbind_queue";
        else if(num == 196) return "sys_raw_spu_set_spu_cfg";
        else if(num == 197) return "sys_raw_spu_get_spu_cfg";
        else if(num == 198) return "sys_spu_thread_recover_page_fault";
        else if(num == 199) return "sys_raw_spu_recover_page_fault";
        else if(num == 251) return "sys_spu_thread_group_connect_event_all_threads";
        else if(num == 252) return "sys_spu_thread_group_disconnect_event_all_threads";
        else if(num == 260) return "sys_spu_image_open_by_fd";
        else if(num == 327) return "sys_mmapper_enable_page_fault_notification";
        else if(num == 329) return "sys_mmapper_free_shared_memory";
        else if(num == 330) return "sys_mmapper_allocate_address";
        else if(num == 331) return "sys_mmapper_free_address";
        else if(num == 332) return "sys_mmapper_allocate_shared_memory";
        else if(num == 333) return "sys_mmapper_set_shared_memory_flag";
        else if(num == 334) return "sys_mmapper_map_shared_memory";
        else if(num == 335) return "sys_mmapper_unmap_shared_memory";
        else if(num == 336) return "sys_mmapper_change_address_access_right";
        else if(num == 337) return "sys_mmapper_search_and_map";
        else if(num == 338) return "sys_mmapper_get_shared_memory_attribute";
        else if(num == 341) return "sys_memory_container_create";
        else if(num == 342) return "sys_memory_container_destroy";
        else if(num == 343) return "sys_memory_container_get_size";
        else if(num == 348) return "sys_memory_allocate";
        else if(num == 349) return "sys_memory_free";
        else if(num == 350) return "sys_memory_allocate_from_container";
        else if(num == 351) return "sys_memory_get_page_attribute";
        else if(num == 352) return "sys_memory_get_user_memory_size";
        else if(num == 402) return "sys_tty_read";
        else if(num == 403) return "sys_tty_write";
        else if(num == 450) return "sys_overlay_load_module";
        else if(num == 451) return "sys_overlay_unload_module";
        else if(num == 452) return "sys_overlay_get_module_list";
        else if(num == 453) return "sys_overlay_get_module_info";
        else if(num == 454) return "sys_overlay_load_module_by_fd";
        else if(num == 455) return "sys_overlay_get_module_info2";
        else if(num == 456) return "sys_overlay_get_sdk_version";
        else if(num == 457) return "sys_overlay_get_module_dbg_info";
        else if(num == 461) return "_sys_prx_get_module_id_by_address";
        else if(num == 463) return "_sys_prx_load_module_by_fd";
        else if(num == 464) return "_sys_prx_load_module_on_memcontainer_by_fd";
        else if(num == 480) return "_sys_prx_load_module";
        else if(num == 481) return "_sys_prx_start_module";
        else if(num == 482) return "_sys_prx_stop_module";
        else if(num == 483) return "_sys_prx_unload_module";
        else if(num == 484) return "_sys_prx_register_module";
        else if(num == 485) return "_sys_prx_query_module";
        else if(num == 486) return "_sys_prx_register_library";
        else if(num == 487) return "_sys_prx_unregister_library";
        else if(num == 488) return "_sys_prx_link_library";
        else if(num == 489) return "_sys_prx_unlink_library";
        else if(num == 490) return "_sys_prx_query_library";
        else if(num == 494) return "_sys_prx_get_module_list";
        else if(num == 495) return "_sys_prx_get_module_info";
        else if(num == 496) return "_sys_prx_get_module_id_by_name";
        else if(num == 497) return "_sys_prx_load_module_on_memcontainer";
        else if(num == 498) return "_sys_prx_start";
        else if(num == 499) return "_sys_prx_stop";
        else if(num == 600) return "sys_storage_open";
        else if(num == 601) return "sys_storage_close";
        else if(num == 602) return "sys_storage_read";
        else if(num == 603) return "sys_storage_write";
        else if(num == 604) return "sys_storage_send_device_command";
        else if(num == 605) return "sys_storage_async_configure";
        else if(num == 606) return "sys_storage_async_read";
        else if(num == 607) return "sys_storage_async_write";
        else if(num == 608) return "sys_storage_async_cancel";
        else if(num == 609) return "sys_storage_get_device_info";
        else if(num == 610) return "sys_storage_get_device_config";
        else if(num == 611) return "sys_storage_report_devices";
        else if(num == 612) return "sys_storage_configure_medium_event";
        else if(num == 613) return "sys_storage_set_medium_polling_interval";
        else if(num == 614) return "sys_storage_create_region";
        else if(num == 615) return "sys_storage_delete_region";
        else if(num == 616) return "sys_storage_execute_device_command";
        else if(num == 617) return "sys_storage_get_region_acl";
        else if(num == 618) return "sys_storage_set_region_acl";
        else if(num == 624) return "sys_io_buffer_create";
        else if(num == 625) return "sys_io_buffer_destroy";
        else if(num == 626) return "sys_io_buffer_allocate";
        else if(num == 627) return "sys_io_buffer_free";
        else if(num == 630) return "sys_gpio_set";
        else if(num == 631) return "sys_gpio_get";
        else if(num == 633) return "sys_fsw_connect_event";
        else if(num == 634) return "sys_fsw_disconnect_event";
        else if(num == 666) return "sys_rsx_device_open";
        else if(num == 667) return "sys_rsx_device_close";
        else if(num == 668) return "sys_rsx_memory_allocate";
        else if(num == 669) return "sys_rsx_memory_free";
        else if(num == 670) return "sys_rsx_context_allocate";
        else if(num == 671) return "sys_rsx_context_free";
        else if(num == 672) return "sys_rsx_context_iomap";
        else if(num == 673) return "sys_rsx_context_iounmap";
        else if(num == 674) return "sys_rsx_context_attribute";
        else if(num == 675) return "sys_rsx_device_map";
        else if(num == 676) return "sys_rsx_device_unmap";
        else if(num == 677) return "sys_rsx_attribute";
        else if(num == 801) return "open";
        else if(num == 802) return "read";
        else if(num == 803) return "write";
        else if(num == 804) return "close";
        else if(num == 805) return "opendir";
        else if(num == 806) return "readdir";
        else if(num == 807) return "closedir";
        else if(num == 808) return "stat";
        else if(num == 809) return "fstat";
        else if(num == 810) return "link";
        else if(num == 811) return "mkdir";
        else if(num == 812) return "rename";
        else if(num == 813) return "rmdir";
        else if(num == 814) return "unlink";
        else if(num == 815) return "utime";
        else if(num == 818) return "lseek";
        else if(num == 820) return "fsync";
        else if(num == 831) return "truncate";
        else if(num == 832) return "ftruncate";
        else if(num == 834) return "chmod";
        else if(num == 872) return "sys_ss_get_open_psid";
        else if(num == 873) return "sys_ss_get_cache_of_product_mode";
        else if(num == 880) return "sys_deci3_open";
        else if(num == 881) return "sys_deci3_create_event_path";
        else if(num == 882) return "sys_deci3_close";
        else if(num == 883) return "sys_deci3_send";
        else if(num == 884) return "sys_deci3_receive";
        else
          return NULL;
}



int main (int argc, char *argv[])
{
  FILE *in = NULL;
  int ret;
  char buf[1028];
  pcaprec_hdr_t header;
  ethernet_hdr_t eth;
  vlan_hdr_t vlan;
  uint64_t value = -1;
  uint64_t syscall = -1;
  int offset = 0;

  if (argc != 2) {
    printf ("Usage : %s in.pcap\n", argv[0]);
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
        header.incl_len != 72) {
      char *temp = malloc (header.incl_len);
      ret = fread(temp, 1, header.incl_len, in);
      if (ret != header.incl_len)
        break;
      free (temp);
      continue;
    }
    ret = fread(buf, 1, 72, in);
    if (ret != 72)
      break;
    offset = 0;
    syscall = *((uint32_t *) (buf + 68));
    syscall = ntohl (syscall);
    if (get_syscall_name (syscall) == NULL)
      printf ("syscall %d\n", syscall);
    else
      printf ("syscall %s\n", get_syscall_name (syscall));
    /*
    while (offset < 64) {
      value = *((uint64_t *) (buf + offset));
      if (offset == 0) {
        if (ntohl (value >> 32) == 0)
          break;
        printf ("Return : %d\n", ntohl (value >> 32));
      } else if (value != 0) {
        printf ("Frame %d : 0x%0.8X%0.8X\n", (offset - 8) / 8,
            ntohl (value), ntohl (value >> 32));
      }
      offset += 8;

      if ((offset > 0 && value == 0) || offset == 64)
      printf ("\n\n");
    }*/
  }

  fclose (in);

  return 0;
}
