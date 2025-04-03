/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004,2007,2008,2009  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_I386_LINUX_HEADER
#define GRUB_I386_LINUX_HEADER	1

#include <grub/types.h>

#define GRUB_LINUX_I386_MAGIC_SIGNATURE	0x53726448      /* "HdrS" */
#define GRUB_LINUX_DEFAULT_SETUP_SECTS	4
#define GRUB_LINUX_INITRD_MAX_ADDRESS	0x37FFFFFF
#define GRUB_LINUX_MAX_SETUP_SECTS	64
#define GRUB_LINUX_BOOT_LOADER_TYPE	0x72
#define GRUB_LINUX_HEAP_END_OFFSET	(0x9000 - 0x200)

#define GRUB_LINUX_BZIMAGE_ADDR		0x100000
#define GRUB_LINUX_ZIMAGE_ADDR		0x10000
#define GRUB_LINUX_OLD_REAL_MODE_ADDR	0x90000
#define GRUB_LINUX_SETUP_STACK		0x9000

#define GRUB_LINUX_FLAG_BIG_KERNEL	0x1
#define GRUB_LINUX_FLAG_QUIET		0x20
#define GRUB_LINUX_FLAG_CAN_USE_HEAP	0x80

/* Linux's video mode selection support. Actually I hate it!  */
#define GRUB_LINUX_VID_MODE_NORMAL	0xFFFF
#define GRUB_LINUX_VID_MODE_EXTENDED	0xFFFE
#define GRUB_LINUX_VID_MODE_ASK		0xFFFD
#define GRUB_LINUX_VID_MODE_VESA_START	0x0300

#define GRUB_LINUX_CL_MAGIC		0xA33F

#define VIDEO_CAPABILITY_SKIP_QUIRKS	(1 << 0)
#define VIDEO_CAPABILITY_64BIT_BASE	(1 << 1)	/* Frame buffer base is 64-bit. */

/* Maximum number of MBR signatures to store. */
#define EDD_MBR_SIG_MAX			16

/* Number of edd_info structs starting at EDDBUF. */
#define EDDMAXNR			6

#ifdef __x86_64__

#define GRUB_LINUX_EFI_SIGNATURE	\
  ('4' << 24 | '6' << 16 | 'L' << 8 | 'E')

#else

#define GRUB_LINUX_EFI_SIGNATURE	\
  ('2' << 24 | '3' << 16 | 'L' << 8 | 'E')

#endif

#define GRUB_LINUX_EFI_SIGNATURE_0204	\
  ('L' << 24 | 'I' << 16 | 'F' << 8 | 'E')

#define GRUB_LINUX_OFW_SIGNATURE	\
  (' ' << 24 | 'W' << 16 | 'F' << 8 | 'O')

#define LINUX_X86_XLF_KERNEL_64			(1<<0)
#define LINUX_X86_XLF_CAN_BE_LOADED_ABOVE_4G	(1<<1)
#define LINUX_X86_XLF_EFI_HANDOVER_32		(1<<2)
#define LINUX_X86_XLF_EFI_HANDOVER_64		(1<<3)
#define LINUX_X86_XLF_EFI_KEXEC			(1<<4)
#define LINUX_X86_XLF_5LEVEL			(1<<5)
#define LINUX_X86_XLF_5LEVEL_ENABLED		(1<<6)

#define LINUX_X86_STARTUP64_OFFSET		0x200

#ifndef ASM_FILE

#define GRUB_E820_RAM        1
#define GRUB_E820_RESERVED   2
#define GRUB_E820_ACPI       3
#define GRUB_E820_NVS        4
#define GRUB_E820_BADRAM     5

#define GRUB_E820_MAX_ENTRIES_ZEROPAGE 128

struct grub_screen_info
{
  grub_uint8_t orig_x;			/* 0x00 */
  grub_uint8_t orig_y;			/* 0x01 */
  grub_uint16_t ext_mem_k;		/* 0x02 */
  grub_uint16_t orig_video_page;	/* 0x04 */
  grub_uint8_t orig_video_mode;		/* 0x06 */
  grub_uint8_t orig_video_cols;		/* 0x07 */
  grub_uint8_t flags;			/* 0x08 */
  grub_uint8_t unused2;			/* 0x09 */
  grub_uint16_t orig_video_ega_bx;	/* 0x0a */
  grub_uint16_t unused3;		/* 0x0c */
  grub_uint8_t orig_video_lines;	/* 0x0e */
  grub_uint8_t orig_video_isVGA;	/* 0x0f */
  grub_uint16_t orig_video_points;	/* 0x10 */

  /* VESA graphic mode -- linear frame buffer */
  grub_uint16_t lfb_width;		/* 0x12 */
  grub_uint16_t lfb_height;		/* 0x14 */
  grub_uint16_t lfb_depth;		/* 0x16 */
  grub_uint32_t lfb_base;		/* 0x18 */
  grub_uint32_t lfb_size;		/* 0x1c */
  grub_uint16_t cl_magic, cl_offset;	/* 0x20 */
  grub_uint16_t lfb_linelength;		/* 0x24 */
  grub_uint8_t red_size;		/* 0x26 */
  grub_uint8_t red_pos;			/* 0x27 */
  grub_uint8_t green_size;		/* 0x28 */
  grub_uint8_t green_pos;		/* 0x29 */
  grub_uint8_t blue_size;		/* 0x2a */
  grub_uint8_t blue_pos;		/* 0x2b */
  grub_uint8_t rsvd_size;		/* 0x2c */
  grub_uint8_t rsvd_pos;		/* 0x2d */
  grub_uint16_t vesapm_seg;		/* 0x2e */
  grub_uint16_t vesapm_off;		/* 0x30 */
  grub_uint16_t pages;			/* 0x32 */
  grub_uint16_t vesa_attributes;	/* 0x34 */
  grub_uint32_t capabilities;		/* 0x36 */
  grub_uint32_t ext_lfb_base;		/* 0x3a */
  grub_uint8_t _reserved[2];		/* 0x3e */
} GRUB_PACKED;

struct grub_apm_bios_info
{
  grub_uint16_t version;
  grub_uint16_t cseg;
  grub_uint32_t offset;
  grub_uint16_t cseg_16;
  grub_uint16_t dseg;
  grub_uint16_t flags;
  grub_uint16_t cseg_len;
  grub_uint16_t cseg_16_len;
  grub_uint16_t dseg_len;
};

struct grub_ist_info
{
  grub_uint32_t signature;
  grub_uint32_t command;
  grub_uint32_t event;
  grub_uint32_t perf_level;
};

struct grub_sys_desc_table
{
  grub_uint16_t length;
  grub_uint8_t table[14];
};

struct grub_olpc_ofw_header {
  grub_uint32_t ofw_magic;	/* OFW signature */
  grub_uint32_t ofw_version;
  grub_uint32_t cif_handler;	/* callback into OFW */
  grub_uint32_t irq_desc_table;
} GRUB_PACKED;

struct grub_setup_header
{
  grub_uint8_t setup_sects;		/* The size of the setup in sectors */
  grub_uint16_t root_flags;		/* If the root is mounted readonly */
  grub_uint32_t syssize;		/* obsolete */
  grub_uint16_t ram_size;		/* obsolete */
  grub_uint16_t vid_mode;		/* Video mode control */
  grub_uint16_t root_dev;		/* Default root device number */
  grub_uint16_t boot_flag;		/* 1fe */
  grub_uint16_t jump;			/* Jump instruction */
  grub_uint32_t header;			/* Magic signature "HdrS" */
  grub_uint16_t version;		/* Boot protocol version supported */
  grub_uint32_t realmode_swtch;		/* Boot loader hook */
  grub_uint16_t start_sys;		/* The load-low segment (obsolete) */
  grub_uint16_t kernel_version;		/* Points to kernel version string */
  grub_uint8_t type_of_loader;		/* Boot loader identifier */
  grub_uint8_t loadflags;		/* Boot protocol option flags */
  grub_uint16_t setup_move_size;	/* Move to high memory size */
  grub_uint32_t code32_start;		/* Boot loader hook */
  grub_uint32_t ramdisk_image;		/* initrd load address */
  grub_uint32_t ramdisk_size;		/* initrd size */
  grub_uint32_t bootsect_kludge;	/* obsolete */
  grub_uint16_t heap_end_ptr;		/* Free memory after setup end */
  grub_uint8_t ext_loader_ver;		/* Extended loader version */
  grub_uint8_t ext_loader_type;		/* Extended loader type */
  grub_uint32_t cmd_line_ptr;		/* Points to the kernel command line */
  grub_uint32_t initrd_addr_max;	/* Maximum initrd address */
  grub_uint32_t kernel_alignment;	/* Alignment of the kernel */
  grub_uint8_t relocatable_kernel;	/* Is the kernel relocatable */
  grub_uint8_t min_alignment;
  grub_uint16_t xloadflags;
  grub_uint32_t cmdline_size;		/* Size of the kernel command line */
  grub_uint32_t hardware_subarch;
  grub_uint64_t hardware_subarch_data;
  grub_uint32_t payload_offset;
  grub_uint32_t payload_length;
  grub_uint64_t setup_data;
  grub_uint64_t pref_address;
  grub_uint32_t init_size;
  grub_uint32_t handover_offset;
  grub_uint32_t kernel_info_offset;
} GRUB_PACKED;

struct grub_boot_e820_entry
{
  grub_uint64_t addr;
  grub_uint64_t size;
  grub_uint32_t type;
} GRUB_PACKED;

struct grub_edd_device_params
{
  grub_uint16_t length;
  grub_uint16_t info_flags;
  grub_uint32_t num_default_cylinders;
  grub_uint32_t num_default_heads;
  grub_uint32_t sectors_per_track;
  grub_uint64_t number_of_sectors;
  grub_uint16_t bytes_per_sector;
  grub_uint32_t dpte_ptr;		/* 0xFFFFFFFF for our purposes */
  grub_uint16_t key;			/* = 0xBEDD */
  grub_uint8_t device_path_info_length;	/* = 44 */
  grub_uint8_t reserved2;
  grub_uint16_t reserved3;
  grub_uint8_t host_bus_type[4];
  grub_uint8_t interface_type[8];
  union
    {
      struct
	{
	  grub_uint16_t base_address;
	  grub_uint16_t reserved1;
	  grub_uint32_t reserved2;
	} isa;
      struct
	{
	  grub_uint8_t bus;
	  grub_uint8_t slot;
	  grub_uint8_t function;
	  grub_uint8_t channel;
	  grub_uint32_t reserved;
	} pci;
      /* pcix is same as pci */
      struct
	{
	  grub_uint64_t reserved;
	} ibnd;
      struct
	{
	  grub_uint64_t reserved;
	} xprs;
      struct
	{
	  grub_uint64_t reserved;
	} htpt;
      struct
	{
	  grub_uint64_t reserved;
	} unknown;
    } interface_path;
  union
    {
      struct
	{
	  grub_uint8_t device;
	  grub_uint8_t reserved1;
	  grub_uint16_t reserved2;
	  grub_uint32_t reserved3;
	  grub_uint64_t reserved4;
	} ata;
      struct
	{
	  grub_uint8_t device;
	  grub_uint8_t lun;
	  grub_uint8_t reserved1;
	  grub_uint8_t reserved2;
	  grub_uint32_t reserved3;
	  grub_uint64_t reserved4;
	} atapi;
      struct
	{
	  grub_uint16_t id;
	  grub_uint64_t lun;
	  grub_uint16_t reserved1;
	  grub_uint32_t reserved2;
	} scsi;
      struct
	{
	  grub_uint64_t serial_number;
	  grub_uint64_t reserved;
	} usb;
      struct
	{
	  grub_uint64_t eui;
	  grub_uint64_t reserved;
	} i1394;
      struct
	{
	  grub_uint64_t wwid;
	  grub_uint64_t lun;
	} fibre;
      struct
	{
	  grub_uint64_t identity_tag;
	  grub_uint64_t reserved;
	} i2o;
      struct
	{
	  grub_uint32_t array_number;
	  grub_uint32_t reserved1;
	  grub_uint64_t reserved2;
	} raid;
      struct
	{
	  grub_uint8_t device;
	  grub_uint8_t reserved1;
	  grub_uint16_t reserved2;
	  grub_uint32_t reserved3;
	  grub_uint64_t reserved4;
	} sata;
      struct
	{
	  grub_uint64_t reserved1;
	  grub_uint64_t reserved2;
	} unknown;
    } device_path;
  grub_uint8_t reserved4;
  grub_uint8_t checksum;
} GRUB_PACKED;

struct grub_edd_info
{
  grub_uint8_t device;
  grub_uint8_t version;
  grub_uint16_t interface_support;
  grub_uint16_t legacy_max_cylinder;
  grub_uint8_t legacy_max_head;
  grub_uint8_t legacy_sectors_per_track;
  struct grub_edd_device_params params;
} GRUB_PACKED;

enum
  {
    GRUB_VIDEO_LINUX_TYPE_TEXT = 0x01,
    GRUB_VIDEO_LINUX_TYPE_VESA = 0x23,	/* VESA VGA in graphic mode.  */
    GRUB_VIDEO_LINUX_TYPE_EFIFB = 0x70,	/* EFI Framebuffer.  */
    GRUB_VIDEO_LINUX_TYPE_SIMPLE = 0x70	/* Linear framebuffer without any additional functions.  */
  };

/* For the Linux/i386 boot protocol version 2.10. */
struct linux_i386_kernel_header
{
  grub_uint8_t code1[0x0020];
  grub_uint16_t cl_magic;		/* Magic number 0xA33F */
  grub_uint16_t cl_offset;		/* The offset of command line */
  grub_uint8_t code2[0x01F1 - 0x0020 - 2 - 2];
  grub_uint8_t setup_sects;		/* The size of the setup in sectors */
  grub_uint16_t root_flags;		/* If the root is mounted readonly */
  grub_uint16_t syssize;		/* obsolete */
  grub_uint16_t swap_dev;		/* obsolete */
  grub_uint16_t ram_size;		/* obsolete */
  grub_uint16_t vid_mode;		/* Video mode control */
  grub_uint16_t root_dev;		/* Default root device number */
  grub_uint16_t boot_flag;		/* 0xAA55 magic number */
  grub_uint16_t jump;			/* Jump instruction */
  grub_uint32_t header;			/* Magic signature "HdrS" */
  grub_uint16_t version;		/* Boot protocol version supported */
  grub_uint32_t realmode_swtch;		/* Boot loader hook */
  grub_uint16_t start_sys;		/* The load-low segment (obsolete) */
  grub_uint16_t kernel_version;		/* Points to kernel version string */
  grub_uint8_t type_of_loader;		/* Boot loader identifier */
#define LINUX_LOADER_ID_LILO		0x0
#define LINUX_LOADER_ID_LOADLIN		0x1
#define LINUX_LOADER_ID_BOOTSECT	0x2
#define LINUX_LOADER_ID_SYSLINUX	0x3
#define LINUX_LOADER_ID_ETHERBOOT	0x4
#define LINUX_LOADER_ID_ELILO		0x5
#define LINUX_LOADER_ID_GRUB		0x7
#define LINUX_LOADER_ID_UBOOT		0x8
#define LINUX_LOADER_ID_XEN		0x9
#define LINUX_LOADER_ID_GUJIN		0xa
#define LINUX_LOADER_ID_QEMU		0xb
  grub_uint8_t loadflags;		/* Boot protocol option flags */
  grub_uint16_t setup_move_size;	/* Move to high memory size */
  grub_uint32_t code32_start;		/* Boot loader hook */
  grub_uint32_t ramdisk_image;		/* initrd load address */
  grub_uint32_t ramdisk_size;		/* initrd size */
  grub_uint32_t bootsect_kludge;	/* obsolete */
  grub_uint16_t heap_end_ptr;		/* Free memory after setup end */
  grub_uint16_t pad1;			/* Unused */
  grub_uint32_t cmd_line_ptr;		/* Points to the kernel command line */
  grub_uint32_t initrd_addr_max;	/* Highest address for initrd */
  grub_uint32_t kernel_alignment;
  grub_uint8_t relocatable;
  grub_uint8_t min_alignment;
  grub_uint16_t xloadflags;
  grub_uint32_t cmdline_size;
  grub_uint32_t hardware_subarch;
  grub_uint64_t hardware_subarch_data;
  grub_uint32_t payload_offset;
  grub_uint32_t payload_length;
  grub_uint64_t setup_data;
  grub_uint64_t pref_address;
  grub_uint32_t init_size;
  grub_uint32_t handover_offset;
} GRUB_PACKED;

/*
 * Boot parameters for Linux based on 6.13.7 stable. This is used
 * by the setup sectors of Linux, and must be simulated by GRUB
 * on EFI, because the setup sectors depend on BIOS.
 */
struct linux_kernel_params
{
  struct grub_screen_info screen_info;		/* 0 */
  struct grub_apm_bios_info apm_bios_info;	/* 40 */
  grub_uint8_t _pad2[4];			/* 54 */
  grub_uint64_t tboot_addr;			/* 58 */
  struct grub_ist_info ist_info;		/* 60 */
  grub_uint64_t acpi_rsdp_addr;			/* 70 */
  grub_uint8_t _pad3[8];			/* 78 */
  grub_uint8_t hd0_info[16];			/* 80 */
  grub_uint8_t hd1_info[16];			/* 90 */
  struct grub_sys_desc_table sys_desc_table;	/* a0 */
  struct grub_olpc_ofw_header olpc_ofw_header;	/* b0 */
  grub_uint32_t ext_ramdisk_image;		/* c0 */
  grub_uint32_t ext_ramdisk_size;		/* c4 */
  grub_uint32_t ext_cmd_line_ptr;		/* c8 */
  grub_uint8_t _pad4[112];			/* cc */
  grub_uint32_t cc_blob_address;		/* 13c */

  /*
   * edid_info should be a struct with "unsigned char dummy[128]" and
   * efi_info should be a struct as well, starting at 0x1c0. However,
   * for backwards compatibility, GRUB can have efi_systab at 0x1b8 and
   * padding at 0x1bc (or padding at both spots). This cuts into the end
   * of edid_info. Make edid_info inline and only make it go up to 0x1b8.
   */
  grub_uint8_t edid_info[0x1b8 - 0x140];	/* 140 */
  union
    {
      struct
	{
	  grub_uint32_t efi_systab;		/* 1b8 */
	  grub_uint32_t padding7_2;		/* 1bc */
	  grub_uint32_t efi_loader_signature;	/* 1c0 */
	  grub_uint32_t efi_memdesc_size;	/* 1c4 */
	  grub_uint32_t efi_memdesc_version;	/* 1c8 */
	  grub_uint32_t efi_memmap_size;	/* 1cc */
	  grub_uint32_t efi_memmap;		/* 1d0 */
	} v0204;
      struct
	{
	  grub_uint32_t padding7_1;		/* 1b8 */
	  grub_uint32_t padding7_2;		/* 1bc */
	  grub_uint32_t efi_loader_signature;	/* 1c0 */
	  grub_uint32_t efi_systab;		/* 1c4 */
	  grub_uint32_t efi_memdesc_size;	/* 1c8 */
	  grub_uint32_t efi_memdesc_version;	/* 1cc */
	  grub_uint32_t efi_memmap;		/* 1d0 */
	  grub_uint32_t efi_memmap_size;	/* 1d4 */
	} v0206;
      struct
	{
	  grub_uint32_t padding7_1;		/* 1b8 */
	  grub_uint32_t padding7_2;		/* 1bc */
	  grub_uint32_t efi_loader_signature;	/* 1c0 */
	  grub_uint32_t efi_systab;		/* 1c4 */
	  grub_uint32_t efi_memdesc_size;	/* 1c8 */
	  grub_uint32_t efi_memdesc_version;	/* 1cc */
	  grub_uint32_t efi_memmap;		/* 1d0 */
	  grub_uint32_t efi_memmap_size;	/* 1d4 */
	  grub_uint32_t efi_systab_hi;		/* 1d8 */
	  grub_uint32_t efi_memmap_hi;		/* 1dc */
	} v0208;
    } efi_info;

  grub_uint32_t alt_mem_k;			/* 1e0 */
  grub_uint32_t scratch;			/* 1e4 */
  grub_uint8_t e820_entries;			/* 1e8 */
  grub_uint8_t eddbuf_entries;			/* 1e9 */
  grub_uint8_t edd_mbr_sig_buf_entries;		/* 1ea */
  grub_uint8_t kbd_status;			/* 1eb */
  grub_uint8_t secure_boot;			/* 1ec */
  grub_uint8_t _pad5[2];			/* 1ed */
  grub_uint8_t sentinel;			/* 1ef */
  grub_uint8_t _pad6[1];			/* 1f0 */
  struct grub_setup_header hdr;			/* 1f1 */
  grub_uint8_t _pad7[0x290 - 0x1f1 - sizeof(struct grub_setup_header)];
  grub_uint32_t edd_mbr_sig_buffer[EDD_MBR_SIG_MAX];	/* 290 */
  struct grub_boot_e820_entry e820_table[GRUB_E820_MAX_ENTRIES_ZEROPAGE];	/* 2d0 */
  grub_uint8_t _pad8[48];			/* cd0 */
  struct grub_edd_info eddbuf[EDDMAXNR];	/* d00 */
  grub_uint8_t _pad9[276];			/* eec */
} GRUB_PACKED;
#endif /* ! ASM_FILE */

#endif /* ! GRUB_I386_LINUX_HEADER */
