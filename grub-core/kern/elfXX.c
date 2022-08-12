int
grub_elf_is_elfXX (grub_elf_t elf)
{
  return elf->ehdr.ehdrXX.e_ident[EI_CLASS] == ELFCLASSXX;
}

grub_err_t
grub_elfXX_load_phdrs (grub_elf_t elf)
{
  grub_ssize_t phdrs_size;

  if (elf->phdrs)
    return GRUB_ERR_NONE;

  phdrs_size = (grub_uint32_t) elf->ehdr.ehdrXX.e_phnum * elf->ehdr.ehdrXX.e_phentsize;

  grub_dprintf ("elf", "Loading program headers at 0x%llx, size 0x%lx.\n",
		(unsigned long long) elf->ehdr.ehdrXX.e_phoff,
		(unsigned long) phdrs_size);

  elf->phdrs = grub_malloc (phdrs_size);
  if (! elf->phdrs)
    return grub_errno;

  if ((grub_file_seek (elf->file, elf->ehdr.ehdrXX.e_phoff) == (grub_off_t) -1)
      || (grub_file_read (elf->file, elf->phdrs, phdrs_size) != phdrs_size))
    {
      if (!grub_errno)
	grub_error (GRUB_ERR_FILE_READ_ERROR, N_("premature end of file %s"),
		    elf->filename);
      return grub_errno;
    }

#if GRUB_ELF_ENABLE_BI_ENDIAN
  if (elf->ehdr.ehdrXX.e_ident[EI_DATA] == GRUB_ELF_OPPOSITE_ENDIANNESS)
    {
      ElfXX_Phdr *phdr;
      for (phdr = elf->phdrs; (char *) phdr < (char *) elf->phdrs + phdrs_size;
	   phdr = (ElfXX_Phdr *) ((char *) phdr + elf->ehdr.ehdrXX.e_phentsize))
	{
	  phdr->p_type = grub_swap_bytes_wordXX (phdr->p_type);
	  phdr->p_flags = grub_swap_bytes_wordXX (phdr->p_flags);
          phdr->p_offset = grub_swap_bytes_offXX (phdr->p_offset);
          phdr->p_vaddr = grub_swap_bytes_addrXX (phdr->p_vaddr);
          phdr->p_paddr = grub_swap_bytes_addrXX (phdr->p_paddr);
          phdr->p_filesz = grub_swap_bytes_XwordXX (phdr->p_filesz);
          phdr->p_memsz = grub_swap_bytes_XwordXX (phdr->p_memsz);
          phdr->p_align = grub_swap_bytes_XwordXX (phdr->p_align);
        }
    }
#endif /* GRUB_ELF_ENABLE_BI_ENDIAN */

  return GRUB_ERR_NONE;
}

/* Calculate the amount of memory spanned by the segments.  */
grub_size_t
grub_elfXX_size (grub_elf_t elf,
		 ElfXX_Addr *base, grub_uintXX_t *max_align)
{
  ElfXX_Addr segments_start = (ElfXX_Addr) -1;
  ElfXX_Addr segments_end = 0;
  int nr_phdrs = 0;
  grub_uint32_t curr_align = 1;
  ElfXX_Phdr *phdr;

  /* Run through the program headers to calculate the total memory size we
   * should claim.  */
  FOR_ELFXX_PHDRS (elf, phdr)
    {
      /* Only consider loadable segments.  */
      if (phdr->p_type != PT_LOAD)
	continue;
      nr_phdrs++;
      if (phdr->p_paddr < segments_start)
	segments_start = phdr->p_paddr;
      if (phdr->p_paddr + phdr->p_memsz > segments_end)
	segments_end = phdr->p_paddr + phdr->p_memsz;
      if (curr_align < phdr->p_align)
	curr_align = phdr->p_align;
    }

  if (base)
    *base = 0;

  if (nr_phdrs == 0)
    {
      grub_error (GRUB_ERR_BAD_OS, "no program headers present");
      return 0;
    }

  if (segments_end < segments_start)
    {
      /* Very bad addresses.  */
      grub_error (GRUB_ERR_BAD_OS, "bad program header load addresses");
      return 0;
    }

  if (base)
    *base = segments_start;
  if (max_align)
    *max_align = curr_align;
  return segments_end - segments_start;
}

grub_err_t
grub_elfXX_load (grub_elf_t elf, const char *filename,
		 void *load_offset, enum grub_elf_load_flags load_flags,
		 grub_addr_t *base, grub_size_t *size)
{
  grub_addr_t load_base = (grub_addr_t) -1ULL;
  grub_size_t load_size = 0;
  ElfXX_Phdr *phdr;

  FOR_ELFXX_PHDRS(elf, phdr)
  {
    grub_addr_t load_addr;

    if (phdr->p_type != PT_LOAD && !((load_flags & GRUB_ELF_LOAD_FLAGS_LOAD_PT_DYNAMIC) && phdr->p_type == PT_DYNAMIC))
      continue;

    load_addr = (grub_addr_t) phdr->p_paddr;
    switch (load_flags & GRUB_ELF_LOAD_FLAGS_BITS)
      {
      case GRUB_ELF_LOAD_FLAGS_ALL_BITS:
	break;
      case GRUB_ELF_LOAD_FLAGS_28BITS:
	load_addr &= 0xFFFFFFF;
	break;
      case GRUB_ELF_LOAD_FLAGS_30BITS:
	load_addr &= 0x3FFFFFFF;
	break;
      case GRUB_ELF_LOAD_FLAGS_62BITS:
	load_addr &= 0x3FFFFFFFFFFFFFFFULL;
	break;
      }
    load_addr += (grub_addr_t) load_offset;

    if (load_addr < load_base)
      load_base = load_addr;

    grub_dprintf ("elf", "Loading segment at 0x%llx, size 0x%llx\n",
		  (unsigned long long) load_addr,
		  (unsigned long long) phdr->p_memsz);

    if (grub_file_seek (elf->file, phdr->p_offset) == (grub_off_t) -1)
      return grub_errno;

    if (phdr->p_filesz)
      {
	grub_ssize_t read;
	read = grub_file_read (elf->file, (void *) load_addr, phdr->p_filesz);
	if (read != (grub_ssize_t) phdr->p_filesz)
	  {
	    if (!grub_errno)
	      grub_error (GRUB_ERR_FILE_READ_ERROR, N_("premature end of file %s"),
			  filename);
	    return grub_errno;
	  }
      }

    if (phdr->p_filesz < phdr->p_memsz)
      grub_memset ((void *) (grub_addr_t) (load_addr + phdr->p_filesz),
		   0, phdr->p_memsz - phdr->p_filesz);

    load_size += phdr->p_memsz;
  }

  if (base)
    *base = load_base;
  if (size)
    *size = load_size;

  return grub_errno;
}

static int
grub_elfXX_check_endianess_and_bswap_ehdr (grub_elf_t elf)
{
  ElfXX_Ehdr *e = &(elf->ehdr.ehdrXX);
  if (e->e_ident[EI_DATA] == GRUB_ELF_NATIVE_ENDIANNESS)
    {
      return 1;
    }

#if GRUB_ELF_ENABLE_BI_ENDIAN
  if (e->e_ident[EI_DATA] == GRUB_ELF_OPPOSITE_ENDIANNESS)
    {
      e->e_type = grub_swap_bytes_halfXX (e->e_type);
      e->e_machine = grub_swap_bytes_halfXX (e->e_machine);
      e->e_version = grub_swap_bytes_wordXX (e->e_version);
      e->e_entry = grub_swap_bytes_addrXX (e->e_entry);
      e->e_phoff = grub_swap_bytes_offXX (e->e_phoff);
      e->e_shoff = grub_swap_bytes_offXX (e->e_shoff);
      e->e_flags = grub_swap_bytes_wordXX (e->e_flags);
      e->e_ehsize = grub_swap_bytes_halfXX (e->e_ehsize);
      e->e_phentsize = grub_swap_bytes_halfXX (e->e_phentsize);
      e->e_phnum = grub_swap_bytes_halfXX (e->e_phnum);
      e->e_shentsize = grub_swap_bytes_halfXX (e->e_shentsize);
      e->e_shnum = grub_swap_bytes_halfXX (e->e_shnum);
      e->e_shstrndx = grub_swap_bytes_halfXX (e->e_shstrndx);
      return 1;
    }
#endif /* GRUB_ELF_ENABLE_BI_ENDIAN */

  return 0;
}

grub_err_t
grub_elfXX_get_shnum (ElfXX_Ehdr *e, ElfXX_Shnum *shnum)
{
  ElfXX_Shdr *s;

  if (shnum == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("NULL pointer passed for shnum"));

  /* Set *shnum to 0 so that shnum doesn't return junk on error */
  *shnum = 0;

  if (e == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("NULL pointer passed for elf header"));

  *shnum = e->e_shnum;
  if (*shnum == SHN_UNDEF)
    {
      if (e->e_shoff == 0)
	return grub_error (GRUB_ERR_BAD_NUMBER, N_("invalid section header table offset in e_shoff"));

      s = (ElfXX_Shdr *) ((grub_uint8_t *) e + e->e_shoff);
      *shnum = s->sh_size;
      if (*shnum < SHN_LORESERVE)
	return grub_error (GRUB_ERR_BAD_NUMBER, N_("invalid number of section header table entries in sh_size: %" PRIuGRUB_UINT64_T), (grub_uint64_t) *shnum);
    }
  else
    {
      if (*shnum >= SHN_LORESERVE)
	return grub_error (GRUB_ERR_BAD_NUMBER, N_("invalid number of section header table entries in e_shnum: %" PRIuGRUB_UINT64_T), (grub_uint64_t) *shnum);
    }

  return GRUB_ERR_NONE;
}

grub_err_t
grub_elfXX_get_shstrndx (ElfXX_Ehdr *e, ElfXX_Word *shstrndx)
{
  ElfXX_Shdr *s;

  if (shstrndx == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("NULL pointer passed for shstrndx"));

  /* Set *shstrndx to 0 so that shstrndx doesn't return junk on error */
  *shstrndx = 0;

  if (e == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("NULL pointer passed for elf header"));

  *shstrndx = e->e_shstrndx;
  if (*shstrndx == SHN_XINDEX)
    {
      if (e->e_shoff == 0)
	return grub_error (GRUB_ERR_BAD_NUMBER, N_("invalid section header table offset in e_shoff"));

      s = (ElfXX_Shdr *) ((grub_uint8_t *) e + e->e_shoff);
      *shstrndx = s->sh_link;
      if (*shstrndx < SHN_LORESERVE)
	return grub_error (GRUB_ERR_BAD_NUMBER, N_("invalid section header table index in sh_link: %d"), *shstrndx);
    }
  else
    {
      if (*shstrndx >= SHN_LORESERVE)
	return grub_error (GRUB_ERR_BAD_NUMBER, N_("invalid section header table index in e_shstrndx: %d"), *shstrndx);
    }
  return GRUB_ERR_NONE;
}

grub_err_t
grub_elfXX_get_phnum (ElfXX_Ehdr *e, ElfXX_Word *phnum)
{
  ElfXX_Shdr *s;

  if (phnum == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("NULL pointer passed for phnum"));

  /* Set *phnum to 0 so that phnum doesn't return junk on error */
  *phnum = 0;

  if (e == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("NULL pointer passed for elf header"));

  *phnum = e->e_phnum;
  if (*phnum == PN_XNUM)
    {
      if (e->e_shoff == 0)
	return grub_error (GRUB_ERR_BAD_NUMBER, N_("invalid section header table offset in e_shoff"));

      s = (ElfXX_Shdr *) ((grub_uint8_t *) e + e->e_shoff);
      *phnum = s->sh_info;
      if (*phnum < PN_XNUM)
	return grub_error (GRUB_ERR_BAD_NUMBER, N_("invalid number of program header table entries in sh_info: %d"), *phnum);
    }
  else
    {
      if (*phnum >= PN_XNUM)
	return grub_error (GRUB_ERR_BAD_NUMBER, N_("invalid number of program header table entries in e_phnum: %d"), *phnum);
    }

  return GRUB_ERR_NONE;
}
