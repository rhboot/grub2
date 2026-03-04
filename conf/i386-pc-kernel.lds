ENTRY(_start)

/*
 * Align sections to a 16-byte boundary. This guarantees ABI compatibility with
 * C generated code.
 */
SECTION_ALIGN = 0x10;

PHDRS {
    text PT_LOAD FLAGS(7) /* PF_R | PF_W | PF_X */;
}

SECTIONS
{
    /*
     * Set section alignment to 1. This allows sections to be aligned without
     * creating holes in the VMA space or gaps in the file.
     */
    . = _grub_text_base;
    .text ALIGN(0x1) : {
        _start = .;
        *(.text .text.*)
        . = ALIGN(SECTION_ALIGN);
    } :text
    .rodata ALIGN(0x1) : {
        *(.rodata .rodata.*)
        . = ALIGN(SECTION_ALIGN);
    } :text
    .module_license ALIGN(0x1) : {
        *(.module_license)
        . = ALIGN(SECTION_ALIGN);
    } :text
    .data ALIGN(0x1) : {
        *(.data .data.*)
        . = ALIGN(SECTION_ALIGN);
        _edata = .;
    } :text
    .bss ALIGN(0x1) : {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(SECTION_ALIGN);
        _end = .;
    } :text
    /DISCARD/ : {
        *(.interp)
        *(.note*)
        *(.comment)
        *(.build-id)
    }
}
