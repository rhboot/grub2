import os
import re
import subprocess

def prompt_hook (current_prompt):
  return "(grub gdb) "
gdb.prompt_hook = prompt_hook

##### Convenience functions #####

class IsGrubLoaded (gdb.Function):
  """Return 1 if GRUB has been loaded in memory, otherwise 0.
The hueristic used is checking if the first 4 bytes of the memory pointed
to by the _start symbol are not 0. This is true for QEMU on the first run
of GRUB. This may not be true on physical hardware, where memory is not
necessarily cleared on soft reset. This may not also be true in QEMU on
soft resets. Also this many not be true when chainloading GRUB.
"""

  def __init__ (self):
    super (IsGrubLoaded, self).__init__ ("is_grub_loaded")

  def invoke (self):
    return int (gdb.parse_and_eval ("*(int *) _start")) != 0

is_grub_loaded = IsGrubLoaded ()

class IsUserCommand (gdb.Function):
  """Set the second argument to true value if first argument is the name
of a user-defined command.
"""

  def __init__ (self):
    super (IsUserCommand, self).__init__ ("is_user_command")

  def invoke (self, fmt, *args):
    name = fmt.string () % tuple(a.string () for a in args)
    for line in gdb.execute ("help user-defined", to_string=True).splitlines ():
      line_parts = line.split(' -- ', 1)
      if len (line_parts) > 1 and line_parts[0] == name:
        return True
    return False

is_user_command = IsUserCommand ()

##### Commands #####

# Loading symbols is complicated by the fact that kernel.exec is an ELF
# ELF binary, but the UEFI runtime is PE32+. All the data sections of
# the ELF binary are concatenated (accounting for ELF section alignment)
# and put into one .data section of the PE32+ runtime image. So given
# the load address of the .data PE32+ section we can determine the
# addresses each ELF data section maps to. The UEFI application is
# loaded into memory just as it is laid out in the file. It is not
# assumed that the binary is available, but it is known that the .text
# section directly precedes the .data section and that .data is EFI
# page aligned. Using this, the .data offset can be found from the .text
# address.
class GrubLoadKernelExecSymbols (gdb.Command):
  """Load debugging symbols from kernel.exec given the address of the
.text segment of the UEFI binary in memory."""

  PE_SECTION_ALIGN = 12

  def __init__ (self):
    super (GrubLoadKernelExecSymbols, self).__init__ ("dynamic_load_kernel_exec_symbols",
						      gdb.COMMAND_USER,
						      gdb.COMPLETE_EXPRESSION)

  def invoke (self, arg, from_tty):
    self.dont_repeat ()
    args = gdb.string_to_argv (arg)

    if len (args) != 1:
      raise RuntimeError ("dynamic_load_kernel_exec_symbols expects exactly one argument")

    sections = self.parse_objdump_sections ("kernel.exec")
    pe_text = args[0]
    text_size = [s['size'] for s in sections if s['name'] == '.text'][0]
    pe_data_offset = self.alignup (text_size, self.PE_SECTION_ALIGN)

    sym_load_cmd_parts = ["add-symbol-file", "kernel.exec", pe_text]
    offset = 0
    for section in sections:
      if 'DATA' in section["flags"] or section["name"] == ".bss":
        offset = self.alignup (offset, section["align"])
        sym_load_cmd_parts.extend (["-s", section["name"], "(%s+0x%x+0x%x)" % (pe_text, pe_data_offset, offset)])
        offset += section["size"]
    gdb.execute (' '.join (sym_load_cmd_parts))

  @staticmethod
  def parse_objdump_sections (filename):
    fields = ("idx", "name", "size", "vma", "lma", "fileoff", "align")
    re_section = re.compile ("^\s*" + "\s+".join(["(?P<%s>\S+)" % f for f in fields]))
    c = subprocess.run (["objdump", "-h", filename], text=True, capture_output=True)
    section_lines = c.stdout.splitlines ()[5:]
    sections = []

    for i in range (len (section_lines) >> 1):
      m = re_section.match (section_lines[i * 2])
      s = dict (m.groupdict ())
      for f in ("size", "vma", "lma", "fileoff"):
        s[f] = int (s[f], 16)
      s["idx"] = int (s["idx"])
      s["align"] = int (s["align"].split ("**", 1)[1])
      s["flags"] = section_lines[(i * 2) + 1].strip ().split (", ")
      sections.append (s)
    return sections

  @staticmethod
  def alignup (addr, align):
    pad = (addr % (1 << align)) and 1 or 0
    return ((addr >> align) + pad) << align

dynamic_load_kernel_exec_symbols = GrubLoadKernelExecSymbols ()


class GrubLoadModuleSymbols (gdb.Command):
  """Load module symbols at correct locations.
Takes one argument which is a pointer to a grub_dl_t struct."""

  def __init__ (self):
    super (GrubLoadModuleSymbols, self).__init__ ("load_module",
						  gdb.COMMAND_USER,
						  gdb.COMPLETE_EXPRESSION)

  def invoke (self, arg, from_tty):
    self.dont_repeat ()
    args = gdb.string_to_argv (arg)
    self.mod = gdb.parse_and_eval (args[0])
    sections = self.get_section_offsets ()
    section_names = self.get_section_names ()

    sym_load_cmd_parts = ["add-symbol-file",
			  "%s.module" % (self.mod['name'].string (),)]
    for idx, addr in sections:
      section_name = section_names[idx]
      if section_name == ".text":
        sym_load_cmd_parts.append (addr)
      else:
        sym_load_cmd_parts.extend (["-s", section_name, addr])
    gdb.execute (' '.join (sym_load_cmd_parts))

    if is_user_command.invoke (gdb.Value ("onload_%s"), self.mod['name']):
      gdb.execute ("onload_%s (grub_dl_t)%s" % (self.mod['name'].string (),
						self.mod.format_string (format='x')))

  def get_section_offsets (self):
    sections = []
    segment = self.mod['segment']
    while segment:
      sections.append ((int (segment['section']), segment['addr'].format_string (format='x')))
      segment = segment['next']
    return sections

  def get_section_names (self):
    re_index = re.compile ("^\s+\[\s*(\d+)\] (\S*)")
    names = {}
    modfilename = "%s.mod" % (self.mod['name'].string (),)

    if not os.path.exists (modfilename):
      raise RuntimeError ("%s not found in current directory" % (modfilename,))

    c = subprocess.run (["readelf", "-SW", modfilename], text=True, capture_output=True)
    for line in c.stdout.splitlines ()[4:]:
      m = re_index.match (line)
      if not m:
        continue
      idx, name = m.groups ()
      names[int (idx)] = name
    return names

grub_load_module = GrubLoadModuleSymbols ()
