bash_completion_source = grub-completion.bash.in
bash_completion_script = grub
grub_bios_setup_source = grub-bios-setup.bash.in
grub_bios_setup_script = @grub_bios_setup@
grub_editenv_source = grub-editenv.bash.in
grub_editenv_script = @grub_editenv@
grub_install_source = grub-install.bash.in
grub_install_script = @grub_install@
grub_mkconfig_source = grub-mkconfig.bash.in
grub_mkconfig_script = @grub_mkconfig@
grub_mkfont_source = grub-mkfont.bash.in
grub_mkfont_script = @grub_mkfont@
grub_mkimage_source = grub-mkimage.bash.in
grub_mkimage_script = @grub_mkimage@
grub_mkpasswd_pbkdf2_source = grub-mkpasswd-pbkdf2.bash.in
grub_mkpasswd_pbkdf2_script = @grub_mkpasswd_pbkdf2@
grub_mkrescue_source = grub-mkrescue.bash.in
grub_mkrescue_script = @grub_mkrescue@
grub_probe_source = grub-probe.bash.in
grub_probe_script = @grub_probe@
grub_reboot_source = grub-reboot.bash.in
grub_reboot_script = @grub_reboot@
grub_script_check_source = grub-script-check.bash.in
grub_script_check_script = @grub_script_check@
grub_set_default_source = grub-set-default.bash.in
grub_set_default_script = @grub_set_default@
grub_sparc64_setup_source = grub-sparc64-setup.bash.in
grub_sparc64_setup_script = @grub_sparc64_setup@

EXTRA_DIST = $(bash_completion_source) \
	$(grub_bios_setup_source) \
	$(grub_editenv_source) \
	$(grub_install_source) \
	$(grub_mkconfig_source) \
	$(grub_mkfont_source) \
	$(grub_mkimage_source) \
	$(grub_mkpasswd_pbkdf2_source) \
	$(grub_mkrescue_source) \
	$(grub_probe_source) \
	$(grub_reboot_source) \
	$(grub_script_check_source) \
	$(grub_set_default_source) \
	$(grub_sparc64_setup_source)

CLEANFILES = $(bash_completion_script) \
	$(grub_bios_setup_script) \
	$(grub_editenv_script) \
	$(grub_install_script) \
	$(grub_mkconfig_script) \
	$(grub_mkfont_script) \
	$(grub_mkimage_script) \
	$(grub_mkpasswd_pbkdf2_script) \
	$(grub_mkrescue_script) \
	$(grub_probe_script) \
	$(grub_reboot_script) \
	$(grub_script_check_script) \
	$(grub_set_default_script) \
	$(grub_sparc64_setup_script) \
	config.log

bashcompletiondir = $(datarootdir)/bash-completion/completions
bashcompletion_DATA = $(bash_completion_script) \
	$(grub_bios_setup_script) \
	$(grub_editenv_script) \
	$(grub_install_script) \
	$(grub_mkconfig_script) \
	$(grub_mkfont_script) \
	$(grub_mkimage_script) \
	$(grub_mkpasswd_pbkdf2_script) \
	$(grub_mkrescue_script) \
	$(grub_probe_script) \
	$(grub_reboot_script) \
	$(grub_script_check_script) \
	$(grub_set_default_script) \
	$(grub_sparc64_setup_script)

$(bash_completion_script): $(bash_completion_source) $(top_builddir)/config.status
	$(top_builddir)/config.status --file=$@:$<

$(grub_bios_setup_script): $(grub_bios_setup_source) $(top_builddir)/config.status
	$(top_builddir)/config.status --file=$@:$<

$(grub_editenv_script): $(grub_editenv_source) $(top_builddir)/config.status
	$(top_builddir)/config.status --file=$@:$<

$(grub_install_script): $(grub_install_source) $(top_builddir)/config.status
	$(top_builddir)/config.status --file=$@:$<

$(grub_mkconfig_script): $(grub_mkconfig_source) $(top_builddir)/config.status
	$(top_builddir)/config.status --file=$@:$<

$(grub_mkfont_script): $(grub_mkfont_source) $(top_builddir)/config.status
	$(top_builddir)/config.status --file=$@:$<

$(grub_mkimage_script): $(grub_mkimage_source) $(top_builddir)/config.status
	$(top_builddir)/config.status --file=$@:$<

$(grub_mkpasswd_pbkdf2_script): $(grub_mkpasswd_pbkdf2_source) $(top_builddir)/config.status
	$(top_builddir)/config.status --file=$@:$<

$(grub_mkrescue_script): $(grub_mkrescue_source) $(top_builddir)/config.status
	$(top_builddir)/config.status --file=$@:$<

$(grub_probe_script): $(grub_probe_source) $(top_builddir)/config.status
	$(top_builddir)/config.status --file=$@:$<

$(grub_reboot_script): $(grub_reboot_source) $(top_builddir)/config.status
	$(top_builddir)/config.status --file=$@:$<

$(grub_script_check_script): $(grub_script_check_source) $(top_builddir)/config.status
	$(top_builddir)/config.status --file=$@:$<

$(grub_set_default_script): $(grub_set_default_source) $(top_builddir)/config.status
	$(top_builddir)/config.status --file=$@:$<

$(grub_sparc64_setup_script): $(grub_sparc64_setup_source) $(top_builddir)/config.status
	$(top_builddir)/config.status --file=$@:$<
