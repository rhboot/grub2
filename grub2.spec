# Modules always contain just 32-bit code
%define _libdir %{_exec_prefix}/lib

# 64bit intel machines use 32bit boot loader
# (We cannot just redefine _target_cpu, as we'd get i386.rpm packages then)
%ifarch x86_64
%define _target_platform i386-%{_vendor}-%{_target_os}%{?_gnu}
%endif
#sparc is always compile 64 bit
%ifarch %{sparc}
%define _target_platform sparc64-%{_vendor}-%{_target_os}%{?_gnu}
%endif

Name:           grub2
Epoch:          1
Version:        1.97.1
Release:        5%{?dist}
Summary:        Bootloader with support for Linux, Multiboot and more

Group:          System Environment/Base
License:        GPLv3+
URL:            http://www.gnu.org/software/grub/
Source0:        ftp://alpha.gnu.org/gnu/grub/grub-%{version}.tar.gz
Source1:        90_persistent
Source2:        grub.default
Source3:        README.Fedora
Patch0:         grub-1.95-grubdir.patch
Patch1:         http://fedorapeople.org/~lkundrak/grub2/grub2-dlsym-v4.patch
Patch2:         grub-1.97.1-initramfs.patch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  flex bison ruby binutils
BuildRequires:  ncurses-devel lzo-devel
BuildRequires:  freetype-devel libusb-devel
%ifarch %{sparc}
BuildRequires:  /usr/lib64/crt1.o glibc-static
%else
BuildRequires:  /usr/lib/crt1.o glibc-static
%endif
BuildRequires:  autoconf automake

# grubby
Requires(pre):  dracut
Requires(post): dracut

# TODO: ppc
ExclusiveArch:  %{ix86} x86_64 %{sparc}

%description
This is the second version of the GRUB (Grand Unified Bootloader),
a highly configurable and customizable bootloader with modular
architecture.  It support rich scale of kernel formats, file systems,
computer architectures and hardware devices.

PLEASE NOTE: This is a development snapshot, and as such will not
replace grub if you install it, but will be merely added as another
kernel to your existing GRUB menu. Do not replace GRUB (grub package)
with it unless you know what are you doing. Refer to README.Fedora
file that is part of this package's documentation for more information.


%prep
%setup -q -n grub-%{version}

%patch0 -p1 -b .grubdir
%patch1 -p1 -b .dlsym
%patch2 -p1 -b .initramfs

# README.Fedora
cp %{SOURCE3} .


%build
sh autogen.sh
# -static is needed so that autoconf script is able to link
# test that looks for _start symbol on 64 bit platforms
%configure TARGET_LDFLAGS=-static       \
%ifarch %{sparc}
        --with-platform=ieee1275        \
%else
        --with-platform=pc              \
%endif
        --enable-grub-emu               \
        --program-transform-name=s,grub,%{name},
# TODO: Other platforms. Use alternatives system?
#       --with-platform=ieee1275        \
#       --with-platform=efi             \
#       --with-platform=i386-pc         \


make %{?_smp_mflags}
#gcc -Inormal -I./normal -I. -Iinclude -I./include -Wall -W -DGRUB_LIBDIR=\"/usr/lib/`echo grub/i386-pc | sed 's&^&&;s,grub,grub2,'`\" -O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic -DGRUB_UTIL=1  -MD -c -o grub_emu-normal_lexer.o normal/lexer.c
#In file included from normal/lexer.c:23:
#include/grub/script.h:26:29: error: grub_script.tab.h: No such file or directory
#make


%install
set -e
rm -fr $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT install

# Script that makes part of grub.cfg persist across updates
install -m 755 %{SOURCE1} $RPM_BUILD_ROOT%{_sysconfdir}/grub.d/

# Ghost config file
install -d $RPM_BUILD_ROOT/boot/%{name}
touch $RPM_BUILD_ROOT/boot/%{name}/grub.cfg
ln -s ../boot/%{name}/grub.cfg $RPM_BUILD_ROOT%{_sysconfdir}/%{name}.cfg

# Install ELF files modules and images were created from into
# the shadow root, where debuginfo generator will grab them from
find $RPM_BUILD_ROOT -name '*.mod' -o -name '*.img' |
while read MODULE
do
        BASE=$(echo $MODULE |sed -r "s,.*/([^/]*)\.(mod|img),\1,")
        # Symbols from .img files are in .exec files, while .mod
        # modules store symbols in .elf. This is just because we
        # have both boot.img and boot.mod ...
        EXT=$(echo $MODULE |grep -q '.mod' && echo '.elf' || echo '.exec')
        TGT=$(echo $MODULE |sed "s,$RPM_BUILD_ROOT,.debugroot,")
#        install -m 755 -D $BASE$EXT $TGT
done

# Defaults
install -m 644 -D %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/default/grub


%clean    
rm -rf $RPM_BUILD_ROOT


%post
exec >/dev/null 2>&1
# Create device.map or reuse one from GRUB Legacy
cp -u /boot/grub/device.map /boot/%{name}/device.map 2>/dev/null ||
        %{name}-mkdevicemap
# Determine the partition with /boot
BOOT_PARTITION=$(df -h /boot |(read; awk '{print $1; exit}'))
# Generate core.img, but don't let it be installed in boot sector
%{name}-install --grub-setup=/bin/true $BOOT_PARTITION
# Remove stale menu.lst entries
/sbin/grubby --remove-kernel=/boot/%{name}/core.img
# Add core.img as multiboot kernel to GRUB Legacy menu
/sbin/grubby --add-kernel=/boot/%{name}/core.img --title="GNU GRUB 2, (%{version})"


%preun
exec >/dev/null
/sbin/grubby --remove-kernel=/boot/%{name}/core.img
# XXX Ugly
rm -f /boot/%{name}/*.mod
rm -f /boot/%{name}/*.img
rm -f /boot/%{name}/*.lst
rm -f /boot/%{name}/device.map


%triggerin -- kernel, kernel-PAE
exec >/dev/null 2>&1
# Generate grub.cfg
%{name}-mkconfig


%triggerun -- kernel, kernel-PAE
exec >/dev/null 2>&1
# Generate grub.cfg
%{name}-mkconfig


%files
%defattr(-,root,root,-)
%{_libdir}/%{name}
%{_libdir}/grub/
%{_sbindir}/%{name}-mkdevicemap
%{_sbindir}/%{name}-install
%{_sbindir}/%{name}-emu
%{_sbindir}/%{name}-probe
%{_sbindir}/%{name}-setup
%{_sbindir}/%{name}-mkconfig
%{_bindir}/%{name}-mkimage
%{_bindir}/%{name}-mkelfimage
%{_bindir}/%{name}-editenv
%{_bindir}/%{name}-fstest
%{_bindir}/%{name}-mkfont
%ifnarch %{sparc}
%{_bindir}/%{name}-mkrescue
%endif
%ifarch %{sparc}
%{_sbindir}/%{name}-ofpathname
%endif
%dir %{_sysconfdir}/grub.d
%config %{_sysconfdir}/grub.d/??_*
%{_sysconfdir}/grub.d/README
%{_sysconfdir}/%{name}.cfg
%{_sysconfdir}/default/grub
%dir /boot/%{name}
# Actually, this is replaced by update-grub from scriptlets,
# but it takes care of modified persistent part
%config(noreplace) /boot/%{name}/grub.cfg
%doc COPYING INSTALL NEWS README THANKS TODO ChangeLog README.Fedora
%exclude %{_mandir}



%changelog
* Wed Jan 20 2010 Dennis Gilmore <dennis@ausil.us> - 1:1.97.1-5
- drop requires on mkinitrd

* Tue Dec 01 2009 Dennis Gilmore <dennis@ausil.us> - 1:1.97.1-4
- add patch so that grub2 finds fedora's initramfs

* Tue Nov 10 2009 Dennis Gilmore <dennis@ausil.us> - 1:1.97.1-3
- no mkrescue on sparc arches
- ofpathname on sparc arches
- Requires dracut, not sure if we should just drop mkinitrd for dracut

* Tue Nov 10 2009 Dennis Gilmore <dennis@ausil.us> - 1:1.97.1-2
- update filelists

* Tue Nov 10 2009 Dennis Gilmore <dennis@ausil.us> - 1:1.97.1-1
- update to 1.97.1 release
- introduce epoch for upgrades

* Tue Nov 10 2009 Dennis Gilmore <dennis@ausil.us> - 1.98-0.7.20090911svn
- fix BR

* Fri Sep 11 2009 Dennis Gilmore <dennis@ausil.us> - 1.98-0.6.20090911svn
- update to new svn snapshot
- add sparc support

* Fri Jul 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.98-0.6.20080827svn
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Sun Mar 01 2009 Lubomir Rintel <lkundrak@v3.sk> - 1.98-0.4.20080827svn
- Add missing BR

* Tue Feb 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.98-0.4.20080827svn
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Wed Aug 27 2008 Lubomir Rintel <lkundrak@v3.sk> - 1.98-0.3.20080827svn
- Updated SVN snapshot
- Added huge fat warnings

* Fri Aug 08 2008 Lubomir Rintel <lkundrak@v3.sk> - 1.98-0.2.20080807svn
- Correct scriptlet dependencies, trigger on kernel-PAE (thanks to Till Maas)
- Fix build on x86_64 (thanks to Marek Mahut)

* Thu Aug 07 2008 Lubomir Rintel <lkundrak@v3.sk> 1.98-0.1.20080807svn
- Another snapshot
- And much more!

* Mon May 12 2008 Lubomir Kundrak <lkundrak@redhat.com> 1.97-0.1.20080512cvs
- CVS snapshot
- buildid patch upstreamed

* Sat Apr 12 2008 Lubomir Kundrak <lkundrak@redhat.com> 1.96-2
- Pull in 32 bit glibc
- Fix builds on 64 bit

* Sun Mar 16 2008 Lubomir Kundrak <lkundrak@redhat.com> 1.96-1
- New upstream release
- More transformation fixes
- Generate -debuginfo from modules again. This time for real.
- grubby stub
- Make it possible to do configuration changes directly in grub.cfg
- grub.cfg symlink in /etc

* Thu Feb 14 2008 Lubomir Kundrak <lkundrak@redhat.com> 1.95.cvs20080214-3
- Update to latest trunk
- Manual pages
- Add pci.c to DISTLIST

* Mon Nov 26 2007 Lubomir Kundrak <lkundrak@redhat.com> 1.95.cvs20071119-2
- Fix program name transformation in utils
- Moved the modules to /lib
- Generate -debuginfo from modules again

* Sun Nov 18 2007 Lubomir Kundrak <lkundrak@redhat.com> 1.95.cvs20071119-1
- Synchronized with CVS, major specfile cleanup

* Mon Jan 30 2007 Lubomir Kundrak <lkundrak@skosi.org> 1.95-lkundrak1
- Removed redundant filelist entries

* Mon Jan 29 2007 Lubomir Kundrak <lkundrak@skosi.org> 1.95-lkundrak0
- Program name transformation
- Bump to 1.95
- grub-probefs -> grub-probe
- Add modules to -debuginfo

* Tue Sep 12 2006 Lubomir Kundrak <lkundrak@skosi.org> 1.94-lkundrak0
- built the package
