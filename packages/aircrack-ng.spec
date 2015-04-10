%define _rel final

# these bits are constant across distributions
#
Name:           aircrack-ng
Version:        1.2-rc2
Summary:        Reliable 802.11 (wireless) sniffer and WEP/WPA-PSK key cracker
License:        GPL
Source:         http://dl.aircrack-ng.org/%{name}-%{version}.tar.gz
URL:            http://www.aircrack-ng.org/
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
Packager:       David Bolt <davjam@davjam.org>
Requires: openssl-devel glibc >= 2


# define the package groups. If they all followed the LSB these would be the same, but they aren't :(
#
%define suse_group Productivity/Networking/Other
%define mandriva_group Productivity/Networking/Other
%define fedora_group Productivity/Networking/Other



# just in case we're not building on a (open)SUSE, Mandriva or Fedora system.
#
%define rel %{_rel}


# figure out which distribution we're being built on. choices so far are (open)SUSE, Mandriva and Fedora Core.
#
%define _suse    %(if [ -f /etc/SuSE-release ]; then echo 1; else echo 0; fi)
%define _mandriva %(if [ -f /etc/mandriva-release ]; then echo 1; else echo 0; fi)
%define _fedora %(if [ -f /etc/fedora-release ]; then echo 1; else echo 0; fi)

# interesting facts: Mandriva includes /etc/redhat-release, as does Fedora.
# This means any builds for redhat are going to need to parse /etc/redhat-release
# to make sure they're being built on a redhat system

%if %{_suse}
%define _mandriva 0
%define _fedora 0
%endif

%if %{_mandriva}
%define _fedora 0
%endif


# now for some distribution-specific modifications.
#
# these include making a distro-specific release number
#

# building on a (open)SUSE Linux system so make a release identifier for the (open)SUSE version
#
%if %_suse
%define _suse_version %(grep VERSION /etc/SuSE-release|cut -f3 -d" ")
%define _suse_vernum %(echo "%{_suse_version}"|tr -d '.')
%define rel %{_rel}.suse%{_suse_vernum}
%define _distribution SUSE Linux %{_suse_version}
%define group %{suse_group}

# distro name change for SUSE >= 10.2 to openSUSE
#
%if %suse_version >= 1020

  %define _distribution openSUSE %{_suse_version}

%endif

# not defined by SUSE/Novell but useful to have
#
%define _icondir %{_datadir}/pixmaps/

%endif

# building on a Mandriva/Mandrake Linux system so use the standard Mandriva release string
#
# this is experimental and untested as yet, but should work.
#
%if %{_mandriva}
%define _mandriva_version %(cat /etc/mandriva-release|cut -f4 -d" ")
%define _distribution Mandriva %{_mandriva_version}
%define rel %{_rel}.mdv
%define group %{mandriva_group}

%endif


# building on a Fedora Core Linux system. not sure if there's a release string, but create one anyway
#
# this is experimental and untested as yet, but should work.
#
%if %{_fedora}
%define _fedora_version %(cat /etc/fedora-release|cut -f3 -d" ")
%define _distribution Fedora Core %{_fedora_version}
%define rel %{_rel}.fc%{_fedora_version}
%define group %{fedora_group}
%endif


# while these few are (relatively) distro-specific
#
Group:          %{group}
Release:        %{rel}
%{?_distribution:Distribution:%{_distribution}}


%description
aircrack-ng is a set of tools for auditing wireless networks. It's an
enhanced/reborn version of aircrack. It consists of airodump-ng (an 802.11
packet capture program), aireplay-ng (an 802.11 packet injection program),
aircrack (static WEP and WPA-PSK cracking), airdecap-ng (decrypts WEP/WPA
capture files), and some tools to handle capture files (merge, convert,
etc.).

%prep
%setup -q

%build
make %{?_smp_mflags} sqlite=true pcre=true experimental=true

%install

rm -rf $RPM_BUILD_ROOT
mkdir $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT prefix=%{_prefix} mandir=%{_mandir}/man1 sqlite=true pcre=true experimental=true

cd $RPM_BUILD_ROOT
find . -type d | sed '1,2d;s,^\.,\%attr(-\,root\,root) \%dir ,' > %{_builddir}/file.list.%{name}
find . -type f | sed 's,^\.,\%attr(-\,root\,root) ,' | grep -v /man/ >> %{_builddir}/file.list.%{name}
find . -type l | sed 's,^\.,\%attr(-\,root\,root) ,' >> %{_builddir}/file.list.%{name}

%files -f %{_builddir}/file.list.%{name}
%doc ChangeLog INSTALLING README LICENSE AUTHORS VERSION
%doc test
%doc patches
%{_mandir}/man1/*

%clean
rm -rf $RPM_BUILD_ROOT

%changelog
* Sun Jan 29 2009 Xury <xury@poczta.onet.pl> aircrack-ng-1.0-rc3
- small fix and update spec file
* Mon Jun 26 2006 David Bolt <davjam@davjam.org> aircrack-ng-0.6
- Removed patch as no longer needed for SUSE 10.1 (GCC 4.1.2)
* Fri Jun  2 2006 David Bolt <davjam@davjam.org> aircrack-ng-0.5
- Patched source to build properly on SUSE 10.1 (GCC 4.1.2)
* Thu Mar 30 2006 David Bolt <davjam@davjam.org>
- First package built for SUSE
