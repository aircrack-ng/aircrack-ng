Summary:	Reliable 802.11 (wireless) sniffer and WEP/WPA-PSK key cracker
Name:		aircrack-ng
Version:	0.6.2
Release:	1
License:	GPL
Group:		Productivity/Networking/Other
URL:		http://www.aircrack-ng.org
Source:		http://freshmeat.net/redir/aircrack-ng/63481/url_tgz/%{name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root
Packager:	David Bolt <davjam@davjam.org>
Requires:	glibc >= 2

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
%{__make}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
for BINARY in aircrack-ng airdecap-ng arpforge-ng ivstools
do
 install -m 755 "$BINARY" %{buildroot}%{_bindir}
done

mkdir -p %{buildroot}%{_sbindir}
for BINARY in aireplay-ng airodump-ng airmon-ng
do
 install -m 755 "$BINARY" %{buildroot}%{_sbindir}
done

mkdir -p %{buildroot}%{_mandir}/man1
cd manpages
for BINARY in aircrack-ng airdecap-ng aireplay-ng airodump-ng arpforge-ng airmon-ng ivstools
do
 install -m 644 "$BINARY.1" %{buildroot}%{_mandir}/man1
done

%clean
rm -rf %{buildroot}

%files
%defattr(-, root, root, 0755)
%{_sbindir}/aireplay-ng
%{_sbindir}/airodump-ng
%{_sbindir}/airmon-ng
%{_bindir}/aircrack-ng
%{_bindir}/airdecap-ng
%{_bindir}/arpforge-ng
%{_bindir}/ivstools
%doc ChangeLog INSTALL README LICENSE AUTHORS VERSION
%doc test
%doc patches
%{_mandir}/man1/aircrack-ng.*
%{_mandir}/man1/airdecap-ng.*
%{_mandir}/man1/aireplay-ng.*
%{_mandir}/man1/airodump-ng.*
%{_mandir}/man1/arpforge-ng.*
%{_mandir}/man1/airmon-ng.*
%{_mandir}/man1/ivstools.*

%changelog
* Mon Jun 26 2006 David Bolt <davjam@davjam.org> aircrack-ng-0.6
- Removed patch as no longer needed for SUSE 10.1 (GCC 4.1.2)
* Fri Jun  2 2006 David Bolt <davjam@davjam.org> aircrack-ng-0.5
- Patched source to build properly on SUSE 10.1 (GCC 4.1.2)
* Thu Mar 30 2006 David Bolt <davjam@davjam.org>
- First package built for SUSE

