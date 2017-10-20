# Aircrack-ng
Aircrack-ng is an 802.11 WEP and WPA-PSK keys cracking program that can recover
keys once enough data packets have been captured. It implements the standard FMS
attack along with some optimizations like KoreK attacks, as well as the
all-new PTW attack, thus making the attack much faster compared to other WEP
cracking tools.

It can attack WPA1/2 networks with some advanced methods or simply by brute force.
It can also fully use a multiprocessor system to its full power in order
to speed up the cracking process.


[![Build Status](https://api.travis-ci.org/aircrack-ng/aircrack-ng.png)](https://travis-ci.org/aircrack-ng/aircrack-ng)


# Building

## Requirements

 * OpenSSL development package or libgcrypt development package.
 * Airmon-ng (Linux) requires ethtool.
 * On windows, cygwin has to be used and it also requires w32api package.
 * Linux: LibNetlink 1 or 3. It can be disabled by setting the flag 'libnl' to false.
 * pkg-config (pkgconf on FreeBSD)
 * FreeBSD, OpenBSD, NetBSD, Solaris and OS X with macports: gmake
 * Linux/Cygwin: make and Standard C++ Library development package (Debian: libstdc++-dev)

## Optional stuff

 * If you want SSID filtering with regular expression in airodump-ng
   (-essid-regex) pcre development package is required.
 * If you want to use airolib-ng and '-r' option in aircrack-ng,
   SQLite development package >= 3.3.17 (3.6.X version or better is recommended)
 * If you want to use Airpcap, the 'developer' directory from the CD is required.
 * For best performance on FreeBSD (50-70% more), install gcc5 via: pkg install gcc5
          Then compile with: gmake CC=gcc5 CXX=g++5
 * rfkill

## Compiling

 * Compilation:

    `make`

 * Compilation on *BSD or Solaris:
 
    `gmake`

 * Strip debugging symbols:

    `make strip`

 * Installing:

    `make install`

 * Uninstall:

    `make uninstall`


###  Makefile flags

When compile and installing, the following flags can be used and combined
to compile and install the suite:

* **sqlite**:   Compile airolib-ng and add support for airolib-ng databases
                in aircrack-ng:
    - Debian based distro: libsqlite3-dev
    - FreeBSD: sqlite3

* **airpcap**:  needed for supporting airpcap devices on windows (cygwin only)
                REQUIREMENT: Copy 'developers' directory from Airpcap CD one 
                level below this INSTALLING file
                Note: Not working yet.

* **experimental**: needed to compile `tkiptun-ng`, `easside-ng` (and `buddy-ng`) and
                    `wesside-ng`. Building besside-ng-crawler requires LibPCAP 
                    (development package). On debian based distro, install libpcap-dev

* **ext_scripts**: needed to build `airoscript-ng`, `versuck-ng`, `airgraph-ng` and 
                   `airdrop-ng`. 
                   Note: Experimental. Each script has its own dependences.
                   Note: It's only required in install phase.

* **gcrypt**:   Use libgcrypt crypto library instead of the default OpenSSL.
                And also use internal fast sha1 implementation (borrowed from GIT)
                Dependency (Debian): libgcrypt20-dev

* **libnl**:    Add support for netlink (nl80211). Linux only.
    - Requires `libnl1` OR `libnl3`.
    - Dependencies (debian):
        + LibNL 1: `libnl-dev`
        + LibNL 3: `libnl-3-dev` and `libnl-genl-3-dev`.

* **pcre**:	Add support for regular expression matching for ESSID in airodump-ng and besside-ng.
            	Dependencies (debian): libpcre3-dev
    - Debian based distro: libpcre3-dev
    - FreeBSD: pcre

* **duma**:	Compile with DUMA support. DUMA is a library to detect buffer overruns and under-runs.
            	Dependencies (debian): duma

* **xcode**:    Set this flag to true to compile on OS X with Xcode 7+.

* **macport**:  Set this flag to true to compile on OS X with macports.

#### Examples:

  * Compiling:

    `make sqlite=true experimental=true pcre=true`

  * Compiling wth gcrypt:
    `make gcrypt=true`

  * Installing:

    `make sqlite=true pcre=true experimental=true install`

  * Installing, with external scripts:

    `make sqlite=true experimental=true ext_scripts=true`

  * Testing (with sqlite, experimental and pcre)

    `make sqlite=true experimental=true pcre=true check`

  * Compiling on OS X with macports (and all options):

    `gmake macport=true sqlite=true experimental=true pcre=true`

  * Compiling on FreeBSD with better performance

    `gmake CC=gcc5 CXX=g++5`

# Packaging

Automatic detection of CPU optimization is done at compile time. This behavior
is not desirable when packaging Aircrack-ng (for a Linux distribution).

It can be overridden by creating common.cfg in the same directory as this file
with the following settings when compiling on x86 (32 or 64 bit):
```
NEWSSE=false
SIMDCORE=false
PTHREAD=Y
```

# Using precompiled binaries

Linux/BSD:
 * Use your package manager to download aircrack-ng
 * In most cases, they have an old version.

Windows:
 * Install the appropriate "monitor" driver for your card (standard drivers doesn't work for capturing data).
 * aircrack-ng suite is command line tools. So, you have to open a commandline
   `Start menu -> Run... -> cmd.exe` then use them
 * Run the executables without any parameters to have help

# Documentation


Documentation, tutorials, ... can be found on https://www.aircrack-ng.org

See also manpages and the forum.

For further information check the [README](README) file
