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

 * OpenSSL development package or libgcrypt development package
 * If you want to use `airolib-ng` and `-r` option in aircrack-ng,
   SQLite development package `>= 3.3.17` (3.6.X version or better is recommended):
   `libsqlite3-devel`
 * On windows, cygwin has to be used and it also requires w32api and gcc-4 package.
 * If you want to use Airpcap, the 'developer' directory from the CD is required.

## Compilating

 * Compilation:

    `make`

 * Strip debugging symbols:

    `make strip`

 * Installing:

    `make install`

 * Uninstall:

    `make uninstall`


###  Makefile flags

When compile and installing, the following flags can be used and combined
to compile and install the suite:

* **sqlite**:   needed to compile `airolib-ng` and add support for `airolib-ng`
                databases in aircrack-ng.
                On cygwin: SQLite has to be compiled manually. See next section.

* **airpcap**:  needed for supporting airpcap devices on windows (cygwin only)
                REQUIREMENT: Copy 'developers' directory from Airpcap CD one 
                level below this INSTALLING file
                Note: Not working yet.

* **experimental**: needed to compile `tkiptun-ng`, `easside-ng` (and `buddy-ng`) and
                    `wesside-ng`

* **ext_scripts**: needed to build `airoscript-ng`, `versuck-ng`, `airgraph-ng` and 
                   `airdrop-ng`. 
                   Note: Experimental. Each script has its own dependences.
                   Note: It's only required in install phase.

* **gcrypt**:   Use libgcrypt crypto library instead of the default OpenSSL.
                And also use internal fast sha1 implementation (borrowed from GIT)

* **libnl**:    Add support for netlink (nl80211). Linux only.
    - Requires `libnl1` OR `libnl3`.
    - Dependencies (debian):
        + LibNL 1: `libnl-dev`
        + LibNL 3: `libnl-3-dev` and `libnl-genl-3-dev`.

#### Examples:

  * Compiling with sqlite and enabling experimental:

    `make sqlite=true experimental=true`

  * Installing:

    `make sqlite=true experimental=true install`

  * Installing, with external scripts:

    `make sqlite=true experimental=true ext_scripts=true`

  * Compiling with gcrypt:

    `make gcrypt=true`


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


Documentation, tutorials, ... can be found on http://www.aircrack-ng.org

See also manpages and the forum.

For further information check the [README](README) file
