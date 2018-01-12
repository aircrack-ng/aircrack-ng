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

To build `aircrack-ng`, the Autotools build system is utilized. Autotools replaces
the older method of compilation.

**NOTE**: If utilizing a developer version, eg: one checked out from source control,
you will need to run a pre-`configure` script. The script to use is one of the
following: `autoreconf -i` or `env NOCONFIGURE=1 ./autogen.sh`.

First, `./configure` the project for building with the appropriate options specified
for your environment:

    `./configure <options>`

**TIP**: If the above fails, please see above about developer source control versions.

Next, compile the project (respecting if `make` or `gmake` is needed):

 * Compilation:

    `make`

 * Compilation on *BSD or Solaris:
 
    `gmake`

Finally, the additional targets listed below may be of use in your environment:

 * Strip debugging symbols:

    `make strip`

 * Installing:

    `make install`

 * Uninstall:

    `make uninstall`


###  `./configure` flags

When configuring, the following flags can be used and combined to adjust the suite
to your choosing:

* **with-airpcap=DIR**:  needed for supporting airpcap devices on windows (cygwin or msys2 only)
                Replace DIR above with the absolute location to the root of the
                extracted source code from the Airpcap CD or downloaded SDK available
                online.

* **with-experimental**: needed to compile `tkiptun-ng`, `easside-ng` (and `buddy-ng`) and
                    `wesside-ng`. Building besside-ng-crawler requires LibPCAP 
                    (development package). On debian based distro, install libpcap-dev

* **with-ext-scripts**: needed to build `airoscript-ng`, `versuck-ng`, `airgraph-ng` and 
                   `airdrop-ng`. 
                   Note: Experimental. Each script has its own dependences.
                   Note: It's only required in install phase.

* **with-gcrypt**:   Use libgcrypt crypto library instead of the default OpenSSL.
                And also use internal fast sha1 implementation (borrowed from GIT)
                Dependency (Debian): libgcrypt20-dev

* **with-duma**:	Compile with DUMA support. DUMA is a library to detect buffer overruns and under-runs.
            	Dependencies (debian): duma

* **with-xcode**:    Set this flag to true to compile on OS X with Xcode 7+.

* **with-simd**:  Compile with SIMD optimizations. This is an auto-detected feature that
                  probably does not need changed, unless wishing to disable SIMD
                  optimizations using `--without-simd`.

#### Examples:

  * Configure and compiling:

    `./configure --with-experimental`
    `make`

  * Compiling wth gcrypt:

    `./configure --with-gcrypt`
    `make`

  * Installing:

    `make install`

  * Installing, with external scripts:

    `./configure --with-experimental --with-ext-scripts`
    `make`
    `make install`

  * Testing (with sqlite, experimental and pcre)

    `./configure --with-experimental`
    `make`
    `make check`

  * Compiling on OS X with macports (and all options):

    `./configure --with-experimental`
    `gmake`

  * Compiling on OS X 10.10 with XCode 7.1 and Homebrew:

    `env CC=gcc-4.9 CXX=g++-4.9 ./configure`
    `make`
    `make check`

    *NOTE*: Older XCode ships with a version of LLVM that does not support CPU feature
    detection; which causes the `./configure` to fail. To work around this older LLVM,
    it is required that a different compile suite is used, such as GCC or a newer LLVM
    from Homebrew.

    If you wish to use OpenSSL from Homebrew, you may need to specify the location
    to its' installation. To figure out where OpenSSL lives, run:

    `brew --prefix openssl`

    Use the output above as the DIR for `--with-openssl=DIR` in the `./configure` line:

    `env CC=gcc-4.9 CXX=g++-4.9 ./configure --with-openssl=DIR`
    `make`
    `make check`

  * Compiling on FreeBSD with better performance

    `env CC=gcc5 CXX=g++5 ./configure`
    `gmake`

# Packaging

Automatic detection of CPU optimization is done at compile time. This behavior
is not desirable when packaging Aircrack-ng (for a Linux distribution).

It can be overridden by configuring the build to not utilize the auto-detection
feature:

`./configure --without-simd`

Also, in some cases it may be desired to provide your own flags completely and
not having the suite auto-detect a number of optimizations. To do this, add
the additional flag `--without-opt` to the `./configure` line:

`./configure --without-simd --without-opt`

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
