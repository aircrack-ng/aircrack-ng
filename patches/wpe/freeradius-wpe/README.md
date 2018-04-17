# FreeRadius Wireless Pawn Edition

Updated patch for FreeRadius 3.0.13-3.0.17

More information about WPE can be found:
http://www.willhackforsushi.com/?page_id=37

Supported and tested EAP Types/Inner Authentication Methods (others may also work):
* PEAP/PAP (OTP)
* PEAP/MSCHAPv2
* EAP-TTLS/PAP (includes OTPs)
* EAP-TTLS/MSCHAPv1
* EAP-TTLS/MSCHAPv2
* EAP-MD5

## Installing

### Dependencies

```
apt-get install libssl-dev build-essential libtalloc-dev libpcre3-dev
```

### Compilation

Run the following commands:

```
wget https://github.com/FreeRADIUS/freeradius-server/archive/release_3_0_17.tar.gz
tar -xzf release_3_0_17.tar.gz
cd freeradius-server-release_3_0_17/
wget https://raw.githubusercontent.com/aircrack-ng/aircrack-ng/master/patches/wpe/freeradius-wpe/freeradius-wpe.patch
patch -Np1 -i freeradius-server-wpe.patch
./configure
make
make install
ldconfig
```

## Running

Start ```radiusd``` in a terminal:

```
radiusd -s -X
```

If it fails running and complains about OpenSSL being vulnerable, make sure OpenSSL is up to date. If you are using a recent distribution, most likely OpenSSL is patched, and you can safely allow it. In order to do so, edit /usr/local/etc/raddb/radiusd.conf and change ```allow_vulnerable_openssl``` from ```no``` to ```'CVE-2016-6304'``` (with the single quotes).

Now, connect a client. Once a username/password is entered and the certificate accepted, information regarding that session will be stored in ```/usr/local/var/log/radius/freeradius-server-wpe.log```.

**Note**: This file won't be created until the first client connects and authenticates to the access point.

## Note

Debian testing disabled TLS 1.0 and TLS 1.1 which break FreeRADIUS-WPE <= 3.0.15. Although not recommended to use an older version, if compiling FreeRADIUS <= 3.0.15, run the following commands before running `./configure`:

```
wget https://raw.githubusercontent.com/aircrack-ng/aircrack-ng/master/patches/wpe/freeradius-wpe/freeradius_3_0_15_openssl_1_1_tls_version_fix.diff
patch -Np1 -i freeradius_3_0_15_openssl_1_1_tls_version_fix.diff
```
