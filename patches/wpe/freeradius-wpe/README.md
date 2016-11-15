# FreeRadius Wireless Pawn Edition

Updated patch for FreeRadius 3.0.12

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

Assuming the patch is downloaded in the current directory, run the following commands:

```
wget ftp://ftp.freeradius.org/pub/freeradius/freeradius-server-3.0.12.tar.bz2
tar -xvf freeradius-server-3.0.12.tar.bz2
cd freeradius-server-3.0.12
patch -Np1 -i ../freeradius-server-wpe.patch
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

**Note**: This file won't be created until the first client connects and authenticate to the access point.
