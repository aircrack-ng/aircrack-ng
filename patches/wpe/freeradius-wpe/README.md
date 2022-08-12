# FreeRadius Wireless Pawn Edition

Updated patch for FreeRadius 3.2.0

More information about WPE can be found:
https://www.willhackforsushi.com/?page_id=37

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
apt install libssl-dev build-essential libtalloc-dev libpcre3-dev
```

### Optional dependencies

```
apt install libsqlite3-dev libhiredis-dev libykclient-dev libyubikey-dev default-libmysqlclient-dev libcurl4-openssl-dev libperl-dev libpam0g-dev libcap-dev libmemcached-dev libgdbm-dev unixodbc-dev libpq-dev libwbclient-dev libkrb5-dev libjson-c-dev freetds-dev libwbclient-sssd-dev samba-dev libcollectdclient-dev libldap-dev
```

### Compilation

Run the following commands:

```
wget ftp://ftp.freeradius.org/pub/freeradius/freeradius-server-3.2.0.tar.bz2
tar -xjf freeradius-server-3.2.0.tar.bz2
cd freeradius-server-3.2.0/
wget https://raw.githubusercontent.com/aircrack-ng/aircrack-ng/master/patches/wpe/freeradius-wpe/freeradius-server-3.2.0-wpe.diff
patch -Np1 -i freeradius-server-3.2.0-wpe.diff
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
