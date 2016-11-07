# FreeRadius Wireless Pawn Edition

Updated patch for FreeRadius 2.2.8 (and 2.2.9)

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
apt-get install libssl-dev build-essential
```

### Compilation

Assuming the patch is downloaded in the current directory, run the following commands:

```
wget ftp://ftp.freeradius.org/pub/freeradius/freeradius-server-2.2.9.tar.bz2
tar -xvf freeradius-server-2.2.9.tar.bz2
cd freeradius-server-2.2.9
patch -Np1 -i ../freeradius-server-2.2.8-2.2.9-wpe.patch
./configure
make
make install
ldconfig
```

### Create certificates

```
cd /usr/local/etc/raddb/certs
./bootstrap
```

## Running

Start ```radiusd``` in a terminal:

```
radiusd -s -X
```

Now, connect a client. Once a username/password is entered and the certificate accepted, information regarding that session will be stored in ```/usr/local/var/log/radius/freeradius-server-wpe.log```.

**Note**: This file won't be created until the first client connects and authenticate to the access point.
