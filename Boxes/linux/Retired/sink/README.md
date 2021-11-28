![](sink_banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="https://www.hackthebox.eu/badge/image/391067"></a>
</p>

# Enumeration

**IP-ADDR:** 10.10.10.225 sink.htb

**nmap scan:**
```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gitea=b06d007546b891b1; Path=/; HttpOnly
|     Set-Cookie: _csrf=g8iWus6Yg0Gy4q5O_dzZHqGWHTM6MTYyODczODc4MTA2ODg3ODgzMQ; Path=/; Expires=Fri, 13 Aug 2021 03:26:21 GMT; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 12 Aug 2021 03:26:21 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-">
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title> Gitea: Git with a cup of tea </title>
|     <link rel="manifest" href="/manifest.json" crossorigin="use-credentials">
|     <meta name="theme-color" content="#6cc644">
|     <meta name="author" content="Gitea - Git with a cup of tea" />
|     <meta name="description" content="Gitea (Git with a cup of tea) is a painless
5000/tcp open  http    Gunicorn 20.0.0
|_http-server-header: gunicorn/20.0.0
|_http-title: Sink Devops
```

* Port 3000 is running "gitea", Identified from fingerprint-strings.
* Port 5000 is running "gunicorn/20.0.0" server.
* Gitea running Version: 1.12.6
* There is no signup option in gitea.
* Only interesting thing found is, user "root" contributions but can not see them

  ![](screenshots/root-contributions.png)

*Final thing before diving is that "gunicorn" is a python http server and it cannot handle brute forcing or fuzzing.*

Port 5000 gunicorn is server running a static webapp and have login and signup option

![](screenshots/gunicorn-server.png)

Found `haproxy` is running from response header when doing sign. Also get a session cookie which is a flash auth token.

![](screenshots/sign-rspn-header.png)

we can verify cookie with [`flask-unsign`](https://github.com/Paradoxis/Flask-Unsign)
```bash
❯ flask-unsign --decode --cookie 'eyJlbWFpbCI6Int7Nyo3fX1AdGVzdC5jb20ifQ.YSyjmQ.1l4PRcj8FZl60I98PFQkHpyaF-E'
{'email': '{{7*7}}@test.com'}
```

From google search for "haproxy" for something that already known and found 

![](screenshots/google-haroxy-search.png)


### Guessing haproxy version

There is HTTP Request Smuggling Vulnerability in haproxy package, versions <1.8.19-1+deb10u3; **Source** [snyk Vulnerability DB](https://snyk.io/vuln/SNYK-DEBIAN10-HAPROXY-474258)

Vulnerability resolve in Debian:10 haproxy to version 1.8.19-1+deb10u3 or higher.

The way i verify that this Vulnerability present in this box is,

From Port 22 version header "OpenSSH 8.2p1 Ubuntu 4ubuntu0.1", Running host version is possibly "**Focal**" and update date **2020-06-08**; **Source** [launchpad](https://launchpad.net/ubuntu/+source/openssh/1:8.2p1-4ubuntu0.1)

And Vulnerability resolve on **2020-09-26** update. **Source** [launchpad](https://launchpad.net/debian/+source/haproxy/1.8.19-1+deb10u3)


**Or, Just send a bad request to server and it will return the version number**

![](screenshots/haproxy-version.png)

Server is running version 1.9.10 and http smuggling Vulnerability found in HAProxy before 2.0.6.

# Foothold

## http Request Smuggling

"When malformed or abnormal HTTP requests are interpreted by one or more entities in the data flow between the user and the web server, such as a proxy or firewall, they can be interpreted inconsistently, allowing the attacker to "smuggle" a request to one device without the other device being aware of it."

**Important terms**

* **`transfer-encoding`:** The Transfer-Encoding header specifies the form of encoding used to safely transfer the payload body to the user; **Source** [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding)
* "chunked" value specifications.
  * With `chunked` value Enable, Data is sent in a series of chunks. 
  * The Content-Length header is omitted.
  * At the beginning of each chunk(data) you need to add the length of the current chunk in hexadecimal format, followed by '`\r\n`' and then the chunk itself, followed by another '`\r\n`'.
  * The terminating chunk is a regular chunk, with the exception that its length is zero and formated same as regular data chunks.
* [RFC2616](https://datatracker.ietf.org/doc/html/rfc2616#section-4.4)

**Resources for learning/understanding**

* Video: [Hiding Wookiees in HTTP: HTTP smuggling](https://www.youtube.com/watch?v=dVU9i5PsMPY) by [@regilero](https://twitter.com/regilero)
* Video: [Practical Attacks Using HTTP Request Smuggling](https://www.youtube.com/watch?v=3tpnuzFLU8g) by [@defparam](https://twitter.com/defparam?lang=en)
* Video: HTTP Desync Attacks: Smashing into the Cell Next Door by [@albinowax](https://twitter.com/albinowax)
  * owasp: https://www.youtube.com/watch?v=upEMlJeU_Ik
  * defcon: https://www.youtube.com/watch?v=w-eJM2Pc0KI
  * blackhat: https://www.youtube.com/watch?v=kgkRih2MQtU
  * blackhat: https://www.youtube.com/watch?v=_A04msdplXs
* Research: [request-smuggling](https://portswigger.net/research/request-smuggling) from portswigger 
* Blog: [Protocol Layer Attack - HTTP Request Smuggling](https://paper.seebug.org/1049/)

**Tools**

* [smuggler](https://github.com/defparam/smuggler) by [defparam](https://github.com/defparam)

### Exploit CL.TE

**CL.TE:** the front-end server uses the `Content-Length` header and the back-end server uses the `Transfer-Encoding` header.

**[hacktricks source](https://book.hacktricks.xyz/pentesting-web/http-request-smuggling) that found from google search.**

**CVE identifier:** [CVE-2019-18277](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-18277)

**Vulnerability Description:** "A flaw was found in HAProxy before 2.0.6. In legacy mode, messages featuring a transfer-encoding header missing the "chunked" value were not being correctly rejected. The impact was limited but if combined with the "http-reuse always" setting, it could be used to help construct an HTTP request smuggling attack against a vulnerable component employing a lenient parser that would ignore the content-length header as soon as it saw a transfer-encoding one (even if not entirely valid according to the specification)."

**And here is the [haproxy Vulnerability PoC](https://gist.github.com/ndavison/4c69a2c164b2125cd6685b7d5a3c135b) by [ndavison](https://github.com/ndavison)**


When `Transfer-Encoding` and `Content-Length` is provided together, The request HAProxy sends to the backend has correctly prioritized `Transfer-Encoding`, and has stripped out the `content-length` and cut off everything, which went outside the boundry of the `Transfer-Encoding` request (Anything after `0`).

However, if we have a `\x0b` (vertical tab) before the "chunked" string (note: `\x0c` aka form feed also works).

In this case, the `Transfer-Encoding` is not detected by HAProxy, and so the `Content-Length` is used. However, because the `Transfer-Encoding` remains in the request sent to the backend, it means that if a backend server manages to parse the `Transfer-Encoding` header and proceeds to treat the request as a TE encoded request, a desync could occur and the backend TCP socket could be poisoned. This could then lead to HTTP request smuggling.

So if the backend server allowed `Transfer-Encoding` then backend server give priority to `Transfer-Encoding` header and terminate request at terminating chunk `0` and anything after that treated as second request.
* If not worked then use connection as `keep-alive`

![](screenshots/haproxy-http-smuggling.png)

And you can add `0b` byte before `chunked` string from hex tab in repeater window and with `\n` switch in repeater window you can see non-printable chars

![](screenshots/add-hex-0b.png)

If everything goes well, our comment contians admin session cookie

![](screenshots/admin-cookie.png)

Got admin cookie because while backend server waiting to complete 300 bytes of data of our request while frontend server forward another user's request to backend and this request concatenate to our request to complete 300 bytes. 

And replacing sessoin cookie with admin cookie ge to the admin panel

![](screenshots/edit-cookie.png)

From admin's `/notes` found 3 notes with creds and subdomains
```
Chef Login : http://chef.sink.htb Username : chefadm Password : /6'fEGC&zEx{4]zz 
```
```
Dev Node URL : http://code.sink.htb Username : root Password : FaH@3L>Z3})zzfQ3 
```
```
Nagios URL : https://nagios.sink.htb Username : nagios_adm Password : g8<H6GK\{*L.fB3C 
```

First i tried to login to gitea server because there is a user named "root" who has some contributions

With `root:FaH@3L>Z3})zzfQ3` creds logged in successfully and found some repositories

![](screenshots/root-repos.png)

__Some interesting Information collected from these repositories:__

* Got ssh key for user "marcus" from http://10.10.10.225:3000/root/Key_Management/commit/b01a6b7ed372d154ed0bc43a342a5e1203d07b1e commit in root's "Key_Management" repository.

  ![](screenshots/user-ssh-key.png)

* Found some aws secret from http://10.10.10.225:3000/root/Log_Management/commit/e8d68917f2570f3695030d0ded25dc95738fb1ba commit in root's "Log_Management" repository.
  <!-- 
  'key' => 'AKIAIUEN3QWCPSTEITJQ',
	'secret' => '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'
  -->

  ![](screenshots/aws-secret.png)

# Privesc

* Get shell as user marcus and there is a another use name "david".

There are multiple [containerd](https://containerd.io/) container (total 16) running same web server application.

![](screenshots/container-servers.png)

This application is same, where we exploit http request smuggling in foothold.

![](screenshots/container-web-app.png)

* Every container of this application is runnning some services that doing there parts(guessing)

  ![](screenshots/container-process.png)

  * Running `/usr/local/bin/gunicorn` server.
  * Running `/home/haproxy/haproxy` server.
  * Executing `/home/bot/bot.py` which give us admin token from http smuggling attack.
  * Running `/usr/bin/fail2ban-server` to prevent brute-force on web server.

There are some local services running 

![](screenshots/local-services.png)

Port `4566` is by defaut used by [localstack](https://github.com/localstack/localstack)

localstack running from a container on `172.18.0.2`.

* [localstack](https://localstack.cloud/) provides an easy-to-use test/mocking framework for developing Cloud applications. It spins up a testing environment on your local machine that provides the same functionality and APIs as the real AWS cloud environment.
* `awscli` already installed in the box.

There is a local aws instance is running and awscli already installed in the box and we found aws secret from gitea.

## AWS secretsmanager

Configure awscli to access localstack instance by running `aws configure`

![](screenshots/aws-configure.png)

Get access to aws [secretsmanager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html), aws secrets manager stores credentials.
```bash
aws --endpoint-url="http://127.0.0.1:4566/" secretsmanager list-secrets
```

![](screenshots/aws-secretlist.png)

There are 3 secret IDs(ARN), we  can retrive there secret string with; **Source** [aws docs](https://docs.aws.amazon.com/secretsmanager/latest/userguide/tutorials_basic.html)
```bash
aws --endpoint-url="http://127.0.0.1:4566/" secretsmanager get-secret-value --secret-id <ARN>
```

and get david password from `"arn:aws:secretsmanager:us-east-1:1234567890:secret:Jira Support-LtCKQ"`

![](screenshots/david-password.png)
<!--david:EALB=bcC=`a7f2#k-->

There is a encrypted file in david home folder

![](screenshots/enc-file.png)

## AWS kms decrypt

From [aws kms docs](https://docs.aws.amazon.com/cli/latest/reference/kms/index.html) found some kms command that are useful.

`decrypt`: Decrypts ciphertext that was encrypted by a KMS key.

`enable-key`: Sets the key state of a KMS key to enabled. This allows you to use the KMS key for cryptographic operations.

`list-keys` : Gets a list of all KMS keys in the caller's Amazon Web Services account and Region.

`describe-key`: Provides detailed information about a KMS key.

Get kms key from aws server
```bash
aws --endpoint-url="http://127.0.0.1:4566/" kms list-keys
```

![](screenshots/awskms-keys.png)

Now to can decrypt that file with decrypt command
```bash
aws --endpoint-url="http://127.0.0.1:4566/" kms decrypt \
    --ciphertext-blob fileb:///home/david/Projects/Prod_Deployment/servers.enc \
    --key-id <KeyId> \
    --output text \
    --query Plaintext | base64
```

but when run this command, get key is disabled error.

![](screenshots/key-disabled.png)

First we need to enable all key with
```bash
aws --endpoint-url="http://127.0.0.1:4566/" kms enable-key --key-id <KeyId>
```

Second, This file is not encrypted with default encryption algorithm. We can check this by describing 'KeyArn" 
```bash
aws --endpoint-url="http://127.0.0.1:4566/" kms describe-key --key-id "<KeyArn>"
```

![](screenshots/enc-algo.png)

Final decryption script
```bash
keys=$(aws --endpoint-url="http://127.0.0.1:4566/" kms list-keys | grep KeyId | cut -d'"' -f4)

for key in $keys;
do
	aws --endpoint-url="http://127.0.0.1:4566/" kms enable-key --key-id "$key"
	aws --endpoint-url="http://127.0.0.1:4566/" kms decrypt \
	    --ciphertext-blob fileb:///home/david/Projects/Prod_Deployment/servers.enc \
	    --encryption-algorithm "RSAES_OAEP_SHA_256" \
	    --key-id "$key" \
	    --output text \
	    --query Plaintext | base64
done
```

And file decrypted with `804125db-bdf1-465a-a058-07fc87c0fad0`
```bash
aws --endpoint-url="http://127.0.0.1:4566/" kms decrypt \
    --ciphertext-blob fileb:///home/david/Projects/Prod_Deployment/servers.enc \
    --encryption-algorithm "RSAES_OAEP_SHA_256" \
    --key-id 804125db-bdf1-465a-a058-07fc87c0fad0 \
    --output text \
    --query Plaintext | base64 \
    --decode > decrypted-file
```

![](screenshots/file-decrypted.png)

Got an admin password which worked for root user.
<!--_uezduQ!EY5AHfe2-->