from Crypto.Cipher import AES
from crccheck.crc import Crc16X25 #pip install crccheck
from pwn import *
from python_modhex.python_modhex import from_modhex, to_modhex #pip install python-modhex

key = unhex("6bf9a26475388ce998988b67eaa2ea87")
kid = unhex("a4ce1128bde4")

#struct: uid + counter + timestamp_L + timestamp_H + session_use + random + crc
struct = kid + b'\xf1\xff' + b'\xff\xff' + b'\xff' + b'\xff' + b'\xff\xff'
struct += p16(Crc16X25.calc([_ for _ in struct]))

aes = AES.new(key, AES.MODE_ECB)

print("Token: " + to_modhex(enhex(aes.encrypt(struct))))