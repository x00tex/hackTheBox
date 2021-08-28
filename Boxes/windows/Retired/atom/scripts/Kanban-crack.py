import base64
from des import * #python3 -m pip install des

def decode(hash):
	hash = base64.b64decode(hash.encode('utf-8'))
	key = DesKey(b"7ly6UznJ")
	return key.decrypt(hash,initial=b"XuVUm5fR",padding=True).decode('utf-8')

print(decode("Odh7N3L9aVQ8/srdZgG2hIR0SSJoJKGi"))