from http.server import BaseHTTPRequestHandler, HTTPServer
import websockets
import asyncio
import json

ws_server = "ws://soc-player.soccer.htb:9091"

def send_ws(data):

    async def lets_talk():
        async with websockets.connect(ws_server) as ws:
            payload = json.dumps({"id": data})
            await ws.send(payload)
            msg = await ws.recv()
            if msg:
                # print(f"> {msg}")
                return f"> {msg}"

    try:
        msg = asyncio.get_event_loop().run_until_complete(lets_talk())
        return msg
    except websockets.exceptions.ConnectionClosed as e:
        # print(e)
        return 'ConnectionClosedError'

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path == '/forward':
            content_length = int(self.headers['Content-Length'])
            content_type = self.headers['Content-Type']

            # Parse the POST data as JSON
            if 'application/json' in content_type:
                post_data = json.loads(self.rfile.read(content_length))
            else:
                # Return error if content type is not JSON
                self.send_error(400, 'Invalid content type')
                return

            # Extract the 'payload' parameter from the JSON object
            mw_data = post_data.get('payload')
            ws_resp = send_ws(mw_data)

            # If debug flag is set, print out the submitted payload to the console
            if self.server.debug:
                print("< "+mw_data)  # Print data recieved on the middleware server
                print(ws_resp)  # Print response recieved from websocket server

            # Add logic based on the ws server to send a response back to the client

            if ws_resp:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(ws_resp.encode())
            else:
                self.send_response(500)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
            return

if __name__ == '__main__':
    httpd = HTTPServer(('127.0.0.1', 8080), SimpleHTTPRequestHandler)
    print("[+] Server started on 127.0.0.1:8080")
    httpd.debug = True
    httpd.serve_forever()
