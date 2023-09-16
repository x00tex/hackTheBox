import websockets
import asyncio
import json
import sys

url = "ws://ws.qreader.htb:5789/version"

async def lets_talk():
    async with websockets.connect(url) as ws:
        payload = json.dumps({"version": sys.argv[1]})
        await ws.send(payload)
        msg = await ws.recv()
        print(f"> {msg}")


if __name__ == "__main__":
    try:
        asyncio.get_event_loop().run_until_complete(lets_talk())
    except KeyboardInterrupt:
        print(' KeyboardInterrupt')
    except websockets.exceptions.ConnectionClosed as e:
        print(e)