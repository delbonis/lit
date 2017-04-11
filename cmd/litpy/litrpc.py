#!/usr/bin/python3


import websocket
import json
import sys
import requests


def mineblock():
	rpcCmd = {
			"method": "getinfo",
			"params": []
	}
	
	rpcCmd.update({"jsonrpc": "2.0", "id": "99"})
	
	rpcuser = "regtestuser"
	rpcpass = "regtestpass"
	rpcport = 18332
	serverURL = "http://" + rpcuser + ":" + rpcpass + "@127.0.0.1:" + str(rpcport)
	
	header = {"Content-type": "application/json"}
	payload = json.dumps(rpcCmd)
	print(payload)
	response = requests.post(serverURL, headers=header, data=payload)
	print(response.json())



def getaddress():
	rpcCmd = {
	   "method": "LitRPC.Address",
	   "params": [{"NumToMake": 0}]
	}

	rpcCmd.update({"jsonrpc": "2.0", "id": "94"})
	
	ws = websocket.WebSocket()
	ws.connect("ws://127.0.0.1:8001/ws")
	
	ws.send(json.dumps(rpcCmd))
	result = json.loads(ws.recv())
	
	result = ws.recv()
	#~ print("got a result")
	#~ print(result)
	print(result["result"]["WitAddresses"][2])
	
	rpc2 = {
	   "method": "LitRPC.Bal",
	   "params": []
	}
	rpc2.update({"jsonrpc": "2.0", "id": "92"})
	
	ws.send(json.dumps(rpc2))
	result = json.loads(ws.recv())
	print(result)
		

def main(args):
	mineblock()
	getaddress()

if __name__ == '__main__':
    main(sys.argv)
