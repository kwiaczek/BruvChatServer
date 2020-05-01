import asyncio
import json
import websockets
import pymongo 
import os
import hashlib
import binascii 
import base64

#"UNIX-STYLE" hashed password 
def hashPassword(password, salt=None, hash='sha256', iter=100000):
    if salt == None:
        salt = os.urandom(16)
    res = hashlib.pbkdf2_hmac(hash, bytes(password, "ascii"), salt, iter) 
    res = f'PBKDF2_HMAC${hash}${iter}${binascii.hexlify(salt).decode("ascii")}${res.hex()}'
    return res

class Connection: 
    def __init__(self, userid=-1, deviceid=-1):
        self.userid = userid
        self.deviceid = deviceid

class Server:
    async def getUserByUsername(self, username):
        return self.db_user_collection.find_one({"username": username})

    async def handleSignUp(self,  data):
        if await self.getUserByUsername(data["username"]) != None:
            return {"type" : "signup_rejected"} 
        next_uid = 1
        print(self.db_user_collection.find_one())
        if self.db_user_collection.find_one() != None:
            next_uid = self.db_user_collection.find().sort([("userid", pymongo.DESCENDING)])[0]["userid"]
            next_uid += 1 

        self.db_user_collection.insert_one({
            "userid" : next_uid,
            "username": data["username"],
            "password" : hashPassword(data["password"]),
            "correspondents" : []
        })
        print(f'Added {data["username"]} with userid {next_uid}.')
        return {"type" : "signup_accepted"}

    async def handleRequest(self, message, websocket):
        if message["type"] == "signup":
            return await self.handleSignUp(message["data"]) 

    async def listen(self, websocket, path):
        await self.register(websocket)
        try:
            async for message in websocket:
                await websocket.send(json.dumps(await self.handleRequest(json.loads(message), websocket)))
        finally:
            await self.unregister(websocket)

    async def unregister(self, websocket):
        del self.connections[websocket]

    async def register(self, websocket):
        self.connections = Connection()

    def __init__(self, mongo_hostname="bruvchatdata", mongo_port=27017):
        #database connection 
        self.db_client = pymongo.MongoClient(f'mongodb://{mongo_hostname}:{mongo_port}')
        self.db_user_collection = self.db_client["bruvchat"]["users"]
        self.db_devices_collection = self.db_client["bruvchat"]["devices"]
        #connections
        self.connections = {}


if __name__ == "__main__":
    server = Server() 
    listen_server = websockets.serve(server.listen, "0.0.0.0", 9300)
    asyncio.get_event_loop().run_until_complete(listen_server)
    asyncio.get_event_loop().run_forever()
