import asyncio
import json
import websockets
import pymongo 
import os
import hashlib
import binascii 
import base64

#"UNIX-STYLE" hashed password 
async def hashPassword(password, salt=None, hash='sha256', iter=100000):
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

    async def fetchMessagesFromMailbox(self, connection):
        user_mailbox = self.db_client[f"mailbox#{connection.userid}"]
        device_mailbox = self.db_client[f"mailbox#{connection.userid}#{connection.deviceid}"]

        messages = []

        for message in user_mailbox.find():
            user_mailbox.delete_one({"_id" : message["_id"]})
            del message["_id"]
            messages.append(message)

        for message in device_mailbox.find():
            device_mailbox.delete_one({"_id" : message["_id"]})
            del message["_id"]
            messages.append(message)
        
        return {
            "type" : "fetch_messages",
            "data" : messages
        } 

    async def acceptedAddCorrespondents(self, data):
        self.db_user_collection.update_one({'userid' : data['to_userid']}, {'$push' : {'correspondents' : data['from_userid']}})
        self.db_user_collection.update_one({'userid' : data['from_userid']}, {'$push' : {'correspondents' : data['to_userid']}})


    async def getDevices(self, userid):
        return self.db_client[f'devices#{userid}'].find()

    async def getUserByUsername(self, username):
        return self.db_user_collection.find_one({"username": username})

    async def addDevice(self, userid, devicedata):
        collection_users_devices = self.db_client[f'devices#{userid}']
        next_deviceid = 1
        if collection_users_devices.find_one() != None:
            next_deviceid = collection_users_devices.find().sort([("userid", pymongo.DESCENDING)])[0]["deviceid"]
            next_deviceid += 1
        
        devicedata["deviceid"] = next_deviceid

        collection_users_devices.insert_one(
            devicedata
        )

        print(f'Added device with id {next_deviceid} for user with userid {userid}.')

        return next_deviceid

    async def addCorrespondent(self, data):
        from_user = await self.getUserByUsername(data["from_username"])
        to_user = await self.getUserByUsername(data["to_username"])
        if to_user == None or from_user == None:
            return {"type" : "add_correspondent_send_rejected"}
        data["to_userid"] = to_user["userid"]

        if to_user["userid"] in from_user["correspondents"]:
            return {"type" : "add_correspondent_send_rejected"}
        
        self.db_client[f'mailbox#{to_user["userid"]}'].insert_one(data)
        return {"type" : "add_correspondent_send_accepted"}

    async def handleSignUp(self,  data):
        if await self.getUserByUsername(data["username"]) != None:
            return {"type" : "signup_rejected"} 
        next_uid = 1
        if self.db_user_collection.find_one() != None:
            next_uid = self.db_user_collection.find().sort([("userid", pymongo.DESCENDING)])[0]["userid"]
            next_uid += 1 

        self.db_user_collection.insert_one({
            "userid" : next_uid,
            "username": data["username"],
            "password" : await hashPassword(data["password"]),
            "correspondents" : []
        })
        print(f'Added {data["username"]} with userid {next_uid}.')
        return {"type" : "signup_accepted"}

    async def handleLoginWithNoData(self, data, websocket):
        user_server_data = await self.getUserByUsername(data["username"]) 
        if user_server_data == None:
            return {"type" : "loginwithnodata_rejected"}

        user_server_password = user_server_data["password"]
        user_server_password = user_server_password.split('$')

        send_password_hashed = await hashPassword(data["password"], binascii.unhexlify(user_server_password[3]), user_server_password[1], int(user_server_password[2]))
        if send_password_hashed != user_server_data["password"]:
            return {"type" : "loginwithnodata_rejected"}
        
        new_deviceid =  await self.addDevice(user_server_data["userid"], data["data"]["current_device"])

        self.connections[websocket].userid = user_server_data["userid"] 
        self.connections[websocket].deviceid = new_deviceid

        return {"type": "loginwithnodata_accepted",
                "userid" : user_server_data["userid"],
                "deviceid" : new_deviceid,
                }

    async def handleLoginWithData(self, data, websocket):
        user_server_data = await self.getUserByUsername(data["username"]) 
        if user_server_data == None:
            return {"type" : "loginwithdata_rejected"}
        user_server_password = user_server_data["password"]
        user_server_password = user_server_password.split('$')

        send_password_hashed = await hashPassword(data["password"], binascii.unhexlify(user_server_password[3]), user_server_password[1], int(user_server_password[2]))
        if send_password_hashed != user_server_data["password"]:
            return {"type" : "loginwithdata_rejected"}
        
        if user_server_data["userid"] != data["userid"]:
            return {"type" : "loginwithdata_rejected"}

        found = False
        for device in await self.getDevices(user_server_data["userid"]):
            if device["deviceid"] == data["deviceid"]:
                found = True
                break
        if not found:
            return {"type" : "loginwithdata_rejected"}
        
        self.connections[websocket].userid = user_server_data["userid"]
        self.connections[websocket].deviceid = device["deviceid"]

        return {"type" : "loginwithdata_accepted"
               }        
        

    async def handleRequest(self, message, websocket):
        if message["type"] == "signup":
            return await self.handleSignUp(message["data"]) 
        elif message["type"] == "loginwithnodata":
            return await self.handleLoginWithNoData(message["data"], websocket) 
        elif message["type"] == "loginwithdata":
            return await self.handleLoginWithData(message["data"], websocket) 
        elif message["type"] == "add_correspondent":
            return await self.addCorrespondent(message["data"])
        elif message["type"] == "fetch_messages":
            return await self.fetchMessagesFromMailbox(self.connections[websocket])
        elif message["type"] == "add_correspondent_accepted":
            return await self.acceptedAddCorrespondents(message)

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
        self.connections[websocket] = Connection()
    

    def __init__(self, mongo_hostname="bruvchatdata", mongo_port=27017):
        #database connection 
        self.db_client = pymongo.MongoClient(f'mongodb://{mongo_hostname}:{mongo_port}')["bruvchat"]
        self.db_user_collection = self.db_client["users"]
        #connections
        self.connections = {}


if __name__ == "__main__":
    server = Server() 
    listen_server = websockets.serve(server.listen, "0.0.0.0", 9300)
    asyncio.get_event_loop().run_until_complete(listen_server)
    asyncio.get_event_loop().run_forever()
