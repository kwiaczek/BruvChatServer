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
    async def getDevices(self, userid):
        devices = []
        for device in  self.db_client[f'devices#{userid}'].find():
            del device["_id"]
            devices.append(device)
        return devices

    async def getUserByUserID(self, userid):
        return self.db_client["users"].find_one({"userid": userid})

    async def getUserByUsername(self, username):
        return self.db_client["users"].find_one({"username": username})

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

    async def handleSignUp(self,  data):
        if await self.getUserByUsername(data["username"]) != None:
            return {"type" : "signup_rejected"} 
        next_uid = 1
        if self.db_client["users"].find_one() != None:
            next_uid = self.db_client["users"].find().sort([("userid", pymongo.DESCENDING)])[0]["userid"]
            next_uid += 1 

        self.db_client["users"].insert_one({
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

        return {"type" : "loginwithdata_accepted"}        

    async def fetchMessages(self, connection):
        messages = []
        user_mailbox = self.db_client[f'mailbox#{connection.userid}']
        #general meaning meant for every device 
        for general_messsage in user_mailbox.find():
            user_mailbox.delete_one({"_id" : general_messsage["_id"]})
            del general_messsage["_id"]
            messages.append(general_messsage)
        user_device_mailbox = self.db_client[f'mailbox#{connection.userid}#{connection.deviceid}']
        #device meaning meant for this particular device 
        for device_messsage in user_device_mailbox.find():
            user_device_mailbox.delete_one({"_id" : device_messsage["_id"]})
            del device_messsage["_id"]
            messages.append(device_messsage)
        return messages

    async def fetchCorrespondents(self, connection):
        user = await self.getUserByUserID(connection.userid)
        correspondents = []
        for correspondent_id in user["correspondents"]:
            correspondent = await self.getUserByUserID(correspondent_id)
            del correspondent["_id"]
            del correspondent["password"]
            del correspondent["correspondents"]
            correspondent["devices"] = await self.getDevices(correspondent_id)
            correspondents.append(correspondent) 
        return correspondents
    
    async def notifyOutdated(self, userid):
        notify_outdate_msg = {
            "type" : "outdated"
        }

        for socket, connection in self.connections.items():
            if connection.userid == userid:
                await socket.send(json.dumps(notify_outdate_msg))

    async def handleRequestUpdate(self, websocket):
        messages = await self.fetchMessages(self.connections[websocket])
        correspondents = await self.fetchCorrespondents(self.connections[websocket])
        return {
                "type" : "request_update",
                "messages": messages,
                "correspondents" : correspondents
        }
    async def handleAddCorrespondentRequest(self, data, websocket):
        to_user = await self.getUserByUsername(data["to_username"])
        if to_user == None:
            return {"type" : "add_correspondent_request_rejected"}
        data["to_userid"] = to_user["userid"]
        self.db_client[f'mailbox#{to_user["userid"]}'].insert_one(data)        
        await self.notifyOutdated(data["to_userid"])
        return {"type" : "add_correspondent_request_accept"}
    
    async def handleAcceptCorrespondentRequest(self, data):
        self.db_client["users"].update_one({'userid' : data['to_userid']}, {'$push' : {'correspondents' : data['from_userid']}})
        self.db_client["users"].update_one({'userid' : data['from_userid']}, {'$push' : {'correspondents' : data['to_userid']}})
        await self.notifyOutdated(data["to_userid"])
        await self.notifyOutdated(data["from_userid"])
        return {"type" : "accept_correspondent_request_accepted"}

    async def handleSendMessage(self, messages):
        sender_userid = 0
        sender_deviceid = 0
        receiver_deviceid = 0
        receiver_userid = 0
        for message in messages:
            print(message.keys())
            print(message)


            receiver_userid = message["receiver_userid"]
            sender_userid = message["sender_userid"]
            receiver_deviceid = message["device"]["receiver_deviceid"]
            sender_deviceid = message["device"]["sender_deviceid"]

            print(receiver_userid)
            print(receiver_deviceid)
            print(sender_userid)
            print(sender_deviceid)

            if message["encrypted_type"] == "internal":
                print("internal")
                self.db_client[f'mailbox#{sender_userid}#{receiver_deviceid}'].insert_one(message)
            elif message["encrypted_type"] == "external":
                print("internal")
                self.db_client[f'mailbox#{receiver_userid}#{receiver_deviceid}'].insert_one(message)
        await self.notifyOutdated(receiver_userid)
        await self.notifyOutdated(sender_userid)
        return {"type" : "send_message_accepted"}


    async def handleRequest(self, message, websocket):
        if message["type"] == "signup":
            return await self.handleSignUp(message["data"]) 
        elif message["type"] == "loginwithnodata":
            return await self.handleLoginWithNoData(message["data"], websocket) 
        elif message["type"] == "loginwithdata":
            return await self.handleLoginWithData(message["data"], websocket) 
        elif message["type"] == "request_update":
            return await self.handleRequestUpdate(websocket) 
        elif message["type"] == "add_correspondent_request":
            return await self.handleAddCorrespondentRequest(message["data"], websocket) 
        elif message["type"] == "accept_correspondent_request":
            return await self.handleAcceptCorrespondentRequest(message) 
        elif message["type"] == "send_message":
            return await self.handleSendMessage(message["data"])

    async def listen(self, websocket, path):
        await self.register(websocket)
        try:
            async for message in websocket:
                await websocket.send(json.dumps(await self.handleRequest(json.loads(message), websocket)))
        finally:
            await self.unregister(websocket)

    #functions for managing connections
    async def unregister(self, websocket):
        del self.connections[websocket]
    async def register(self, websocket):
        self.connections[websocket] = Connection()
    

    def __init__(self, mongo_hostname="bruvchatdata", mongo_port=27017):
        #database connection 
        self.db_client = pymongo.MongoClient(f'mongodb://{mongo_hostname}:{mongo_port}')["bruvchat"]
        #connections
        self.connections = {}


if __name__ == "__main__":
    server = Server() 
    listen_server = websockets.serve(server.listen, "0.0.0.0", 9300)
    asyncio.get_event_loop().run_until_complete(listen_server)
    asyncio.get_event_loop().run_forever()
