import json
from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class NodeClient:
    def __init__(self, clientId, data, connectIDs):
        self.clientID = clientId
        self.data = data
        self.connections = connectIDs
        self.allSecrets = dict(zip(connectIDs, [None for i in range(len(connectIDs))]))

    # TODO: Post-Handshake Adjacent-Node/Connect-Node Check (in main)
    # Is overriden by receiveHandshake method for simplicity (helps with "in-transit" key issues)
    def createHandshake(self, endpt, secretLen=128):
        if(self.allSecrets[endpt] != None):
            return None
        
        # Data-Endpoint pair 1
        raw_data = get_random_bytes(secretLen)
        keyOne = self.clientID.encode()

        # Data-Endpoint pair 2
        resultOne = self.encryptAES(raw_data, keyOne)
        keyTwo = endpt.encode()

        # Store Key Data
        self.allSecrets[endpt] = raw_data

        # Second Encryption and Return
        finalResult = self.encryptAES(resultOne, keyTwo)
        return finalResult

    # TODO: "On-exit" key storage (plaintext is fine for now)
    # Overrides createHandshake method for simplicity (helps with "in-transit" key issues)
    def receiveHandshake(self, data, endpt):

        # First Decryption Layer
        keyOne = self.clientID.encode()
        decOne = self.decryptAES(data, keyOne)

        # Second Decryption Layer
        keyTwo = endpt.encode()
        plaintextKey = self.decryptAES(decOne, keyTwo)

        # Store Key
        self.allSecrets[endpt] = plaintextKey

    # Returns byte representation of array containing initialization vector and ciphertext
    def encryptAES(self, data, key):
        cipher = AES.new(key, AES.MODE_CBC)
        cipher = cipher.encrypt(pad(data, AES.block_size))
        init_vector = b64encode(cipher.iv).decode('utf-8')
        ciphertext = b64encode(cipher).decode('utf-8')
        return json.dumps([init_vector, ciphertext]).encode()

    def decryptAES(self, data, key):
        encrypted_data = json.loads(data.decode())
        init_vector = b64decode(encrypted_data[0])
        ciphertext = b64decode(encrypted_data[1])
        cipher = AES.new(key, AES.MODE_CBC, init_vector)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext

    def getID(self):
        return self.clientID
