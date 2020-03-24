# ICS483 Group Project
# Authors: Kekeli D Akouete, Vang Uni A
# Implementing encryption in an application

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# noinspection PyMethodMayBeStatic
class MyCipher:
    def encryptAES_128(self, plaintext, key):
        try:
            plaintext = str.encode(plaintext)
            cipher = AES.new(b64decode(key), AES.MODE_CBC)
            encrypted = cipher.encrypt(pad(plaintext, AES.block_size))
            ciphertext = b64encode(encrypted).decode('utf-8')
            result = (b64encode(cipher.iv).decode('utf-8'), ciphertext)
            return result
        except ValueError as error:
            error = "Something went wrong try again!"
            return error

    def decryptAES_128(self, key, iv, ciphertext):
        try:
            ciphertext = b64decode(ciphertext)
            cipher = AES.new(b64decode(key), AES.MODE_CBC, b64decode(iv))
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
            return plaintext
        except ValueError as error:
            error = "Wrong key or IV provided"
            return error

    def keygen(self):
        # Generate a random 16-bytes (128-bits)key and return it to the caller
        keyString = b64encode(get_random_bytes(16)).decode('utf-8')
        return keyString


################### Test codes ###############################
# c = MyCipher()
# myKey = c.keygen()
# print(myKey.hex().upper())
# with open("test.txt", 'r') as fd:
#     content = fd.read()
#     encrypt = c.encryptAES_128(content, myKey)
# ptext = c.decryptAES_128(myKey, encrypt[0], encrypt[1])
# print(ptext)
