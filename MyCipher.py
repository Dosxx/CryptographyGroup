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
            if type(plaintext) != bytes:
                # Convert to byte if not already a byte
                plaintext = str.encode(plaintext)
            cipher = AES.new(b64decode(key), AES.MODE_CBC)
            encrypted = cipher.encrypt(pad(plaintext, AES.block_size))
            ciphertext = b64encode(encrypted).decode('utf-8')
            result = (b64encode(cipher.iv).decode('utf-8'), ciphertext)
            return result
        except ValueError as error:
            if error.args[0] == "Incorrect padding":
                error = "Wong Key Length"
                return error

    def decryptAES_128(self, key, iv, ciphertext):
        try:
            ciphertext = b64decode(ciphertext)
            cipher = AES.new(b64decode(key), AES.MODE_CBC, b64decode(iv))
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
            return plaintext
        except ValueError as error:
            if error.args[0] == "Incorrect padding":
                error = "Wrong key or IV provided"
                return error
            elif error.args[0] == "utf-8":
                error = "Incorrect Encoding"
                return error

    def keygen(self):
        # Generate a random 16-bytes (128-bits)key and return it to the caller
        keyString = b64encode(get_random_bytes(16)).decode('utf-8')
        return keyString


################### Test codes ###############################
# c = MyCipher()
# myKey = c.keygen()
# print(myKey)
# with open("Linux.png", 'r+b') as fd:
#     content = fd.read()
#     # print("Bytes Read: ", content[0:4])
#     # print(b64decode(content))
#     encrypt = c.encryptAES_image(content, myKey)
#     # print(encrypt[1][0:10])
# ptext = c.decryptAES_image(myKey, encrypt[0], encrypt[1])
# print(ptext)
