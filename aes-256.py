import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]


class AESCipher(object):
    # cipher with blocks of 16 bytes using UTF-8 characters
    def __init__(self, key): 
        self.blocksize = 16
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, plaintext):
        plaintext = pad(plaintext)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(plaintext))

    def decrypt(self, ciphertext):
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext[AES.block_size:])).decode('utf-8')
