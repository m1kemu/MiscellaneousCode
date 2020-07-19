package main

import (
  "io/ioutil"
  "fmt"
  "os"
  "encoding/base64"
)

func EncryptXOR(plaintext, key []byte) []byte {
  ciphertext := make([]byte, len(plaintext))
  for i := 0; i < len(plaintext); i++ {
    ciphertext[i] = plaintext[i] ^ key[i % len(key)]
  }

  return ciphertext
}

func main() {
  args := os.Args
  sc_file := args[1]
  key := args[2]

  fmt.Println("\n[!] XOR Encryption")

  sc, _ := ioutil.ReadFile(sc_file)
  fmt.Println("[*] Shellcode bytes:", sc)
  fmt.Println("[*] Key:", key)

  ciphertext := EncryptXOR([]byte(sc), []byte(key))
  fmt.Println("[*] Ciphertext:", ciphertext)

  ciphertext_b64 := base64.StdEncoding.EncodeToString([]byte(ciphertext))

  fmt.Println("[+] Final message:", ciphertext_b64)

  ciphertext, _ = base64.StdEncoding.DecodeString(ciphertext_b64)
  fmt.Println("[*] Message decoded:", ciphertext)
  plaintext := EncryptXOR(ciphertext, []byte(key))
  fmt.Println("[+] Decrypted:", plaintext)

}
