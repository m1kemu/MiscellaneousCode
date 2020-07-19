package main

import (
  "io/ioutil"
  "fmt"
  "strings"
  "os"
  "crypto/aes"
  "crypto/cipher"
  "encoding/base64"
  "time"
  "math/rand"
)

// https://www.calhoun.io/creating-random-strings-in-go/
const charset = "abcdefghijklmnopqrstuvwxyz0123456789"

var seeded *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func StringWithCharset(length int, charset string) string {
  b := make([]byte, length)
  for i := range b {
    b[i] = charset[seeded.Intn(len(charset))]
  }
  return string(b)
}

func EncryptAES(ciphertext, plaintext, key, iv []byte) {
  aesBlockEncrypter, _ := aes.NewCipher([]byte(key))
  aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, iv)
  aesEncrypter.XORKeyStream(ciphertext, plaintext)
}

func DecryptAES(plaintext, ciphertext, key, iv []byte) {
  aesBlockDecrypter, _ := aes.NewCipher([]byte(key))
  aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, iv)
  aesDecrypter.XORKeyStream(plaintext, ciphertext)
}

func main() {
  args := os.Args
  sc_file := args[1]
  key := args[2]

  iv_str := StringWithCharset(16, charset)
  iv := []byte(iv_str)[:aes.BlockSize]

  fmt.Println("[!] AES Encryption")

  sc, _ := ioutil.ReadFile(sc_file)
  fmt.Println("[*] Shellcode bytes:", sc)
  fmt.Println("[*] Key:", key)
  fmt.Println("[*] IV:", iv)

  ciphertext := make([]byte, len(sc))
  EncryptAES(ciphertext, []byte(sc), []byte(key), iv)
  fmt.Println("[+] Ciphertext:", ciphertext)

  ciphertext_b64 := base64.StdEncoding.EncodeToString([]byte(ciphertext))
  iv_b64 := base64.StdEncoding.EncodeToString([]byte(iv))

  s := []string{ciphertext_b64, iv_b64}
  msg := strings.Join(s, "::")
  fmt.Println("[+] Final message:", msg)

  msg_b64_split := strings.Split(msg, "::")
  ciphertext_b64 = msg_b64_split[0]
  iv_b64 = msg_b64_split[1]
  fmt.Println("[*] Ciphertext base64:", ciphertext_b64)
  fmt.Println("[*] IV base64:", iv_b64)

  ciphertext, _ = base64.StdEncoding.DecodeString(ciphertext_b64)
  iv, _ = base64.StdEncoding.DecodeString(iv_b64)
  fmt.Println("[*] Ciphertext bytes:", ciphertext)
  fmt.Println("[*] IV bytes:", iv)

  plaintext := make([]byte, len(ciphertext))
  DecryptAES(plaintext, ciphertext, []byte(key), iv)
  fmt.Println("[+] Decrypted:", plaintext)
}
