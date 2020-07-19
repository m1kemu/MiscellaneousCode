package main

import (
        "fmt"
        "context"
        "net"
        "time"
        "strings"
)

func main() {
        domain := "example.com"

        r := &net.Resolver{
                PreferGo: true,
                Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
                        d := net.Dialer {
                                Timeout: time.Millisecond * time.Duration(10000),
                        }
                        return d.DialContext(ctx, "udp", "127.0.0.1:5053")
                },
        }

        txt_records, _ := r.LookupTXT(context.Background(), domain)
        fmt.Println("[+] TXT Record Data:", txt_records)

        msg_b64 := txt_records[0]
        msg_b64_split := strings.Split(msg_b64, "::")

        ciphertext_b64 := msg_b64_split[0]
        iv_b64 := msg_b64_split[1]

        fmt.Println("[+] Ciphertext:", ciphertext_b64)
        fmt.Println("[+] IV :", iv_b64)
}
