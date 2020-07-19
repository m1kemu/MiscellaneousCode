package main

import (
        "fmt"
        "net/http"
        "io/ioutil"
)

func main() {
        url := "https://gist.githubusercontent.com/m1kemu/ad1a7b87fb1b82e45ec63d63964d9473/raw/c4aaafe195ef7dc969edf0f53f34f4572bfc0e79/download_me_go.txt"
        user_agent := "Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36"

        req, _ := http.NewRequest("GET", url, nil)
        req.Header.Set("User-Agent", user_agent)
        client := &http.Client{}
        resp, _ := client.Do(req)

        defer resp.Body.Close()

        content, _ := ioutil.ReadAll(resp.Body)

        fmt.Println(string(content))
}
