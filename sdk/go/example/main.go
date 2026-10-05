package main

import (
	"fmt"
	"time"

	authv4 "github.com/V12KLT/authris-sdk/sdk/go/v4"
)

func main() {
	app := authv4.NewClient("PASTE_PROJECT_ID", "http://127.0.0.1:8080", "", "")
	if err := app.Init(); err != nil {
		fmt.Println("auth failed:", err)
		return
	}
	if _, err := app.License("XXXX-XXXX-XXXX-XXXX", ""); err != nil {
		fmt.Println("auth failed:", err)
		return
	}
	fmt.Println("licensed, remaining:", app.Remaining)
	for {
		time.Sleep(60 * time.Second)
		remaining, err := app.Heartbeat()
		if err != nil {
			fmt.Println("heartbeat failed:", err)
			return
		}
		fmt.Println("heartbeat, remaining:", remaining)
	}
}
