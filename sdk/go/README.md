# authv4 (Go)

Authris license client for Go 1.21+. Standard library only —
zero dependencies.

```sh
go get github.com/V12KLT/authris-sdk/sdk/go/v4
```

```go
package main

import (
	"fmt"
	"time"

	authv4 "github.com/V12KLT/authris-sdk/sdk/go/v4"
)

func main() {
	app := authv4.NewClient("PASTE_PROJECT_ID", "https://your-server", "", "")
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
```

Full guide: [sdk/INTEGRATION.md](../INTEGRATION.md).
