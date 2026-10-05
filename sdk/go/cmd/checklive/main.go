package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	authv4 "github.com/V12KLT/authris-sdk/sdk/go/v4"
)

func check(name string, condition bool) {
	if condition {
		fmt.Println("PASS " + name)
	} else {
		fmt.Println("FAIL " + name)
		os.Exit(1)
	}
}

func main() {
	base := os.Getenv("AUTHV4_BASE")
	pid := os.Getenv("AUTHV4_PID")
	key := os.Getenv("AUTHV4_KEY")
	key2 := os.Getenv("AUTHV4_KEY2")
	hwid := os.Getenv("AUTHV4_HWID")

	app := authv4.NewClient(pid, base, "", "")
	if err := app.Init(); err != nil {
		fmt.Println("init error:", err)
		os.Exit(1)
	}
	check("init", app.ServerKey != "")
	licensed, err := app.License(key, hwid)
	if err != nil {
		fmt.Println("license error:", err)
		os.Exit(1)
	}
	check("license", licensed.Remaining > 80000)
	beat, err := app.Heartbeat()
	if err != nil {
		fmt.Println("heartbeat error:", err)
		os.Exit(1)
	}
	check("heartbeat", beat > 80000)
	info, err := app.Info()
	if err != nil {
		fmt.Println("info error:", err)
		os.Exit(1)
	}
	check("info", info.Status == "active")
	value, err := app.Variable("offset")
	if err != nil {
		fmt.Println("variable error:", err)
		os.Exit(1)
	}
	check("variable", value == "0x10")
	vars, err := app.Variables()
	if err != nil {
		fmt.Println("variables error:", err)
		os.Exit(1)
	}
	check("variables", vars["offset"] == "0x10")
	blob, err := app.File("app.bin")
	if err != nil {
		fmt.Println("file error:", err)
		os.Exit(1)
	}
	check("file", bytes.Equal(blob, []byte("sdk-file-secret-bytes")))
	hooked, err := app.Webhook("orders", "ping")
	if err != nil {
		fmt.Println("webhook error:", err)
		os.Exit(1)
	}
	check("webhook", hooked.Status == 200)
	added, err := app.Table("config", "add_row", 0, map[string]any{"offset": "0x20", "label": "go"}, 100)
	if err != nil {
		fmt.Println("table add error:", err)
		os.Exit(1)
	}
	check("table add", added.OK)
	rows, err := app.Table("config", "get_rows", 0, nil, 100)
	if err != nil {
		fmt.Println("table rows error:", err)
		os.Exit(1)
	}
	found := false
	for _, row := range rows.Rows {
		if label, _ := row.Data["label"].(string); label == "go" {
			found = true
		}
	}
	check("table rows", found)

	user := authv4.NewClient(pid, base, "", "")
	uname, err := user.UserRegister("gouser", "DemoPass123!", key, "")
	if err != nil {
		fmt.Println("user register error:", err)
		os.Exit(1)
	}
	check("user register", uname == "gouser")
	ulogged, err := user.UserLogin("gouser", "DemoPass123!", hwid)
	if err != nil {
		fmt.Println("user login error:", err)
		os.Exit(1)
	}
	check("user login", ulogged.Remaining > 80000)
	sub, err := user.UserUpgrade("gouser", key2)
	if err != nil {
		fmt.Println("user upgrade error:", err)
		os.Exit(1)
	}
	check("user upgrade", sub.Active && sub.Remaining > 80000)
	ubeat, err := user.Heartbeat()
	if err != nil {
		fmt.Println("user heartbeat error:", err)
		os.Exit(1)
	}
	check("user heartbeat", ubeat > 80000)
	uvalue, err := user.Variable("offset")
	if err != nil {
		fmt.Println("user variable error:", err)
		os.Exit(1)
	}
	check("user variable", uvalue == "0x10")

	bad := authv4.NewClient(pid, base, "", "")
	_, err = bad.License("ZZZZ-9999-ZZZZ-9999", hwid)
	check("bad key rejected", err != nil && strings.Contains(err.Error(), "Invalid key"))
	fmt.Println("GO CHECKS PASSED")
}
