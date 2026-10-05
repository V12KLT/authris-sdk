package authv4

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func fail(message string) error {
	return errors.New("authv4: " + message)
}

func MachineHWID() string {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("wmic", "csproduct", "get", "UUID").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				cleaned := strings.Map(func(r rune) rune {
					if (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || (r >= '0' && r <= '9') || r == '-' {
						return r
					}
					return -1
				}, strings.TrimSpace(line))
				if cleaned != "" && !strings.EqualFold(cleaned, "UUID") {
					return cleaned
				}
			}
		}
	case "linux":
		if raw, err := os.ReadFile("/etc/machine-id"); err == nil {
			if id := strings.TrimSpace(string(raw)); id != "" {
				return id
			}
		}
		if out, err := exec.Command("cat", "/proc/cpuinfo").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "Serial") {
					parts := strings.Split(line, ":")
					return strings.TrimSpace(parts[len(parts)-1])
				}
			}
		}
	case "darwin":
		if out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "IOPlatformUUID") {
					parts := strings.Split(line, `"`)
					if len(parts) >= 2 {
						return parts[len(parts)-2]
					}
				}
			}
		}
	}
	host, _ := os.Hostname()
	sum := sha256.Sum256([]byte(host + runtime.GOARCH + runtime.GOOS))
	return hex.EncodeToString(sum[:])[:32]
}

func SHA256File(path string) (string, error) {
	handle, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer handle.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, handle); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func VerifySignature(publicHex string, data string, signatureHex string) bool {
	rawKey, err := hex.DecodeString(publicHex)
	if err != nil || len(rawKey) != 64 {
		return false
	}
	rawSig, err := hex.DecodeString(signatureHex)
	if err != nil || len(rawSig) != 64 {
		return false
	}
	curve := elliptic.P256()
	x := new(big.Int).SetBytes(rawKey[:32])
	y := new(big.Int).SetBytes(rawKey[32:])
	if !curve.IsOnCurve(x, y) {
		return false
	}
	r := new(big.Int).SetBytes(rawSig[:32])
	s := new(big.Int).SetBytes(rawSig[32:])
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(curve.Params().N) >= 0 || s.Cmp(curve.Params().N) >= 0 {
		return false
	}
	digest := sha256.Sum256([]byte(data))
	return ecdsa.Verify(&ecdsa.PublicKey{Curve: curve, X: x, Y: y}, digest[:], r, s)
}

func hmacHex(key string, message string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

type LicenseResult struct {
	Expires   int64
	Remaining int64
}

type Subscription struct {
	Expires   int64 `json:"expires"`
	Remaining int64 `json:"remaining"`
	Active    bool  `json:"active"`
}

type InfoResult struct {
	Expires   int64  `json:"expires"`
	Status    string `json:"status"`
	Remaining int64  `json:"remaining"`
	Created   int64  `json:"created"`
}

type WebhookResult struct {
	Status    int    `json:"status"`
	Body      string `json:"body"`
	Truncated bool   `json:"truncated"`
}

type TableRow struct {
	ID   int64          `json:"id"`
	Data map[string]any `json:"data"`
}

type TableResult struct {
	OK   bool           `json:"ok"`
	ID   int64          `json:"id"`
	Rows []TableRow     `json:"rows"`
	Data map[string]any `json:"data"`
}

type Client struct {
	ProjectID string
	BaseURL   string
	AppHash   string
	ServerKey string
	Session   string
	Key       string
	HWID      string
	Username  string
	Expires   int64
	Remaining int64

	challengeID string
	challenge   string
	http        *http.Client
}

func NewClient(projectID string, baseURL string, appHash string, serverKey string) *Client {
	return &Client{
		ProjectID: projectID,
		BaseURL:   strings.TrimRight(baseURL, "/"),
		AppHash:   appHash,
		ServerKey: serverKey,
		Remaining: -1,
		http:      &http.Client{},
	}
}

func (c *Client) post(path string, payload any, timeout time.Duration) (map[string]any, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fail("encode request: " + err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+path, bytes.NewReader(raw))
	if err != nil {
		return nil, fail("build request: " + err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fail("request failed: " + err.Error())
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fail("read response: " + err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fail(fmt.Sprintf("request failed: HTTP %d", resp.StatusCode))
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, fail("decode response: " + err.Error())
	}
	return decoded, nil
}

func (c *Client) get(path string, timeout time.Duration) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+path, nil)
	if err != nil {
		return nil, fail("build request: " + err.Error())
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fail("request failed: " + err.Error())
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fail("read response: " + err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fail(fmt.Sprintf("request failed: HTTP %d", resp.StatusCode))
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, fail("decode response: " + err.Error())
	}
	return decoded, nil
}

func str(body map[string]any, key string) string {
	value, _ := body[key].(string)
	return value
}

func num(body map[string]any, key string) int64 {
	switch value := body[key].(type) {
	case float64:
		return int64(value)
	case int64:
		return value
	case int:
		return int64(value)
	}
	return 0
}

func rotationOk(payload map[string]any, current string, pinned string) bool {
	rotation, ok := payload["rotation"].(map[string]any)
	if !ok {
		return false
	}
	newKey, _ := rotation["new_key"].(string)
	sig, _ := rotation["signature"].(string)
	if newKey != current || sig == "" {
		return false
	}
	return VerifySignature(pinned, "ROTATE:"+current, sig)
}

func remap(body map[string]any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func (c *Client) Init() error {
	fetched, err := c.get("/v4/server-key", 15*time.Second)
	if err != nil {
		return err
	}
	key := str(fetched, "server_key")
	if key == "" {
		return fail("Server key missing")
	}
	if c.ServerKey != "" && !hmac.Equal([]byte(c.ServerKey), []byte(key)) && !rotationOk(fetched, key, c.ServerKey) {
		return fail("Server key mismatch (get the current key from GET /v4/server-key or the dashboard Setup page)")
	}
	c.ServerKey = key
	result, err := c.post("/v4/init", map[string]any{"project_id": c.ProjectID}, 15*time.Second)
	if err != nil {
		return err
	}
	if ok, _ := result["ok"].(bool); !ok {
		return fail(str(result, "error"))
	}
	c.challengeID = str(result, "challenge_id")
	c.challenge = str(result, "challenge")
	return nil
}

func (c *Client) License(key string, hwid string) (*LicenseResult, error) {
	if c.challenge == "" {
		if err := c.Init(); err != nil {
			return nil, err
		}
	}
	useHWID := hwid
	if useHWID == "" {
		useHWID = MachineHWID()
	}
	challenge := c.challenge
	payload := map[string]any{
		"project_id": c.ProjectID, "key": key, "hwid": useHWID,
		"challenge_id": c.challengeID, "signature": hmacHex(key, challenge),
	}
	if c.AppHash != "" {
		payload["app_hash"] = c.AppHash
	}
	c.challenge = ""
	c.challengeID = ""
	result, err := c.post("/v4/license", payload, 15*time.Second)
	if err != nil {
		return nil, err
	}
	if ok, _ := result["ok"].(bool); !ok {
		return nil, fail(str(result, "error"))
	}
	session := str(result, "session")
	proofBase := challenge + "|" + session
	if !hmac.Equal([]byte(hmacHex(key, proofBase)), []byte(str(result, "server_proof"))) {
		return nil, fail("Server proof mismatch")
	}
	if c.ServerKey != "" && !VerifySignature(c.ServerKey, proofBase, str(result, "signature")) {
		return nil, fail("Server signature mismatch")
	}
	c.Session = session
	c.Key = key
	c.HWID = useHWID
	c.Expires = num(result, "expires")
	c.Remaining = num(result, "remaining")
	if _, present := result["remaining"]; !present {
		c.Remaining = -1
	}
	return &LicenseResult{Expires: c.Expires, Remaining: c.Remaining}, nil
}

func (c *Client) UserRegister(username string, password string, key string, hwid string) (string, error) {
	payload := map[string]any{"project_id": c.ProjectID, "username": username, "password": password, "key": key}
	if hwid != "" {
		payload["hwid"] = hwid
	}
	result, err := c.post("/v4/user/register", payload, 15*time.Second)
	if err != nil {
		return "", err
	}
	if ok, _ := result["ok"].(bool); !ok {
		return "", fail(str(result, "error"))
	}
	return str(result, "username"), nil
}

func (c *Client) UserLogin(username string, password string, hwid string) (*LicenseResult, error) {
	if c.ServerKey == "" {
		if err := c.Init(); err != nil {
			return nil, err
		}
	}
	useHWID := hwid
	if useHWID == "" {
		useHWID = MachineHWID()
	}
	result, err := c.post("/v4/user/login", map[string]any{
		"project_id": c.ProjectID, "username": username, "password": password, "hwid": useHWID,
	}, 15*time.Second)
	if err != nil {
		return nil, err
	}
	if ok, _ := result["ok"].(bool); !ok {
		return nil, fail(str(result, "error"))
	}
	session := str(result, "session")
	if c.ServerKey != "" && !VerifySignature(c.ServerKey, "user|"+session, str(result, "signature")) {
		return nil, fail("Server signature mismatch")
	}
	c.Session = session
	c.Key = password
	c.HWID = useHWID
	c.Username = username
	if raw, isMap := result["subscription"].(map[string]any); isMap {
		c.Expires = num(raw, "expires")
		c.Remaining = num(raw, "remaining")
	}
	return &LicenseResult{Expires: c.Expires, Remaining: c.Remaining}, nil
}

func (c *Client) UserRedeem(username string, password string, key string) (*Subscription, error) {
	result, err := c.post("/v4/user/redeem", map[string]any{
		"project_id": c.ProjectID, "username": username, "password": password, "key": key,
	}, 15*time.Second)
	if err != nil {
		return nil, err
	}
	if ok, _ := result["ok"].(bool); !ok {
		return nil, fail(str(result, "error"))
	}
	var sub Subscription
	if raw, isMap := result["subscription"].(map[string]any); isMap {
		if err := remap(raw, &sub); err != nil {
			return nil, fail("decode subscription: " + err.Error())
		}
	}
	return &sub, nil
}

func (c *Client) UserUpgrade(username string, key string) (*Subscription, error) {
	result, err := c.post("/v4/user/upgrade", map[string]any{
		"project_id": c.ProjectID, "username": username, "key": key,
	}, 15*time.Second)
	if err != nil {
		return nil, err
	}
	if ok, _ := result["ok"].(bool); !ok {
		return nil, fail(str(result, "error"))
	}
	var sub Subscription
	if raw, isMap := result["subscription"].(map[string]any); isMap {
		if err := remap(raw, &sub); err != nil {
			return nil, fail("decode subscription: " + err.Error())
		}
	}
	return &sub, nil
}

func (c *Client) Heartbeat() (int64, error) {
	if c.Session == "" || c.Key == "" {
		return 0, fail("Not licensed")
	}
	result, err := c.post("/v4/heartbeat", map[string]any{"session": c.Session, "key": c.Key}, 15*time.Second)
	if err != nil {
		return 0, err
	}
	if ok, _ := result["ok"].(bool); !ok {
		return 0, fail(str(result, "error"))
	}
	remaining := num(result, "remaining")
	base := fmt.Sprintf("VERIFY:%s:%d", c.ProjectID, remaining)
	if !hmac.Equal([]byte(hmacHex(c.Key, base)), []byte(str(result, "proof"))) {
		return 0, fail("Heartbeat proof mismatch")
	}
	if c.ServerKey != "" && !VerifySignature(c.ServerKey, base, str(result, "signature")) {
		return 0, fail("Heartbeat signature mismatch")
	}
	c.Remaining = remaining
	return remaining, nil
}

func (c *Client) Info() (*InfoResult, error) {
	if c.Key == "" {
		return nil, fail("Not licensed")
	}
	hwid := c.HWID
	if hwid == "" {
		hwid = MachineHWID()
	}
	result, err := c.post("/v4/info", map[string]any{
		"project_id": c.ProjectID, "key": c.Key, "hwid": hwid,
	}, 15*time.Second)
	if err != nil {
		return nil, err
	}
	if ok, _ := result["ok"].(bool); !ok {
		return nil, fail(str(result, "error"))
	}
	var out InfoResult
	if err := remap(result, &out); err != nil {
		return nil, fail("decode info: " + err.Error())
	}
	return &out, nil
}

func (c *Client) Variables() (map[string]string, error) {
	if c.Session == "" || c.Key == "" {
		return nil, fail("Not licensed")
	}
	result, err := c.post("/v4/variable", map[string]any{"session": c.Session, "key": c.Key}, 15*time.Second)
	if err != nil {
		return nil, err
	}
	if ok, _ := result["ok"].(bool); !ok {
		return nil, fail(str(result, "error"))
	}
	out := map[string]string{}
	if vars, isMap := result["variables"].(map[string]any); isMap {
		for k, v := range vars {
			if text, isStr := v.(string); isStr {
				out[k] = text
			}
		}
	}
	return out, nil
}

func (c *Client) Variable(name string) (string, error) {
	if c.Session == "" || c.Key == "" {
		return "", fail("Not licensed")
	}
	result, err := c.post("/v4/variable", map[string]any{"session": c.Session, "key": c.Key, "name": name}, 15*time.Second)
	if err != nil {
		return "", err
	}
	if ok, _ := result["ok"].(bool); !ok {
		return "", fail(str(result, "error"))
	}
	return str(result, "value"), nil
}

func (c *Client) File(name string) ([]byte, error) {
	if c.Session == "" || c.Key == "" {
		return nil, fail("Not licensed")
	}
	result, err := c.post("/v4/file", map[string]any{"session": c.Session, "key": c.Key, "name": name}, 60*time.Second)
	if err != nil {
		return nil, err
	}
	if ok, _ := result["ok"].(bool); !ok {
		return nil, fail(str(result, "error"))
	}
	nonceHex := str(result, "nonce")
	fileKey, err := hex.DecodeString(hmacHex(c.Key, "FILE_KEY:"+nonceHex))
	if err != nil {
		return nil, fail("decode file key")
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return nil, fail("decode nonce")
	}
	content, err := base64.StdEncoding.DecodeString(str(result, "data"))
	if err != nil {
		return nil, fail("decode file data")
	}
	tag, err := hex.DecodeString(str(result, "tag"))
	if err != nil {
		return nil, fail("decode file tag")
	}
	block, err := aes.NewCipher(fileKey)
	if err != nil {
		return nil, fail("file cipher: " + err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fail("file cipher: " + err.Error())
	}
	plain, err := gcm.Open(nil, nonce, append(content, tag...), []byte(c.ProjectID))
	if err != nil {
		return nil, fail("File decrypt failed")
	}
	sum := sha256.Sum256(plain)
	if hex.EncodeToString(sum[:]) != str(result, "hash") {
		return nil, fail("File hash mismatch")
	}
	return plain, nil
}

func (c *Client) Webhook(name string, data string) (*WebhookResult, error) {
	if c.Session == "" || c.Key == "" {
		return nil, fail("Not licensed")
	}
	result, err := c.post("/v4/webhook", map[string]any{"session": c.Session, "key": c.Key, "name": name, "data": data}, 30*time.Second)
	if err != nil {
		return nil, err
	}
	if ok, _ := result["ok"].(bool); !ok {
		return nil, fail(str(result, "error"))
	}
	var out WebhookResult
	if err := remap(result, &out); err != nil {
		return nil, fail("decode webhook: " + err.Error())
	}
	return &out, nil
}

func (c *Client) Table(table string, op string, id int64, data map[string]any, limit int) (*TableResult, error) {
	if c.Session == "" || c.Key == "" {
		return nil, fail("Not licensed")
	}
	payload := map[string]any{"session": c.Session, "key": c.Key, "table": table, "op": op, "limit": limit}
	if id != 0 {
		payload["id"] = id
	}
	if data != nil {
		payload["data"] = data
	}
	result, err := c.post("/v4/table", payload, 15*time.Second)
	if err != nil {
		return nil, err
	}
	if ok, _ := result["ok"].(bool); !ok {
		return nil, fail(str(result, "error"))
	}
	var out TableResult
	if err := remap(result, &out); err != nil {
		return nil, fail("decode table: " + err.Error())
	}
	out.OK = true
	return &out, nil
}
