package trae

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Account-side Trae protocol: OAuth callback exchange, daily check-in
// (status + claim) and entitlement/credit balance.

func hc(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

// checkinHeaders are the shared headers for Trae's own API.
func checkinHeaders(cred *Credential) map[string]string {
	dev := cred.Device()
	return map[string]string{
		"accept":             "*/*",
		"accept-language":    "zh-CN",
		"authorization":      cred.AuthHeader(),
		"content-type":       "application/json",
		"user-agent":         "VSCode 1.107.1 (TRAE SOLO CN)",
		"x-market-client-id": "VSCode 1.107.1",
		"x-market-user-id":   dev.MarketUserID,
		"x-user-region":      "CN",
		"x-device-id":        dev.DeviceID,
		"x-lgw-req-sdk-type": "3",
		"package-type":       "stable_cn",
		"x-request-id":       newHex(16),
		"x-lscbd-aid":        "787976",
		"x-lscbd-platform":   "windows",
		"app-version":        "0.1.45",
		"x-tt-trace-id":      "00-" + newHex(8) + "-01",
		"vscode-sessionid":   dev.SessionID,
		"sec-fetch-dest":     "empty",
		"sec-fetch-mode":     "no-cors",
		"sec-fetch-site":     "none",
	}
}

func idePost(cred *Credential, endpoint string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	for k, v := range checkinHeaders(cred) {
		req.Header.Set(k, v)
	}
	resp, err := hc(30 * time.Second).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, err
}

// CheckinStatus is the state read before claiming.
type CheckinStatus struct {
	CheckedIn bool  `json:"checked_in"`
	Credits   int64 `json:"credits"`
}

// FetchCheckinStatus reads whether today is already claimed.
func FetchCheckinStatus(cred *Credential) (*CheckinStatus, error) {
	status, raw, err := idePost(cred, CheckinStatusURL, []byte("{}"))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("checkin status %d: %s", status, truncate(string(raw), 200))
	}
	checked, _ := findBool(raw, "checked_in")
	credits, _ := findInt(raw, "credits")
	return &CheckinStatus{CheckedIn: checked, Credits: credits}, nil
}

// CheckinResult is one account's daily check-in outcome.
type CheckinResult struct {
	Status  string `json:"status"` // checked | already | failed
	Credits int64  `json:"credits,omitempty"`
	Message string `json:"message,omitempty"`
}

// DailyCheckin runs status-then-claim and never reports an idempotent
// rejection as success.
func DailyCheckin(cred *Credential) *CheckinResult {
	st, err := FetchCheckinStatus(cred)
	if err != nil {
		return &CheckinResult{Status: "failed", Message: err.Error()}
	}
	if st.CheckedIn {
		return &CheckinResult{Status: "already", Credits: st.Credits, Message: "already signed in today"}
	}

	code, raw, err := idePost(cred, CheckinClaimURL, []byte("{}"))
	if err != nil {
		return &CheckinResult{Status: "failed", Message: err.Error()}
	}
	var body struct {
		Code    int    `json:"code"`
		Credits int64  `json:"credits"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &body)

	if code == http.StatusOK && body.Code == 0 {
		credits := body.Credits
		if credits == 0 {
			credits, _ = findInt(raw, "reward", "reward_credits", "claim_credits", "delta", "credits")
		}
		return &CheckinResult{Status: "checked", Credits: credits}
	}
	// Business rejections: an already-signed day is not a failure.
	lower := strings.ToLower(string(body.Message) + string(raw))
	if strings.Contains(lower, "already") || strings.Contains(lower, "signed today") {
		return &CheckinResult{Status: "already", Message: body.Message}
	}
	return &CheckinResult{Status: "failed", Message: firstNonEmpty(body.Message, truncate(string(raw), 200))}
}

// Balance is the entitlement snapshot returned to the panel.
type Balance struct {
	Remaining int64  `json:"remaining"`
	Used      int64  `json:"used"`
	Total     int64  `json:"total"`
	Detail    string `json:"detail,omitempty"`
}

// FetchBalance sums the entitlement packs (product 208 = general credits).
func FetchBalance(cred *Credential) (*Balance, error) {
	body, _ := json.Marshal(map[string]any{"require_usage": true, "req_source": 2})
	status, raw, err := idePost(cred, EntitlementURL, body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("entitlement %d: %s", status, truncate(string(raw), 200))
	}

	// The response is a tolerant tree: find every pack and sum credits.
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("entitlement decode: %w", err)
	}
	out := &Balance{}
	packs := findPacks(root)
	for _, p := range packs {
		out.Total += p.limit
		out.Used += p.used
	}
	out.Remaining = out.Total - out.Used
	if out.Remaining < 0 {
		out.Remaining = 0
	}
	return out, nil
}

type pack struct {
	limit int64
	used  int64
}

// findPacks walks the entitlement tree collecting quota/usage pairs.
func findPacks(node any) []pack {
	var out []pack
	var walk func(any)
	walk = func(n any) {
		switch v := n.(type) {
		case map[string]any:
			limit, hasLimit := numeric(v["credits_limit"])
			used, hasUsed := numeric(v["credits_amount"])
			if hasLimit && hasUsed {
				out = append(out, pack{limit: limit, used: used})
			}
			// quota{credits_limit} + usage{credits_amount} nesting.
			if q, ok := v["quota"].(map[string]any); ok {
				if u, ok := v["usage"].(map[string]any); ok {
					l, lok := numeric(q["credits_limit"])
					us, uok := numeric(u["credits_amount"])
					if lok && uok {
						out = append(out, pack{limit: l, used: us})
					}
				}
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(node)
	return out
}

func numeric(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case string:
		var f float64
		if _, err := fmt.Sscanf(n, "%f", &f); err == nil {
			return int64(f), true
		}
	}
	return 0, false
}

// findBool walks a JSON tree for the first key match of a bool.
func findBool(raw []byte, keys ...string) (bool, bool) {
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return false, false
	}
	if v, ok := walkKey(root, keys...); ok {
		if b, ok := v.(bool); ok {
			return b, true
		}
	}
	return false, false
}

// findInt walks a JSON tree for the first key match of a number.
func findInt(raw []byte, keys ...string) (int64, bool) {
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return 0, false
	}
	if v, ok := walkKey(root, keys...); ok {
		return numeric(v)
	}
	return 0, false
}

func walkKey(node any, keys ...string) (any, bool) {
	set := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		set[k] = struct{}{}
	}
	var found any
	var ok bool
	var walk func(any)
	walk = func(n any) {
		if ok {
			return
		}
		switch v := n.(type) {
		case map[string]any:
			for k, child := range v {
				if _, want := set[k]; want {
					found, ok = child, true
					return
				}
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(node)
	return found, ok
}

// LoginStart describes one OAuth authorization attempt.
type LoginStart struct {
	URL   string
	State string
}

// StartOAuthLogin builds the Trae authorization URL with a CSRF state.
func StartOAuthLogin() *LoginStart {
	state := newHex(16)
	q := url.Values{}
	q.Set("login_version", "1")
	q.Set("auth_from", "trae")
	q.Set("login_channel", "native_ide")
	q.Set("plugin_version", "2.3.83560")
	q.Set("auth_type", "local")
	q.Set("client_id", "ono9krqynydwx5")
	q.Set("redirect", "0")
	q.Set("login_trace_id", state)
	q.Set("auth_callback_url", "http://127.0.0.1:17388/authorize")
	q.Set("code_challenge_method", "S256")
	q.Set("channel_name", "common")
	return &LoginStart{
		URL:   "https://www.trae.cn/authorization?" + q.Encode(),
		State: state,
	}
}

// ParseCallbackURL extracts the tokens a user pastes back after authorizing.
// Trae appends either flat params or an authCodeInfo JSON blob.
func ParseCallbackURL(raw string) (*Credential, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("trae: empty callback")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("trae: callback parse: %w", err)
	}
	q := u.Query()

	refresh := firstNonEmpty(q.Get("refreshToken"), q.Get("refresh_token"))
	access := firstNonEmpty(q.Get("accessToken"), q.Get("access_token"))
	uid := firstNonEmpty(q.Get("userId"), q.Get("user_id"))
	name := firstNonEmpty(q.Get("userName"), q.Get("user_name"))

	if blob := firstNonEmpty(q.Get("authCodeInfo"), q.Get("auth_code_info")); blob != "" {
		var info struct {
			RefreshToken string `json:"refreshToken"`
			AccessToken  string `json:"accessToken"`
			UserID       string `json:"userId"`
			UserName     string `json:"userName"`
		}
		if err := json.Unmarshal([]byte(blob), &info); err == nil {
			refresh = firstNonEmpty(refresh, info.RefreshToken)
			access = firstNonEmpty(access, info.AccessToken)
			uid = firstNonEmpty(uid, info.UserID)
			name = firstNonEmpty(name, info.UserName)
		}
	}
	if access == "" && refresh == "" {
		return nil, fmt.Errorf("trae: callback carried no token")
	}
	cred := &Credential{
		UID:          uid,
		Name:         name,
		JWT:          StripJWTPrefix(access),
		RefreshToken: refresh,
	}
	if cred.UID == "" {
		cred.UID = JWTUserID(cred.JWT)
	}
	return cred, nil
}

// ExchangeAuthCode trades an authorization code for a JWT (P1363 device proof
// is omitted for the auth-code variant; the device is declared via DeviceInfo).
func ExchangeAuthCode(code, verifier string) (*Credential, error) {
	dev := DeriveDevice(code)
	body, _ := json.Marshal(map[string]any{
		"ClientID":     AppID,
		"AuthCode":     code,
		"CodeVerifier": verifier,
		"DeviceInfo": map[string]any{
			"DeviceID":      dev.DeviceID,
			"MachineID":     SeededHex(64, code, "mach"),
			"PlatformCode":  "IDE_PC",
			"DeviceType":    "PC",
			"ClientVersion": IDEVersion,
		},
		"IDEVersion": IDEVersion,
	})
	req, err := http.NewRequest(http.MethodPost, TraeAPIHost+"/trae/api/v3/oauth/ExchangeToken", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// Mandatory even when empty: a missing header yields 20403.
	req.Header.Set("x-cloudide-token", "")
	req.Header.Set("x-device-id", dev.DeviceID)
	req.Header.Set("x-app-id", AppID)
	req.Header.Set("x-platform-code", "IDE_PC")

	resp, err := hc(30 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("exchange status %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var env struct {
		Result struct {
			Token        string `json:"Token"`
			RefreshToken string `json:"RefreshToken"`
		} `json:"Result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("exchange decode: %w", err)
	}
	if env.Result.Token == "" {
		return nil, fmt.Errorf("exchange returned no token: %s", truncate(string(raw), 200))
	}
	cred := &Credential{
		JWT:          StripJWTPrefix(env.Result.Token),
		RefreshToken: env.Result.RefreshToken,
	}
	cred.UID = JWTUserID(cred.JWT)
	return cred, nil
}

var _ = context.Background
