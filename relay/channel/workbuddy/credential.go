// Package workbuddy turns WorkBuddy/CodeBuddy account credentials into a native
// new-api channel. The channel key stores the account JSON; the adaptor talks to
// the official WorkBuddy upstream directly, so no separate relay process sits
// between new-api and the provider.
package workbuddy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Credential is the normalized account shape persisted in Channel.Key.
type Credential struct {
	UID          string `json:"uid"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
	Domain       string `json:"domain,omitempty"`
	Realm        string `json:"realm,omitempty"`
	EnterpriseID string `json:"enterprise_id,omitempty"`
	Nickname     string `json:"nickname,omitempty"`
	DeviceToken  string `json:"device_token,omitempty"`
	// Local maintenance state, written back by the native check-in/balance
	// endpoints. Kept on the credential line so a channel key carries both the
	// upstream credential and the last known quota snapshot.
	Credits        int64  `json:"credits,omitempty"`
	CreditsTotal   int64  `json:"credits_total,omitempty"`
	LastCheckinDay string `json:"last_checkin_day,omitempty"`
}

// ParseCredential accepts the normalized shape plus every shape the cockpit
// export tools produce: snake_case flat, camelCase flat and the nested
// {account, auth} single-account detail export.
func ParseCredential(raw string) (*Credential, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("empty workbuddy credential")
	}

	var c Credential
	if err := json.Unmarshal([]byte(trimmed), &c); err != nil {
		return nil, fmt.Errorf("invalid workbuddy credential JSON: %w", err)
	}
	if strings.TrimSpace(c.AccessToken) != "" {
		c.normalize()
		return &c, nil
	}

	var flat struct {
		UID          string `json:"uid"`
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresAt    int64  `json:"expiresAt"`
		Domain       string `json:"domain"`
		Realm        string `json:"realm"`
		EnterpriseID string `json:"enterpriseId"`
		Nickname     string `json:"nickname"`
		DeviceToken  string `json:"device_token"`
	}
	if err := json.Unmarshal([]byte(trimmed), &flat); err == nil && flat.AccessToken != "" {
		c = Credential{
			UID:          flat.UID,
			AccessToken:  flat.AccessToken,
			RefreshToken: flat.RefreshToken,
			ExpiresAt:    flat.ExpiresAt,
			Domain:       flat.Domain,
			Realm:        flat.Realm,
			EnterpriseID: flat.EnterpriseID,
			Nickname:     flat.Nickname,
			DeviceToken:  flat.DeviceToken,
		}
		c.normalize()
		return &c, nil
	}

	var nested struct {
		Account struct {
			UID          string `json:"uid"`
			Nickname     string `json:"nickname"`
			EnterpriseID string `json:"enterpriseId"`
		} `json:"account"`
		Auth struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
			ExpiresAt    int64  `json:"expiresAt"`
			Domain       string `json:"domain"`
			Realm        string `json:"realm"`
		} `json:"auth"`
		DeviceToken string `json:"device_token"`
	}
	if err := json.Unmarshal([]byte(trimmed), &nested); err == nil && nested.Auth.AccessToken != "" {
		c = Credential{
			UID:          nested.Account.UID,
			Nickname:     nested.Account.Nickname,
			EnterpriseID: nested.Account.EnterpriseID,
			AccessToken:  nested.Auth.AccessToken,
			RefreshToken: nested.Auth.RefreshToken,
			ExpiresAt:    nested.Auth.ExpiresAt,
			Domain:       nested.Auth.Domain,
			Realm:        nested.Auth.Realm,
			DeviceToken:  nested.DeviceToken,
		}
		c.normalize()
		return &c, nil
	}
	return nil, errors.New("workbuddy credential has no access token")
}

func (c *Credential) normalize() {
	c.AccessToken = strings.TrimSpace(c.AccessToken)
	c.RefreshToken = strings.TrimSpace(c.RefreshToken)
	c.Domain = strings.TrimSpace(c.Domain)
	c.Realm = strings.ToLower(strings.TrimSpace(c.Realm))
	c.UID = strings.TrimSpace(c.UID)
	// Cockpit bulk exports use milliseconds, single-account detail exports use
	// seconds. 1e11 is far above any plausible Unix-second value.
	if c.ExpiresAt > 1e11 {
		c.ExpiresAt /= 1000
	}
}

// MarshalCredential writes the canonical stored shape.
func (c *Credential) MarshalCredential() (string, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// IsGlobal reports whether the account belongs to the international site.
// An explicit realm wins; otherwise the domain suffix decides.
func (c *Credential) IsGlobal() bool {
	if c.Realm == "global" {
		return true
	}
	if c.Realm == "cn" {
		return false
	}
	d := strings.ToLower(c.Domain)
	return strings.HasSuffix(d, "workbuddy.ai") || strings.HasSuffix(d, "codebuddy.ai")
}

// IsAPIKey reports a static console key. Those never need a token refresh.
func (c *Credential) IsAPIKey() bool {
	return strings.HasPrefix(c.AccessToken, "ck_") || strings.HasPrefix(c.AccessToken, "pt_")
}

// NeedsRefresh reports whether the access token is missing, expired or within
// five minutes of expiry. Static API keys are never refreshed.
func (c *Credential) NeedsRefresh() bool {
	if c.IsAPIKey() || c.RefreshToken == "" {
		return false
	}
	if c.ExpiresAt <= 0 {
		return false
	}
	return c.ExpiresAt-time.Now().Unix() < 300
}

const (
	BaseCN            = "https://www.workbuddy.cn"
	BaseGlobalDefault = "https://www.codebuddy.ai"
	BaseGlobalLegacy  = "https://www.workbuddy.ai"
)

// BaseURL resolves the upstream host. A custom channel base URL wins, so a
// reverse proxy or a private endpoint stays configurable.
func (c *Credential) BaseURL(custom string) string {
	if v := strings.TrimRight(strings.TrimSpace(custom), "/"); v != "" &&
		v != BaseCN && v != BaseGlobalDefault && v != BaseGlobalLegacy {
		return v
	}
	if !c.IsGlobal() {
		return BaseCN
	}
	d := strings.ToLower(c.Domain)
	if strings.HasSuffix(d, "workbuddy.ai") {
		return BaseGlobalLegacy
	}
	return BaseGlobalDefault
}

// DomainHeader is the value of the X-Domain chat header.
func (c *Credential) DomainHeader() string {
	if c.IsGlobal() {
		return "www.workbuddy.ai"
	}
	return "www.workbuddy.cn"
}

// SplitRealmPrefix strips the panel's "[realm:]model" routing prefix. The
// official upstream only knows bare model names.
func SplitRealmPrefix(model string) (string, string) {
	if i := strings.IndexByte(model, ':'); i >= 0 {
		switch model[:i] {
		case "cn", "global":
			return model[:i], model[i+1:]
		}
	}
	return "cn", model
}

// DefaultModels mirrors the panel's built-in model catalog. It is used when an
// import does not supply an explicit model list and /v3/config is unreachable.
var DefaultModels = []string{
	"glm-5.2", "glm-5.1", "glm-5.3", "glm-5.3-flash", "glm-5v-turbo",
	"kimi-k2.7", "kimi-k2.6", "kimi-k2.5", "kimi-k3", "kimi-k2.8-preview",
	"minimax-m3", "hy3", "hy3-preview", "hy4-preview", "hy4-preview-x",
	"deepseek-v4-pro", "deepseek-v4-flash", "deepseek-v4.1-flash",
	"gpt-6-astra", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna",
	"gpt-5.5", "gpt-5.4", "gpt-5.3-codex", "gemini-3.5-flash", "auto",
}

// ReplaceCredentialLine swaps the account line a relay used (original) for the
// rotated credential, keeping every other account in the pool. A channel key
// can hold many accounts, one JSON per line, and a refresh only covers one.
func ReplaceCredentialLine(key, original, encoded string) string {
	original = strings.TrimSpace(original)
	uid := ""
	if cred, err := ParseCredential(original); err == nil {
		uid = cred.UID
	}
	lines := make([]string, 0)
	replaced := false
	for _, line := range strings.Split(strings.TrimSpace(key), "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		if !replaced && line == original {
			lines = append(lines, encoded)
			replaced = true
			continue
		}
		lines = append(lines, line)
	}
	if !replaced && uid != "" {
		// Whitespace or a re-encoded line broke the exact match; identify the
		// account by UID instead so the pool keeps its order.
		lines = lines[:0]
		for _, line := range strings.Split(strings.TrimSpace(key), "\n") {
			if line = strings.TrimSpace(line); line == "" {
				continue
			}
			if cred, err := ParseCredential(line); err == nil && cred.UID == uid {
				lines = append(lines, encoded)
				replaced = true
				continue
			}
			lines = append(lines, line)
		}
	}
	if !replaced {
		lines = append(lines, encoded)
	}
	return strings.Join(lines, "\n")
}
