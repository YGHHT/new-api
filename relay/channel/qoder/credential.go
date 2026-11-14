package qoder

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Realm base URLs. CN and INTL speak to different hosts; a channel account
// carries exactly one realm.
const (
	OpenAPICN = "https://openapi.qoder.com.cn"
	GatewayCN = "https://gateway.qoder.com.cn"
	WebsiteCN = "https://qoder.com.cn"

	OpenAPIINTL = "https://openapi.qoder.sh"
	GatewayINTL = "https://api3.qoder.sh"
	WebsiteINTL = "https://qoder.com"

	ChatPath = "/algo/api/v2/service/pro/sse/agent_chat_generation"
)

// Credential is one Qoder account line in the channel key.
type Credential struct {
	UID              string `json:"uid"`
	Nickname         string `json:"nickname,omitempty"`
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	UserType         string `json:"user_type,omitempty"`
	OrganizationID   string `json:"organization_id,omitempty"`
	OrganizationName string `json:"organization_name,omitempty"`
	Realm            string `json:"realm,omitempty"`
	Source           string `json:"source,omitempty"`
	ExpiresAt        int64  `json:"expires_at,omitempty"`
	// Local maintenance state, written back by the native check-in/balance
	// endpoints so a key line carries both the upstream credential and quota.
	LastCheckinDay string `json:"last_checkin_day,omitempty"`
	Credits        int64  `json:"credits,omitempty"`
	CreditsTotal   int64  `json:"credits_total,omitempty"`
}

// ParseCredential accepts a normalized flat line or a camelCase one.
func ParseCredential(raw string) (*Credential, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("qoder: empty key line")
	}
	if !strings.HasPrefix(raw, "{") {
		return nil, fmt.Errorf("qoder: key line must be one account JSON object")
	}

	// Fast path: canonical snake_case.
	cred := &Credential{}
	if err := json.Unmarshal([]byte(raw), cred); err == nil && cred.AccessToken != "" {
		return normalize(cred), nil
	}

	// camelCase / nested variants.
	var camel struct {
		UID              string `json:"uid"`
		Nickname         string `json:"nickname"`
		AccessToken      string `json:"accessToken"`
		RefreshToken     string `json:"refreshToken"`
		UserType         string `json:"userType"`
		OrganizationID   string `json:"organizationId"`
		OrganizationName string `json:"organizationName"`
		Realm            string `json:"realm"`
		Source           string `json:"source"`
		ExpiresAt        int64  `json:"expiresAt"`
		LastCheckinDay   string `json:"lastCheckinDay"`
		Credits          int64  `json:"credits"`
		CreditsTotal     int64  `json:"creditsTotal"`
	}
	if err := json.Unmarshal([]byte(raw), &camel); err != nil {
		return nil, fmt.Errorf("qoder: unmarshal key: %w", err)
	}
	out := &Credential{
		UID:              camel.UID,
		Nickname:         camel.Nickname,
		AccessToken:      camel.AccessToken,
		RefreshToken:     camel.RefreshToken,
		UserType:         camel.UserType,
		OrganizationID:   camel.OrganizationID,
		OrganizationName: camel.OrganizationName,
		Realm:            camel.Realm,
		Source:           camel.Source,
		ExpiresAt:        camel.ExpiresAt,
		LastCheckinDay:   camel.LastCheckinDay,
		Credits:          camel.Credits,
		CreditsTotal:     camel.CreditsTotal,
	}
	if out.AccessToken == "" {
		return nil, fmt.Errorf("qoder: credential has no access_token")
	}
	return normalize(out), nil
}

func normalize(c *Credential) *Credential {
	c.UID = strings.TrimSpace(c.UID)
	if c.Realm == "" {
		c.Realm = "cn"
	}
	// A millisecond expiry is normalized to seconds.
	if c.ExpiresAt > 1e11 {
		c.ExpiresAt /= 1000
	}
	return c
}

// MarshalCredential writes the canonical line back to the key.
func (c *Credential) MarshalCredential() (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// NeedsRefresh is true when the token has an explicit expiry within 5 minutes.
func (c *Credential) NeedsRefresh() bool {
	if c.ExpiresAt <= 0 {
		return false
	}
	// Static / PAT console keys without a refresh path are left alone.
	if c.RefreshToken == "" {
		return false
	}
	return time.Until(time.Unix(c.ExpiresAt, 0)) < 5*time.Minute
}

// IsGlobal reports the INTL realm.
func (c *Credential) IsGlobal() bool { return c.Realm == "global" || c.Realm == "intl" }

// OpenAPI base URL for the account's realm.
func (c *Credential) OpenAPI() string {
	if c.IsGlobal() {
		return OpenAPIINTL
	}
	return OpenAPICN
}

// Gateway base URL for the chat upstream.
func (c *Credential) Gateway() string {
	if c.IsGlobal() {
		return GatewayINTL
	}
	return GatewayCN
}

// Website base URL (device login redirect).
func (c *Credential) Website() string {
	if c.IsGlobal() {
		return WebsiteINTL
	}
	return WebsiteCN
}

// ChatURL is the official chat generation endpoint for the account's realm.
// The adaptor may override the gateway host when a channel base URL is set.
func (c *Credential) ChatURL() string {
	return c.Gateway() + ChatPath
}

// RefreshURL picks the token-family refresh endpoint.
func (c *Credential) RefreshURL() string {
	switch {
	case strings.HasPrefix(c.RefreshToken, "drt-"):
		return c.OpenAPI() + "/api/v1/deviceToken/refresh"
	default:
		return c.OpenAPI() + "/api/v1/jobToken/refresh"
	}
}

// ReplaceCredentialLine swaps the account line a relay used (original) for the
// rotated credential, keeping every other account in the pool.
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

// SplitCredentialLines returns the non-empty account lines in a channel key.
func SplitCredentialLines(key string) []string {
	out := make([]string, 0)
	for _, line := range strings.Split(strings.TrimSpace(key), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
