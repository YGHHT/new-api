package trae

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Official Trae upstream constants.
const (
	AgentHost    = "https://trae-api-cn.mchost.guru"
	ChatPath     = "/api/agent/v3/llm_utils_chat"
	AppID        = "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8"
	IDEVersion   = "0.1.50"
	IDEVerCode   = "20260811"
	DefaultFunc  = "solo_work_lite"
	DefaultModel = "deepseek-v4-flash"

	// Trae's own API host: OAuth, check-in and entitlement queries.
	TraeAPIHost = "https://api.trae.cn"

	CheckinStatusURL = TraeAPIHost + "/trae/api/v2/ug/checkin_credits/status"
	CheckinClaimURL  = TraeAPIHost + "/trae/api/v2/ug/checkin_credits/claim"
	EntitlementURL   = TraeAPIHost + "/trae/api/v2/pay/ide_user_ent_usage"
)

// Credential is one Trae account line in the channel key.
type Credential struct {
	UID          string `json:"uid"`
	Name         string `json:"name,omitempty"`
	JWT          string `json:"jwt"`
	RefreshToken string `json:"refresh_token,omitempty"`
	DCID         string `json:"dc_id,omitempty"`
	GroupID      string `json:"group_id,omitempty"`
	// Local maintenance state.
	LastCheckinDay string `json:"last_checkin_day,omitempty"`
	Credits        int64  `json:"credits,omitempty"`
	CreditsTotal   int64  `json:"credits_total,omitempty"`
}

// ParseCredential accepts a normalized flat line or a camelCase one, with or
// without the "Cloud-IDE-JWT " prefix on the token.
func ParseCredential(raw string) (*Credential, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("trae: empty key line")
	}
	if !strings.HasPrefix(raw, "{") {
		return nil, fmt.Errorf("trae: key line must be one account JSON object")
	}

	cred := &Credential{}
	if err := json.Unmarshal([]byte(raw), cred); err == nil && cred.JWT != "" {
		return normalizeCredential(cred), nil
	}

	var camel struct {
		UID            string `json:"uid"`
		UserID         string `json:"userId"`
		Name           string `json:"name"`
		UserName       string `json:"userName"`
		JWT            string `json:"jwt"`
		CloudIdeJWT    string `json:"cloudIdeJwt"`
		RefreshToken   string `json:"refreshToken"`
		DCID           string `json:"dcId"`
		GroupID        string `json:"groupId"`
		LastCheckinDay string `json:"lastCheckinDay"`
		Credits        int64  `json:"credits"`
		CreditsTotal   int64  `json:"creditsTotal"`
	}
	if err := json.Unmarshal([]byte(raw), &camel); err != nil {
		return nil, fmt.Errorf("trae: unmarshal key: %w", err)
	}
	name := camel.Name
	if name == "" {
		name = camel.UserName
	}
	out := &Credential{
		UID:            camel.UID,
		Name:           name,
		JWT:            camel.JWT,
		RefreshToken:   camel.RefreshToken,
		DCID:           camel.DCID,
		GroupID:        camel.GroupID,
		LastCheckinDay: camel.LastCheckinDay,
		Credits:        camel.Credits,
		CreditsTotal:   camel.CreditsTotal,
	}
	if out.JWT == "" {
		out.JWT = camel.CloudIdeJWT
	}
	if out.UID == "" {
		out.UID = camel.UserID
	}
	if out.JWT == "" {
		return nil, fmt.Errorf("trae: credential has no jwt")
	}
	return normalizeCredential(out), nil
}

func normalizeCredential(c *Credential) *Credential {
	c.JWT = StripJWTPrefix(c.JWT)
	c.UID = strings.TrimSpace(c.UID)
	if c.UID == "" {
		c.UID = JWTUserID(c.JWT)
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

// StripJWTPrefix removes the "Cloud-IDE-JWT " / "Bearer " prefix.
func StripJWTPrefix(token string) string {
	t := strings.TrimSpace(token)
	if v, ok := strings.CutPrefix(t, "Cloud-IDE-JWT "); ok {
		return strings.TrimSpace(v)
	}
	if v, ok := strings.CutPrefix(t, "Bearer "); ok {
		return strings.TrimSpace(v)
	}
	return t
}

// AuthHeader returns the Authorization value for Trae's own API (prefixed).
func (c *Credential) AuthHeader() string {
	return "Cloud-IDE-JWT " + StripJWTPrefix(c.JWT)
}

// Device returns the account's stable device triple.
func (c *Credential) Device() Device {
	return DeriveDevice(c.UID)
}

// MachineID is the deterministic machine identity for the account.
func (c *Credential) MachineID() string {
	return SeededHex(64, c.UID, "mach")
}

// NeedsRefresh is true when the JWT expires within 24 hours.
func (c *Credential) NeedsRefresh() bool {
	exp := JWTExpiry(c.JWT)
	if exp <= 0 {
		return false
	}
	return time.Until(time.Unix(exp, 0)) < 24*time.Hour
}

// jwtPayload is the decoded JWT body.
type jwtPayload struct {
	Exp    int64  `json:"exp"`
	Sub    string `json:"sub"`
	AuthID string `json:"auth_id"`
	Data   struct {
		ID string `json:"id"`
	} `json:"data"`
}

func decodeJWT(token string) (*jwtPayload, error) {
	parts := strings.Split(StripJWTPrefix(token), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("trae: malformed jwt")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some issuers pad with standard base64.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("trae: jwt payload decode: %w", err)
		}
	}
	var out jwtPayload
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, fmt.Errorf("trae: jwt payload parse: %w", err)
	}
	return &out, nil
}

// JWTExpiry returns the token expiry, or 0 when it cannot be read.
func JWTExpiry(token string) int64 {
	p, err := decodeJWT(token)
	if err != nil {
		return 0
	}
	return p.Exp
}

// JWTUserID returns the account uid carried by the token, if any.
func JWTUserID(token string) string {
	p, err := decodeJWT(token)
	if err != nil {
		return ""
	}
	if p.Data.ID != "" {
		return p.Data.ID
	}
	if p.AuthID != "" {
		return p.AuthID
	}
	return p.Sub
}

// modelConfig maps a client model id to Trae's (config_name, model_name).
// An unknown model is passed through as "<model>__dev", which is the observed
// upstream convention for newly listed models.
func modelConfig(model string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(model)) {
	case "doubao-seed-evolving":
		return "Doubao-Seed-Evolving", "Doubao-Seed-Evolving__dev"
	case "doubao-seed-2.1-pro", "seed-code-pro-0430":
		return "Doubao-Seed-2.1-Pro", "Doubao-Seed-2.1-Pro__dev"
	case "doubao-seed-2.1-turbo":
		return "Doubao-Seed-2.1-Turbo", "Doubao-Seed-2.1-Turbo__dev"
	case "doubao-seed-code":
		return "Doubao-Seed-Code", "Doubao-Seed-Code__dev"
	case "glm-5.3-flash":
		return "glm-5.3-flash", "glm-5.3-flash__dev"
	case "qwen3.8-flash":
		return "qwen3.8-flash", "qwen3.8-flash__dev"
	case "glm-5.2":
		return "glm-5.2", "glm-5.2__dev"
	case "glm-5.3":
		return "glm-5.3", "glm-5.3__dev"
	case "glm-5":
		return "glm-5", "glm-5__dev"
	case "glm-5-turbo":
		return "glm-5-turbo", "glm-5-turbo__dev"
	case "deepseek-v4.1-flash":
		return "deepseek-v4.1-flash", "deepseek-v4.1-flash__dev"
	case "deepseek-v4-flash":
		return "DeepSeek-V4-Flash", "deepseek_v4_flash__dev"
	case "deepseek-v4-flash-official":
		return "DeepSeek-V4-Flash-Official", "DeepSeek-V4-Flash-Official__dev"
	case "deepseek-v4-pro":
		return "DeepSeek-V4-Pro", "deepseek_v4_pro__dev"
	case "deepseek-v4-pro-official":
		return "DeepSeek-V4-Pro-Official", "DeepSeek-V4-Pro-Official__dev"
	case "kimi-k2.6":
		return "kimi-k2.6", "kimi-k2.6__dev"
	case "kimi-k2.7-code":
		return "kimi-k2.7-code", "kimi-k2.7-code__dev"
	case "kimi-k2.8-preview":
		return "kimi-k2.8-preview", "kimi-k2.8-preview__dev"
	case "kimi-k3":
		return "kimi-k3", "kimi-k3__dev"
	case "minimax-m3":
		return "minimax-m3", "minimax-m3__dev"
	case "qwen3.8-max":
		return "qwen3.8-max", "qwen3.8-max__dev"
	case "qwen-3.7-plus":
		return "qwen-3.7-plus", "qwen-3.7-plus__dev"
	default:
		c := strings.TrimSpace(model)
		return c, c + "__dev"
	}
}

// DefaultModels is the fallback model catalog for the channel UI.
var DefaultModels = []string{
	"deepseek-v4-flash", "deepseek-v4-pro", "deepseek-v4.1-flash", "glm-5.3",
	"glm-5.2", "kimi-k3", "kimi-k2.7-code", "minimax-m3", "qwen3.8-max",
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

// ReplaceCredentialLine swaps the account line a relay used for the rotated
// credential, keeping every other account in the pool.
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
