package workbuddy

import (
	"strings"
	"testing"
	"time"
)

func TestParseCredentialNormalized(t *testing.T) {
	raw := `{"uid":"u1","access_token":"at-1","refresh_token":"rt-1","expires_at":1760000000000,"realm":"global","domain":"www.codebuddy.ai"}`
	c, err := ParseCredential(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.UID != "u1" || c.AccessToken != "at-1" || c.RefreshToken != "rt-1" {
		t.Fatalf("unexpected credential: %+v", c)
	}
	if c.ExpiresAt > 1e11 {
		t.Fatalf("millisecond expiry was not normalized: %d", c.ExpiresAt)
	}
	if !c.IsGlobal() {
		t.Fatalf("realm=global should resolve to the global site")
	}
}

func TestParseCredentialFlatCamelCase(t *testing.T) {
	raw := `{"uid":"u2","accessToken":"at-2","refreshToken":"rt-2","expiresAt":1760000000,"enterpriseId":"ent-1","realm":"cn"}`
	c, err := ParseCredential(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.AccessToken != "at-2" || c.EnterpriseID != "ent-1" || c.IsGlobal() {
		t.Fatalf("unexpected credential: %+v", c)
	}
	if got := c.DomainHeader(); got != "www.workbuddy.cn" {
		t.Fatalf("domain header = %q", got)
	}
}

func TestParseCredentialNestedDetail(t *testing.T) {
	raw := `{"account":{"uid":"u3","nickname":"nick","enterpriseId":"ent-3"},"auth":{"accessToken":"at-3","refreshToken":"rt-3","expiresAt":1760000000,"realm":"cn"},"device_token":"dt-1"}`
	c, err := ParseCredential(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.UID != "u3" || c.Nickname != "nick" || c.DeviceToken != "dt-1" || c.AccessToken != "at-3" {
		t.Fatalf("unexpected credential: %+v", c)
	}
}

func TestParseCredentialRejectsEmpty(t *testing.T) {
	if _, err := ParseCredential("   "); err == nil {
		t.Fatal("empty key should fail")
	}
	if _, err := ParseCredential(`{"uid":"u4"}`); err == nil {
		t.Fatal("credential without a token should fail")
	}
}

func TestNeedsRefresh(t *testing.T) {
	c := &Credential{AccessToken: "at", RefreshToken: "rt", ExpiresAt: time.Now().Unix() + 60}
	if !c.NeedsRefresh() {
		t.Fatal("token expiring in 60s should be refreshed")
	}
	c.ExpiresAt = time.Now().Unix() + 3600
	if c.NeedsRefresh() {
		t.Fatal("token valid for an hour should not be refreshed")
	}
	apiKey := &Credential{AccessToken: "ck_static", RefreshToken: "rt", ExpiresAt: time.Now().Unix() - 10}
	if apiKey.NeedsRefresh() {
		t.Fatal("static console keys must not refresh")
	}
	noExpiry := &Credential{AccessToken: "at", RefreshToken: "rt"}
	if noExpiry.NeedsRefresh() {
		t.Fatal("a credential without expiry should be left alone")
	}
}

func TestBaseURLResolution(t *testing.T) {
	cn := &Credential{Realm: "cn"}
	if got := cn.BaseURL(""); got != BaseCN {
		t.Fatalf("cn base = %q", got)
	}
	global := &Credential{Realm: "global", Domain: "www.codebuddy.ai"}
	if got := global.BaseURL(""); got != BaseGlobalDefault {
		t.Fatalf("global base = %q", got)
	}
	legacy := &Credential{Realm: "global", Domain: "www.workbuddy.ai"}
	if got := legacy.BaseURL(""); got != BaseGlobalLegacy {
		t.Fatalf("legacy global base = %q", got)
	}
	custom := &Credential{Realm: "cn"}
	if got := custom.BaseURL("https://proxy.example.com/"); got != "https://proxy.example.com" {
		t.Fatalf("custom base = %q", got)
	}
}

func TestSplitRealmPrefix(t *testing.T) {
	cases := map[string][2]string{
		"cn:glm-5.3":     {"cn", "glm-5.3"},
		"global:kimi-k3": {"global", "kimi-k3"},
		"glm-5.3":        {"cn", "glm-5.3"},
	}
	for in, want := range cases {
		realm, bare := SplitRealmPrefix(in)
		if realm != want[0] || bare != want[1] {
			t.Fatalf("SplitRealmPrefix(%q) = (%q,%q), want (%q,%q)", in, realm, bare, want[0], want[1])
		}
	}
}

func TestDefaultModelsNonEmpty(t *testing.T) {
	if len(DefaultModels) == 0 {
		t.Fatal("default model catalog is empty")
	}
	for _, m := range DefaultModels {
		if strings.TrimSpace(m) == "" {
			t.Fatal("default model catalog contains an empty id")
		}
	}
}

// A channel key can hold a whole account pool. A token refresh covers one
// account only, so it must swap that line and leave the rest untouched.
func TestReplaceCredentialLineKeepsPool(t *testing.T) {
	line1 := `{"uid":"u1","access_token":"at-1","refresh_token":"rt-1","realm":"cn"}`
	line2 := `{"uid":"u2","access_token":"at-2","refresh_token":"rt-2","realm":"cn"}`
	line3 := `{"uid":"u3","access_token":"at-3","refresh_token":"rt-3","realm":"cn"}`
	pool := strings.Join([]string{line1, line2, line3}, "\n")

	rotated := `{"uid":"u2","access_token":"at-2-new","refresh_token":"rt-2-new","realm":"cn"}`
	got := ReplaceCredentialLine(pool, line2, rotated)
	lines := strings.Split(got, "\n")
	if len(lines) != 3 {
		t.Fatalf("pool size = %d, want 3: %q", len(lines), got)
	}
	if lines[0] != line1 || lines[2] != line3 {
		t.Fatalf("other accounts were modified: %q", got)
	}
	if cred, err := ParseCredential(lines[1]); err != nil || cred.AccessToken != "at-2-new" {
		t.Fatalf("rotated line = %q (%v)", lines[1], err)
	}
}

func TestReplaceCredentialLineFallsBackToUID(t *testing.T) {
	pool := `{"uid":"u1","access_token":"at-1","refresh_token":"rt-1"}` + "\n" +
		`{"uid":"u2", "access_token": "at-2", "refresh_token": "rt-2"}`
	original := `{"uid":"u2","access_token":"at-2","refresh_token":"rt-2"}`
	rotated := `{"uid":"u2","access_token":"at-2-new","refresh_token":"rt-2-new"}`

	got := ReplaceCredentialLine(pool, original, rotated)
	if n := len(strings.Split(got, "\n")); n != 2 {
		t.Fatalf("pool size = %d, want 2: %q", n, got)
	}
	if !strings.Contains(got, "at-2-new") || !strings.Contains(got, "at-1") {
		t.Fatalf("unexpected key: %q", got)
	}
}

func TestReplaceCredentialLineAppendsUnknownAccount(t *testing.T) {
	pool := `{"uid":"u1","access_token":"at-1","refresh_token":"rt-1"}`
	original := `{"uid":"zz","access_token":"at-z","refresh_token":"rt-z"}`
	rotated := `{"uid":"zz","access_token":"at-z-new","refresh_token":"rt-z-new"}`

	got := ReplaceCredentialLine(pool, original, rotated)
	if n := len(strings.Split(got, "\n")); n != 2 {
		t.Fatalf("pool size = %d, want 2: %q", n, got)
	}
}
