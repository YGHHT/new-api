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
