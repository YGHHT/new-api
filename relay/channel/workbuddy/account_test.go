package workbuddy

import (
	"testing"
)

func TestClassifyCheckin(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		status     int
		wantState  string
		wantCredit int
	}{
		{"fresh", `{"credit":100,"streak_days":44}`, 200, "checked", 100},
		{"idempotent", `{"code":10001,"msg":"今天已签到，请明天再来"}`, 400, "already", 0},
		{"pending", `{"code":429,"msg":"请求处理中，请勿重复操作"}`, 429, "pending", 0},
		{"failed", `{"code":10001,"msg":"签到失败，已签到天数不足 7 天"}`, 400, "failed", 0},
		{"envelope-success", `{"code":0,"data":{"credit":30,"streak_days":2}}`, 200, "checked", 30},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyCheckin([]byte(tc.raw), tc.status, nil)
			if got.State != tc.wantState {
				t.Fatalf("state = %q, want %q (message=%q)", got.State, tc.wantState, got.Message)
			}
			if tc.wantCredit > 0 && (!got.CreditKnown || got.Credit != tc.wantCredit) {
				t.Fatalf("credit = %d (known=%v), want %d", got.Credit, got.CreditKnown, tc.wantCredit)
			}
		})
	}
}

func TestClassifyCheckinAlreadyWinsOverSuccess(t *testing.T) {
	// code=0 but the message says it was already checked in: idempotent, no
	// credit was granted this time.
	got := classifyCheckin([]byte(`{"code":0,"msg":"今天已签到"}`), 200, nil)
	if got.State != "already" {
		t.Fatalf("state = %q, want already", got.State)
	}
	if got.CreditKnown {
		t.Fatal("already-checked response must not report a granted credit")
	}
}

func TestResolveSite(t *testing.T) {
	if got := ResolveSite("intl"); got.ID != "intl" || got.Realm != "global" {
		t.Fatalf("intl site = %+v", got)
	}
	if got := ResolveSite("workbuddy"); got.API != SiteWorkBuddy.API {
		t.Fatalf("workbuddy site = %+v", got)
	}
	if got := ResolveSite(""); got.ID != "cn" {
		t.Fatalf("default site = %+v", got)
	}
	if got := ResolveSiteByRealm("global"); got.ID != "workbuddy" {
		t.Fatalf("global realm site = %+v", got)
	}
}

func TestCheckinPaths(t *testing.T) {
	cn := &Credential{Realm: "cn"}
	if paths := checkinPaths(cn); len(paths) != 1 || paths[0] != "/v2/billing/meter/daily-checkin" {
		t.Fatalf("cn checkin paths = %v", paths)
	}
	global := &Credential{Realm: "global", Domain: "www.codebuddy.ai"}
	paths := checkinPaths(global)
	if len(paths) != 2 || paths[0] != "/billing/meter/daily-checkin" {
		t.Fatalf("global checkin paths = %v", paths)
	}
}

func TestValidUID(t *testing.T) {
	for _, ok := range []string{"u1", "abc-DEF_123", "00000001"} {
		if !validUID(ok) {
			t.Fatalf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "../evil", "a/b", "a b", "中文"} {
		if validUID(bad) {
			t.Fatalf("%q should be rejected", bad)
		}
	}
}

func TestDeviceHeaders(t *testing.T) {
	h := deviceStateHeaders(SiteCN)
	if h["X-Domain"] != "www.workbuddy.cn" {
		t.Fatalf("state X-Domain = %q", h["X-Domain"])
	}
	if h["Content-Type"] != "application/json" {
		t.Fatal("auth/state must send Content-Type")
	}
	if h["X-No-Authorization"] != "true" {
		t.Fatal("auth/state must mark no-authorization")
	}
	th := tokenHeaders(SiteCN)
	if _, ok := th["X-Domain"]; ok {
		t.Fatal("auth/token must not send X-Domain")
	}
	if _, ok := th["Content-Type"]; ok {
		t.Fatal("auth/token must not send Content-Type")
	}
	ah := accountHeaders(SiteCN, "tok")
	if ah["Authorization"] != "Bearer tok" {
		t.Fatalf("account Authorization = %q", ah["Authorization"])
	}
}
