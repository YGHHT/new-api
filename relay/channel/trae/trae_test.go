package trae

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func makeJWT(uid string, exp int64) string {
	payload, _ := json.Marshal(map[string]any{"exp": exp, "data": map[string]any{"id": uid}})
	enc := base64.RawURLEncoding.EncodeToString(payload)
	return "aGVhZGVy." + enc + ".c2ln"
}

func TestParseCredentialFlat(t *testing.T) {
	raw := `{"uid":"u1","name":"n","jwt":"abc.def.ghi","refresh_token":"rt","credits":100}`
	cred, err := ParseCredential(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cred.UID != "u1" || cred.JWT != "abc.def.ghi" || cred.RefreshToken != "rt" {
		t.Fatalf("unexpected credential: %+v", cred)
	}
	if cred.Credits != 100 {
		t.Fatalf("credits = %d", cred.Credits)
	}
}

func TestParseCredentialCamelCase(t *testing.T) {
	raw := `{"userId":"u2","userName":"n2","cloudIdeJwt":"Cloud-IDE-JWT a.b.c","refreshToken":"rt2"}`
	cred, err := ParseCredential(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cred.UID != "u2" || cred.Name != "n2" {
		t.Fatalf("unexpected credential: %+v", cred)
	}
	if cred.JWT != "a.b.c" {
		t.Fatalf("jwt prefix not stripped: %q", cred.JWT)
	}
}

func TestParseCredentialRejectsEmpty(t *testing.T) {
	if _, err := ParseCredential("  "); err == nil {
		t.Fatal("empty key should fail")
	}
	if _, err := ParseCredential(`{"uid":"u3"}`); err == nil {
		t.Fatal("credential without a jwt should fail")
	}
}

func TestJWTHelpers(t *testing.T) {
	token := makeJWT("u-9", 4102444800)
	if got := JWTUserID(token); got != "u-9" {
		t.Fatalf("JWTUserID = %q", got)
	}
	if got := JWTExpiry(token); got != 4102444800 {
		t.Fatalf("JWTExpiry = %d", got)
	}
}

func TestStripJWTPrefix(t *testing.T) {
	cases := map[string]string{
		"Cloud-IDE-JWT abc": "abc",
		"Bearer abc":        "abc",
		"abc":               "abc",
		"  abc  ":           "abc",
	}
	for in, want := range cases {
		if got := StripJWTPrefix(in); got != want {
			t.Fatalf("StripJWTPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDeriveDeviceIsStable(t *testing.T) {
	a := DeriveDevice("uid-1")
	b := DeriveDevice("uid-1")
	c := DeriveDevice("uid-2")
	if a != b {
		t.Fatal("device derivation must be stable per uid")
	}
	if a == c {
		t.Fatal("different uids must not share a device")
	}
	if len(a.DeviceID) != 15 {
		t.Fatalf("device id length = %d", len(a.DeviceID))
	}
	for _, r := range a.DeviceID {
		if r < '0' || r > '9' {
			t.Fatalf("device id must be digits, got %q", a.DeviceID)
		}
	}
	if len(a.SessionID) != 64 || len(a.MarketUserID) != 36 {
		t.Fatalf("session/market id shapes: %q %q", a.SessionID, a.MarketUserID)
	}
}

func TestModelConfig(t *testing.T) {
	if c, m := modelConfig("deepseek-v4-flash"); c != "DeepSeek-V4-Flash" || m != "deepseek_v4_flash__dev" {
		t.Fatalf("deepseek mapping = %q,%q", c, m)
	}
	if c, m := modelConfig("kimi-k3"); c != "kimi-k3" || m != "kimi-k3__dev" {
		t.Fatalf("kimi mapping = %q,%q", c, m)
	}
	// An unknown model falls through to the "<model>__dev" convention.
	if c, m := modelConfig("brand-new-model"); c != "brand-new-model" || m != "brand-new-model__dev" {
		t.Fatalf("unknown mapping = %q,%q", c, m)
	}
}

func TestBuildChatBodyAddsRequiredFields(t *testing.T) {
	cred := &Credential{UID: "u-1", JWT: makeJWT("u-1", 4102444800)}
	req := []byte(`{"model":"kimi-k3","messages":[{"role":"user","content":"hi"}],"max_tokens":123}`)
	body, err := buildChatBody(req, cred, "kimi-k3")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{"config_name", "model_name", "stream", "function",
		"max_tokens", "conversation_id", "user_id", "session_id", "device_id",
		"machine_id", "project_id", "workspace_id", "prompt_max_tokens", "mode",
		"ide_version", "app_id", "package_type"} {
		if _, ok := obj[k]; !ok {
			t.Fatalf("missing field %q", k)
		}
	}
	if obj["prompt_max_tokens"].(float64) != 168000 {
		t.Fatalf("prompt_max_tokens = %v", obj["prompt_max_tokens"])
	}
	if obj["stream"] != true {
		t.Fatal("stream must be forced on")
	}
	if obj["max_tokens"].(float64) != 123 {
		t.Fatalf("max_tokens = %v", obj["max_tokens"])
	}
	if obj["user_id"] != "u-1" {
		t.Fatalf("user_id = %v", obj["user_id"])
	}
	// Content strings become text parts.
	msgs := obj["messages"].([]any)
	first := msgs[0].(map[string]any)
	parts := first["content"].([]any)
	p := parts[0].(map[string]any)
	if p["type"] != "text" || p["text"] != "hi" {
		t.Fatalf("content not normalized: %v", first["content"])
	}
}

func TestBuildChatBodyRenamesToolCalls(t *testing.T) {
	cred := &Credential{UID: "u-1", JWT: makeJWT("u-1", 4102444800)}
	req := []byte(`{"model":"kimi-k3","messages":[{"role":"assistant","tool_calls":[{"function":{"name":"f","arguments":"{}"}}]}]}`)
	body, err := buildChatBody(req, cred, "kimi-k3")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var obj map[string]any
	_ = json.Unmarshal(body, &obj)
	msgs := obj["messages"].([]any)
	m := msgs[0].(map[string]any)
	tcs := m["tool_calls"].([]any)
	tc := tcs[0].(map[string]any)
	if _, ok := tc["function_call"]; !ok {
		t.Fatalf("function_call missing: %v", tc)
	}
	if _, ok := tc["function"]; ok {
		t.Fatalf("function should have been renamed: %v", tc)
	}
}

func TestParseSoloEvent(t *testing.T) {
	ev := parseSoloEvent("output", `{"response":"hi","reasoning_content":"think"}`)
	if ev.Response != "hi" || ev.Reasoning != "think" {
		t.Fatalf("output event = %+v", ev)
	}
	ev = parseSoloEvent("done", `{"finish_reason":"length"}`)
	if ev.FinishReason != "length" {
		t.Fatalf("done event = %+v", ev)
	}
	// An unknown finish_reason is normalized to stop.
	ev = parseSoloEvent("turn_completion", `{"finish_reason":"completed"}`)
	if ev.FinishReason != "stop" {
		t.Fatalf("turn_completion finish = %q", ev.FinishReason)
	}
	ev = parseSoloEvent("error", `{"code":4001,"message":"bad"}`)
	if !ev.HasError || ev.ErrorCode != 4001 || ev.ErrorMessage != "bad" {
		t.Fatalf("error event = %+v", ev)
	}
}

func TestNormalizeUsage(t *testing.T) {
	u := normalizeUsage(map[string]any{"prompt_tokens": 10.0, "completion_tokens": 5.0, "total_tokens": 15.0})
	if u["prompt_tokens"].(int64) != 10 || u["completion_tokens"].(int64) != 5 || u["total_tokens"].(int64) != 15 {
		t.Fatalf("usage = %v", u)
	}
	u = normalizeUsage(map[string]any{"input_tokens": 3.0, "output_tokens": 2.0})
	if u["total_tokens"].(int64) != 5 {
		t.Fatalf("total not derived: %v", u)
	}
}

func TestParseFrame(t *testing.T) {
	ev := parseFrame([]byte("event: output\ndata: {\"response\":\"x\"}"))
	if ev == nil || ev.Response != "x" {
		t.Fatalf("frame = %+v", ev)
	}
	if parseFrame([]byte("")) != nil {
		t.Fatal("empty frame should be nil")
	}
}

func TestReplaceCredentialLineKeepsPool(t *testing.T) {
	l1 := `{"uid":"u1","jwt":"a"}`
	l2 := `{"uid":"u2","jwt":"b"}`
	l3 := `{"uid":"u3","jwt":"c"}`
	pool := strings.Join([]string{l1, l2, l3}, "\n")
	rotated := `{"uid":"u2","jwt":"b2"}`
	got := ReplaceCredentialLine(pool, l2, rotated)
	lines := strings.Split(got, "\n")
	if len(lines) != 3 {
		t.Fatalf("pool size = %d: %q", len(lines), got)
	}
	if lines[0] != l1 || lines[2] != l3 {
		t.Fatalf("other accounts changed: %q", got)
	}
}

func TestParseCallbackURL(t *testing.T) {
	cred, err := ParseCallbackURL("http://127.0.0.1:17388/authorize?accessToken=tok&refreshToken=rt&userId=u1&userName=n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cred.JWT != "tok" || cred.RefreshToken != "rt" || cred.UID != "u1" || cred.Name != "n" {
		t.Fatalf("credential = %+v", cred)
	}
}
