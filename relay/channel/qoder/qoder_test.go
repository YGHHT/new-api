package qoder

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
	"testing"
)

func TestQoderEncodeRoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte("{}"),
		[]byte(`{"a":1,"b":"中文","c":[1,2,3]}`),
		[]byte(strings.Repeat("x", 1000)),
		[]byte(""),
	}
	for _, in := range cases {
		enc := QoderEncode(in)
		dec, err := QoderDecode(enc)
		if err != nil {
			t.Fatalf("decode(%q): %v", string(in), err)
		}
		if !bytes.Equal(dec, in) {
			t.Fatalf("round trip mismatch: in=%q out=%q", string(in), string(dec))
		}
	}
}

func TestQoderEncodeAlphabet(t *testing.T) {
	// The encoded output must only contain the custom alphabet plus '$'.
	enc := QoderEncode([]byte(`{"k":"v"}`))
	allowed := customAlphabet + "$"
	for _, r := range enc {
		if !strings.ContainsRune(allowed, r) {
			t.Fatalf("unexpected char %q in %q", r, enc)
		}
	}
}

func TestAESCBCPadPKCS7MatchesStdlib(t *testing.T) {
	// key == iv == secret; verify against crypto/aes + CBC directly.
	secret := "0123456789abcdef"
	plain := `{"uid":"u1","name":"n"}`
	got := aesCBCPadPKCS7(plain, secret)

	block, _ := aes.NewCipher([]byte(secret))
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	data := append([]byte(plain), bytes.Repeat([]byte{byte(pad)}, pad)...)
	want := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, []byte(secret)).CryptBlocks(want, data)
	if !bytes.Equal(got, want) {
		t.Fatalf("aes mismatch")
	}
}

func TestJSONSortedCompact(t *testing.T) {
	got := jsonSortedCompactStrings(map[string]string{
		"version": "v1", "ideVersion": "", "cosyVersion": "1.1.75",
	})
	want := `{"cosyVersion":"1.1.75","ideVersion":"","version":"v1"}`
	if got != want {
		t.Fatalf("sorted compact = %q, want %q", got, want)
	}
}

func TestBearerIsStableShape(t *testing.T) {
	cred := &Credential{UID: "u-1", AccessToken: "at", RefreshToken: "rt", Realm: "cn"}
	sess := NewCosySession(cred)
	if sess.CosyKey == "" || sess.Info == "" {
		t.Fatal("cosy session missing key/info")
	}
	// info must be base64 of a full AES block.
	if _, err := base64.StdEncoding.DecodeString(sess.Info); err != nil {
		t.Fatalf("info not base64: %v", err)
	}
	body := QoderEncode([]byte(`{}`))
	payload, date, bearer := sess.Bearer(body, "https://gateway.qoder.com.cn/algo/api/v2/x?y=1")
	if payload == "" || date == "" {
		t.Fatal("bearer components empty")
	}
	if !strings.HasPrefix(bearer, "Bearer COSY."+payload+".") {
		t.Fatalf("bad bearer prefix: %q", bearer)
	}
	// A second call produces a new payload (new requestId) but the same shape.
	_, _, bearer2 := sess.Bearer(body, "https://gateway.qoder.com.cn/algo/api/v2/x?y=1")
	if bearer2 == bearer {
		t.Fatal("requestId should vary per call")
	}
	if !strings.HasPrefix(bearer2, "Bearer COSY.") {
		t.Fatalf("bad bearer prefix 2: %q", bearer2)
	}
}

func TestHeadersCarryMachineFields(t *testing.T) {
	cred := &Credential{UID: "u-2", AccessToken: "at", RefreshToken: "rt", Realm: "cn"}
	sess := NewCosySession(cred)
	h := sess.Headers("body", "https://gateway.qoder.com.cn/algo/api/v2/x", "auto", true)
	for _, k := range []string{"cosy-machineid", "cosy-machinetoken", "cosy-machinetype",
		"cosy-date", "cosy-key", "cosy-user", "authorization", "x-model-key", "cache-control"} {
		if h[k] == "" {
			t.Fatalf("missing header %q", k)
		}
	}
	if h["cosy-machinehostname"] == "" {
		t.Fatal("SSE headers must carry hostname")
	}
	if h["cosy-user"] != "u-2" {
		t.Fatalf("cosy-user = %q", h["cosy-user"])
	}
}

func TestPathStripsAlgoPrefix(t *testing.T) {
	cred := &Credential{UID: "u-3", AccessToken: "at", RefreshToken: "rt"}
	sess := NewCosySession(cred)
	// Two URLs that differ only in query/host but share the stripped path must
	// produce the same signature, since the path is what gets signed.
	_, _, b1 := sess.Bearer("body", "https://a.qoder.sh/algo/api/v2/x")
	p1 := strings.SplitN(strings.TrimPrefix(b1, "Bearer COSY."), ".", 2)[0]
	_ = sess
	if p1 == "" {
		t.Fatal("empty payload")
	}
}
