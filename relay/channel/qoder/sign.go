package qoder

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// COSY_VERSION aligns with the official qodercli build the reference
// implementation targets.
const CosyVersion = "1.1.75"

const cosyUserAgent = "undici"
const cosyClientType = "5"
const defaultUserType = "personal_professional_trial"

const cosyMachineOS = "x86_64_linux"

// serverPubPEM is the official Qoder RSA public key, hardcoded from the
// client. It wraps the 16-byte session AES key; the server holds the private
// half. 1024-bit — short, but the ciphertext only ever flows up to the
// official server, so the client side has no decryption oracle to exploit.
const serverPubPEM = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----`

var serverPub = parseServerPub()

func parseServerPub() *rsa.PublicKey {
	block, _ := pem.Decode([]byte(serverPubPEM))
	if block == nil {
		panic("qoder: bad embedded RSA public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("qoder: parse RSA public key: " + err.Error())
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		panic("qoder: embedded key is not RSA")
	}
	return rsaPub
}

// Qoder custom Base64 variant (outbound request body encoding).
var (
	stdAlphabet    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	customAlphabet = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!"
	encodeTable    = make(map[byte]byte, 65)
	decodeTable    = make(map[byte]byte, 65)
)

func init() {
	for i := 0; i < 64; i++ {
		encodeTable[stdAlphabet[i]] = customAlphabet[i]
		decodeTable[customAlphabet[i]] = stdAlphabet[i]
	}
	encodeTable['='] = '$'
	decodeTable['$'] = '='
}

// QoderEncode encodes raw bytes into the Qoder custom Base64 variant:
// standard base64, three-way segment rotation (n/3 boundary), then the
// alphabet map with '=' -> '$'.
func QoderEncode(plain []byte) string {
	std := base64.StdEncoding.EncodeToString(plain)
	n := len(std)
	a := n / 3
	rearranged := std[n-a:] + std[a:n-a] + std[:a]
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = encodeTable[rearranged[i]]
	}
	return string(out)
}

// QoderDecode reverses QoderEncode.
func QoderDecode(encoded string) ([]byte, error) {
	std := make([]byte, len(encoded))
	for i := 0; i < len(encoded); i++ {
		c, ok := decodeTable[encoded[i]]
		if !ok {
			return nil, fmt.Errorf("qoder: invalid base64 char %q", encoded[i])
		}
		std[i] = c
	}
	n := len(std)
	a := n / 3
	// forward: rearranged = std[n-a:] + std[a:n-a] + std[:a]; inverse: std = r3 + r2 + r1
	r1, r2, r3 := std[:a], std[a:n-a], std[n-a:]
	original := string(r3) + string(r2) + string(r1)
	return base64.StdEncoding.DecodeString(original)
}

// jsonSortedCompactStrings builds the exact byte string the server signs
// against: keys sorted, `"k":"v"` pairs joined by commas, no whitespace. All
// leaf values in the signed structures are strings, so this matches Python's
// json.dumps(..., ensure_ascii=False) byte-for-byte for the real inputs.
func jsonSortedCompactStrings(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b := strings.Builder{}
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(jsonString(k))
		b.WriteByte(':')
		b.WriteString(jsonString(m[k]))
	}
	b.WriteByte('}')
	return b.String()
}

// jsonString is a minimal JSON string encoder: escapes " and \ plus C0
// control chars, leaves everything else (incl. non-ASCII) verbatim.
func jsonString(s string) string {
	if !needsJSONEscape(s) {
		return `"` + s + `"`
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func needsJSONEscape(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == '"' || c == '\\' {
			return true
		}
	}
	return false
}

// CosySession is a per-account COSY signing context. tempKey/cosyKey/info are
// generated once per access token and regenerated whenever the token rotates.
type CosySession struct {
	UID       string
	MachineID string
	MachToken string
	MachType  string
	Hostname  string
	Info      string // base64 AES-CBC encrypted identity
	CosyKey   string // base64 RSA-wrapped temp key
	tempKey   []byte
}

// NewCosySession builds the signing context for one Qoder account.
func NewCosySession(cred *Credential) *CosySession {
	uid := cred.UID
	// 16 hex chars (uuid4 hex prefix) = 16 ASCII bytes, used as AES key == iv.
	tempKey := make([]byte, 16)
	_, _ = rand.Read(tempKey)

	identity := map[string]string{
		"name":                 cred.Nickname,
		"aid":                  uid,
		"uid":                  uid,
		"yx_uid":               "",
		"organization_id":      cred.OrganizationID,
		"organization_name":    cred.OrganizationName,
		"user_type":            userTypeName(cred.UserType),
		"security_oauth_token": cred.AccessToken,
		"refresh_token":        cred.RefreshToken,
	}
	plain := jsonSortedCompactStrings(identity)
	info := base64.StdEncoding.EncodeToString(aesCBCPadPKCS7(plain, string(tempKey)))

	cosyKey := ""
	if ct, err := rsa.EncryptPKCS1v15(rand.Reader, serverPub, tempKey); err == nil {
		cosyKey = base64.StdEncoding.EncodeToString(ct)
	}

	return &CosySession{
		UID:       uid,
		MachineID: DeriveID(uid, "machine"),
		MachToken: DeriveMachineToken(uid),
		MachType:  DeriveMachineType(uid),
		Hostname:  MachineHostname(uid),
		Info:      info,
		CosyKey:   cosyKey,
		tempKey:   tempKey,
	}
}

// Bearer signs one request: returns the base64 payload, the unix date, and the
// full Authorization value. The signature covers payload, cosyKey, date, the
// (encoded) body, and the /algo-stripped path.
func (s *CosySession) Bearer(body, rawURL string) (string, string, string) {
	path, _ := url.Parse(rawURL)
	p := "/"
	if path != nil {
		p = path.Path
	}
	if p == "" {
		p = "/"
	}
	if strings.HasPrefix(p, "/algo") {
		p = strings.TrimPrefix(p, "/algo")
	}

	reqID := fnvRequestID()
	payload := jsonSortedCompactStrings(map[string]string{
		"cosyVersion": CosyVersion,
		"ideVersion":  "",
		"info":        s.Info,
		"requestId":   reqID,
		"version":     "v1",
	})
	payloadB64 := base64.StdEncoding.EncodeToString([]byte(payload))
	date := strconv.FormatInt(time.Now().Unix(), 10)

	raw := strings.Join([]string{payloadB64, s.CosyKey, date, body, p}, "\n")
	sum := md5.Sum([]byte(raw))
	sig := hex.EncodeToString(sum[:])
	return payloadB64, date, "Bearer COSY." + payloadB64 + "." + sig
}

// Headers builds the full COSY header table for one inference/model call.
func (s *CosySession) Headers(body, rawURL, modelKey string, sse bool) map[string]string {
	_, date, bearer := s.Bearer(body, rawURL)
	h := map[string]string{
		"cosy-data-policy":      "agree",
		"content-type":          "application/json",
		"cosy-business-product": "cli",
		"cosy-business-type":    "agent",
		"cosy-scene":            "assistant",
		"cosy-clienttype":       cosyClientType,
		"cosy-date":             date,
		"cosy-user":             s.UID,
		"cosy-key":              s.CosyKey,
		"accept":                "text/event-stream",
		"authorization":         bearer,
		"accept-encoding":       "identity",
		"cosy-version":          CosyVersion,
		"cosy-machineid":        s.MachineID,
		"cosy-machinetoken":     s.MachToken,
		"cosy-machinetype":      s.MachType,
		"cosy-clientip":         "169.254.198.161",
		"login-version":         "v2",
		"user-agent":            cosyUserAgent,
		"cosy-machineos":        cosyMachineOS,
	}
	if sse {
		h["cosy-machinehostname"] = s.Hostname
		h["cache-control"] = "no-cache"
	}
	if modelKey != "" {
		h["x-model-key"] = modelKey
		h["x-model-source"] = "system"
	}
	return h
}

func userTypeName(t string) string {
	if t == "" {
		return defaultUserType
	}
	return t
}

// fnvRequestID gives a per-request random id without pulling in uuid: 32 hex
// chars from SHA-256 of 16 random bytes, formatted as a dashed UUIDv4.
func fnvRequestID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	d := sha256.Sum256(buf)
	h := hex.EncodeToString(d[:])
	return h[0:8] + "-4" + h[9:13] + "-a" + h[13:17] + "-" + h[17:21] + "-" + h[21:33]
}

// aesCBCPadPKCS7 encrypts plain with AES-128-CBC, key == iv == secret.
func aesCBCPadPKCS7(plain, secret string) []byte {
	key := []byte(secret)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("qoder: aes key: " + err.Error())
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	data := append([]byte(plain), make([]byte, pad)...)
	for i := len(plain); i < len(data); i++ {
		data[i] = byte(pad)
	}
	c := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, key).CryptBlocks(c, data)
	return c
}
