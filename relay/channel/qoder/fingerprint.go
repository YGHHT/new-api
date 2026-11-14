package qoder

import (
	"crypto/md5"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// Fingerprint derivation mirrors qoder_fingerprint.py: one stable virtual
// device per account UID. The official client ties a machine identity to a
// single account, so a gateway that impersonates many accounts must derive a
// *per-account* identity instead of one process-wide value, or every account
// collapses onto one device and trips the cross-account correlation checks.

// DeriveID produces a hyphenated UUIDv4-shaped identifier from uid + salt.
// The version nibble is forced to 4 and the variant to a so the shape matches
// a real hardware UUID character-for-character (the legacy flat-32-hex form
// was a clusterable gateway fingerprint and is no longer the default).
func DeriveID(uid, salt string) string {
	if uid == "" {
		uid = "anonymous"
	}
	sum := md5sum(salt + ":" + uid)
	h := sum
	// h[:12] + "4" + h[13:16] + "a" + h[17:]
	h = h[:12] + "4" + h[13:16] + "a" + h[17:]
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// DeriveMachineType is the 18-char machine type (hyphens stripped).
func DeriveMachineType(uid string) string {
	v := strings.ReplaceAll(DeriveID(uid, "machinetype"), "-", "")
	if len(v) > 18 {
		v = v[:18]
	}
	return v
}

// DeriveMachineToken is a base64url-style token derived from uid.
func DeriveMachineToken(uid string) string {
	d := sha512.Sum512([]byte("machinetoken:" + uid))
	enc := base64.RawURLEncoding.EncodeToString(d[:])
	if len(enc) > 43 {
		enc = enc[:43]
	}
	return enc
}

// MachineHostname is the stable DESKTOP-XXXXXXXX hostname the SSE path carries.
func MachineHostname(uid string) string {
	sum := md5sum("hostname:" + uid)
	return "DESKTOP-" + strings.ToUpper(sum[:7])
}

func md5sum(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
