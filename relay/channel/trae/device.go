package trae

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Stable per-account device identity, matching the Trae gateway's derivation
// (SHA-256 counter stream salted by a label). One account always presents the
// same virtual device; different accounts never collide.

func seededStream(seed, salt string, nbytes int) []byte {
	prefix := []byte(salt + ":" + seed)
	out := make([]byte, 0, nbytes+32)
	var counter uint32
	for len(out) < nbytes {
		h := sha256.New()
		h.Write(prefix)
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], counter)
		h.Write(c[:])
		out = append(out, h.Sum(nil)...)
		counter++
	}
	return out[:nbytes]
}

// SeededHex returns n hex chars derived from uid + salt (a machine id).
func SeededHex(n int, uid, salt string) string {
	b := seededStream(uid, salt, (n+1)/2)
	s := hex.EncodeToString(b)
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// Device is the per-account device triple.
type Device struct {
	DeviceID     string
	SessionID    string
	MarketUserID string
}

// DeriveDevice builds the device triple for a uid, matching gen=2.
func DeriveDevice(uid string) Device {
	deviceID := make([]byte, 15)
	for i, b := range seededStream(uid, "devid", 15) {
		deviceID[i] = '0' + b%10
	}
	sess := seededStream(uid, "sess", 32)
	sessionID := hex.EncodeToString(sess)

	m := seededStream(uid, "market", 16)
	m[6] = (m[6] & 0x0F) | 0x40
	m[8] = (m[8] & 0x3F) | 0x80
	market := fmt.Sprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15],
	)
	return Device{DeviceID: string(deviceID), SessionID: sessionID, MarketUserID: market}
}
