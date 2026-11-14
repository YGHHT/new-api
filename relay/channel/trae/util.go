package trae

import (
	"crypto/rand"
)

func cryptoRandRead(b []byte) (int, error) {
	return rand.Read(b)
}

// newHex returns n random bytes hex-encoded (2n chars).
func newHex(n int) string {
	const hexdigits = "0123456789abcdef"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	out := make([]byte, n*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}
