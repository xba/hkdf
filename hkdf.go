// HKDF implements the HMAC-based Extract-and-Expand Key Derivation Function.
package hkdf

import (
	"bytes"
	"crypto/hmac"
	"hash"
	"math"
)

// Hash is a helper struct for passing to HKDF. HKDF needs to know the output
// length (in bytes) of your hash.Hash function before running. If the 'salt'
// parameter to HKDF is nil, a string of 0 bytes of length Len are used as the
// salt.
type Hash struct {
	Hash func() hash.Hash
	Len  int
}

// HKDF computes a PKM and OKM (where OKM is `l` bytes long) from the provided
// parameters. If `salt` is nil, a string of `0x00` bytes of length `h.Len` are
// used as the salt. If do not want a salt at all, just use `[]byte{}` as the
// `salt` parameter.
func HKDF(h Hash, salt, ikm, info []byte, l int) (prk, okm []byte) {
	if salt == nil {
		salt = bytes.Repeat([]byte{0x00}, h.Len)
	}
	f := hmac.New(h.Hash, salt)
	f.Write(ikm)
	prk = f.Sum(nil)
	okm = make([]byte, l, l)
	f = hmac.New(h.Hash, prk)
	for i := uint8(1); i <= uint8(math.Ceil(float64(l)/float64(h.Len))); i++ {
		s := int(i-2) * h.Len
		e := int(i-1) * h.Len
		if i != 1 {
			f.Write(okm[s:e])
		}
		f.Write(info)
		f.Write([]byte{i})
		copy(okm[e:], f.Sum(nil))
		f.Reset()
	}
	return
}
