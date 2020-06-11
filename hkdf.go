package hkdf

import (
	"bytes"
	"crypto/hmac"
	"hash"
	"math"
)

func HKDF(h func() hash.Hash, salt, ikm, info []byte, l int) (prk, okm []byte) {
	if salt == nil {
		salt = bytes.Repeat([]byte{0x00}, 20)
	}
	f := hmac.New(h, salt)
	f.Write(ikm)
	prk = f.Sum(nil)
	hl := len(prk)
	okm = make([]byte, l, l)
	f = hmac.New(h, prk)
	for i := uint8(1); i <= uint8(math.Ceil(float64(l)/float64(hl))); i++ {
		s := int(i-2) * hl
		e := int(i-1) * hl
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
