package hkdf

import (
	"bytes"
	"crypto/hmac"
	"hash"
	"math"
)

func extract(h func() hash.Hash, salt, ikm []byte) []byte {
	f := hmac.New(h, salt)
	f.Write(ikm)
	return f.Sum(nil)
}

func expand(h func() hash.Hash, prk, info []byte, l int) []byte {
	n := uint8(math.Ceil(float64(l) / float64(len(prk))))
	okm := &bytes.Buffer{}
	f := hmac.New(h, prk)
	for i := uint8(1); i <= n; i++ {
		if i != 1 {
			f.Write(okm.Bytes()[int(i-2)*len(prk) : int(i-1)*len(prk)])
		}
		f.Write(info)
		f.Write([]byte{i})
		okm.Write(f.Sum(nil))
		f.Reset()
	}
	return okm.Bytes()[:l]
}

func HKDF(h func() hash.Hash, salt, ikm, info []byte, l int) (prk, okm []byte) {
	prk = extract(h, salt, ikm)
	okm = expand(h, prk, info, l)
	return
}
