package hkdf

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestExtract(t *testing.T) {
	prk := extract(
		sha256.New,
		// salt
		[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c},
		// ikm
		[]byte{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b},
	)

	okm := expand(
		sha256.New,
		prk,
		[]byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9},
		42,
	)

	/*
		prk := extract(
			sha256.New,
			nil,
			[]byte{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
				0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
				0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b},
		)

		okm := expand(
			sha256.New,
			prk,
			nil,
			42,
		)
	*/

	fmt.Printf("%x\n%x\n", prk, okm)
}