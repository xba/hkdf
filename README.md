# hkdf

[![GoDoc](https://img.shields.io/badge/api-reference-blue.svg)](https://godoc.org/github.com/xba/hkdf)
[![Go Report Card](https://img.shields.io/badge/go%20report-A%2B-green.svg)](https://goreportcard.com/report/github.com/xba/hkdf)
[![Coverage](https://img.shields.io/badge/coverage-100%25-ff69b4.svg)](https://gocover.io/xba/hkdf)

[HMAC-based Extract-and-Expand Key Derivation Function
(HKDF)](https://tools.ietf.org/html/rfc5869) for Go.

## testing

I'm using the test vectors described in the [official IETF HKDF
paper](https://tools.ietf.org/html/rfc5869). You can execute the tests yourself
by running:

```
$ go test
```
