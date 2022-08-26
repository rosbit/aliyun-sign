package aysign

import (
	"encoding/base64"
	"crypto/sha256"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/md5"
	"io"
	"os"
	"fmt"
	"hash"
	"net/url"
)

var (
	signMethodMap = map[string]func()hash.Hash{
		"HMAC-SHA1":   sha1.New,
		"HMAC-SHA256": sha256.New,
		"HMAC-MD5":    md5.New,
	}
)

func HmacSign(signMethod string, httpMethod string, appKeySecret string, vals url.Values, dumpingStrToSign ...bool) (signature []byte) {
	key := []byte(appKeySecret+"&")

	var h hash.Hash
	if method, ok := signMethodMap[signMethod]; ok {
		h = hmac.New(method, key)
	} else {
		h = hmac.New(sha1.New, key)
	}
	makeDataToSign(h, httpMethod, vals, dumpingStrToSign...)
	return h.Sum(nil)
}

func HmacSignToB64(signMethod string, httpMethod string, appKeySecret string, vals url.Values, dumpingStrToSign ...bool) (signature string) {
	return base64.StdEncoding.EncodeToString(HmacSign(signMethod, httpMethod, appKeySecret, vals, dumpingStrToSign...))
}

type strToEnc struct {
	s string // string to encode
	e bool   // encoding needed?
}

func makeDataToSign(w io.Writer, httpMethod string, vals url.Values, dumpingStrToSign ...bool) {
	in := make(chan *strToEnc)
	go func() {
		in <- &strToEnc{s:httpMethod}
		in <- &strToEnc{s:"&"}
		in <- &strToEnc{s:"/", e:true}
		in <- &strToEnc{s:"&"}
		in <- &strToEnc{s:vals.Encode(), e:true}
		close(in)
	}()

	if len(dumpingStrToSign) == 0 || !dumpingStrToSign[0] {
		specialUrlEncode(in, w)
	} else {
		mw, deferFunc := dumpStrToSign(w)
		defer deferFunc()
		specialUrlEncode(in, mw)
	}
}

var (
	encTilde = fmt.Sprintf("%%%02X", '~') // "%7E"
	tilde    = []byte("~")
)

func dumpStrToSign(w io.Writer) (mw io.Writer, deferFunc func()) {
	fmt.Fprintf(os.Stderr, "----- strToSign begin -----\n")
	deferFunc = func() {
		fmt.Fprintf(os.Stderr, "\n----- strToSign end -----\n")
	}
	mw = io.MultiWriter(w, os.Stderr)
	return
}

func specialUrlEncode(in <-chan *strToEnc, w io.Writer) {
	for s := range in {
		if !s.e {
			io.WriteString(w, s.s)
			continue
		}

		l := len(s.s)
		for i:=0; i<l; {
			ch := s.s[i]

			switch ch {
			case '%':
				if encTilde == s.s[i:i+3] {
					w.Write(tilde)
					i += 3
					continue
				}
				fallthrough
			case '*', '/', '&', '=':
				fmt.Fprintf(w, "%%%02X", ch)
			case '+':
				fmt.Fprintf(w, "%%%02X%02X", '%', ' ')  // '+' -> "%20" -> "%2520"
			default:
				fmt.Fprintf(w, "%c", ch)
			}

			i += 1
		}
	}
}
