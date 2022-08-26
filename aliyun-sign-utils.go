package aysign

import (
	"net/url"
	"fmt"
	"time"
	"strings"
)

type CommonParams struct {
	Format  string
	Version string
	SignatureMethod string
}

func CreateParamsWithSignature(accessKeyId, accessSecret, method string, commonParams CommonParams, apiParams map[string]string, dumpingStrToSign ...bool) (params url.Values) {
	var format, signatureMethod string
	if strings.ToUpper(commonParams.Format) == "XML" {
		format = "XML"
	} else {
		format = "JSON"
	}
	if len(commonParams.SignatureMethod) > 0 {
		signatureMethod = commonParams.SignatureMethod
	} else {
		signatureMethod = "HMAC-SHA1"
	}

	now := time.Now()
	params = url.Values{}
	params.Set("Format", format)
	params.Set("Version", commonParams.Version)
	params.Set("AccessKeyId", accessKeyId)
	params.Set("SignatureMethod", signatureMethod)
	params.Set("Timestamp", now.UTC().Format("2006-01-02T15:04:05Z"))
	params.Set("SignatureVersion", "1.0")
	params.Set("SignatureNonce", fmt.Sprintf("%d", now.UnixNano()))

	for k, v := range apiParams {
		params.Set(k, v)
	}

	signature := HmacSignToB64(signatureMethod, method, accessSecret, params, dumpingStrToSign...)
	params.Set("Signature", signature)

	return
}
