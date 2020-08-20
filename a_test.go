package aysign

import (
	"testing"
	"net/url"
	"fmt"
)

func Test_A(t *testing.T) {
	accessKeyId := "testId"
	accessSecret := "testSecret"

	params := url.Values{}
	params.Set("SignatureMethod", "HMAC-SHA1")
	params.Set("SignatureNonce", "b47d4920-e21d-11ea-aaf5-155b68031f52")
	params.Set("AccessKeyId", accessKeyId)
	params.Set("SignatureVersion", "1.0")
	params.Set("Timestamp", "2020-08-19T13:12:59Z")
	params.Set("Format", "JSON")
	params.Set("Action", "SendSms")
	params.Set("Version", "2017-05-25")
	params.Set("RegionId", "cn-hangzhou")
	//params.Set("PhoneNumbers", "15300000001")
	//params.Set("SignName", "阿里云短信测试专用")
	//params.Set("TemplateParam", "{\"customer\":\"test\"}")
	//params.Set("TemplateCode", "SMS_71390007")
	//params.Set("OutId", "123")

	signature := HmacSignToB64("HMAC-SHA1", "POST", accessSecret, params)
	fmt.Printf("signature: %s\n", string(signature))
}
