package aysign

import (
	"testing"
	"net/url"
	"fmt"
)

func Test_HamcSha1(t *testing.T) {
	accessKeyId := "testId"
	accessSecret := "testSecret"

	params := url.Values{}
	params.Set("SignatureMethod", "HMAC-SHA1")
	params.Set("SignatureNonce", "45e25e9b-0a6f-4070-8c85-2956eda1b466")
	params.Set("AccessKeyId", accessKeyId)
	params.Set("SignatureVersion", "1.0")
	params.Set("Timestamp", "2017-07-12T02:42:19Z")
	params.Set("Format", "XML")
	params.Set("Action", "SendSms")
	params.Set("Version", "2017-05-25")
	params.Set("RegionId", "cn-hangzhou")
	params.Set("PhoneNumbers", "15300000001")
	params.Set("SignName", "阿里云短信测试专用")
	params.Set("TemplateParam", "{\"customer\":\"test\"}")
	params.Set("TemplateCode", "SMS_71390007")
	params.Set("OutId", "123")

	signature := HmacSignToB64("HMAC-SHA1", "GET", accessSecret, params, true)
	fmt.Printf("signature: %s\n", signature)
}

func Test_Util(t *testing.T) {
	accessKeyId := "testId"
	accessSecret := "testSecret"

	params := CreateParamsWithSignature(accessKeyId, accessSecret, "GET",
		CommonParams{
			Format: "XML",
			Version: "2017-05-25",
			SignatureMethod: "HMAC-SHA1",
		}, map[string]string{
			"Action": "SendSms",
			"RegionId": "cn-hangzhou",
			"PhoneNumbers": "15300000001",
			"SignName": "阿里云短信测试专用",
			"TemplateParam": "{\"customer\":\"test\"}",
			"TemplateCode": "SMS_71390007",
			"OutId": "123",
		}, true,
	)
	fmt.Printf("params: %s\n", params)
}
