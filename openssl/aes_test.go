package openssl

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAesECBEncodeCrypt(t *testing.T) {
	src := []byte("3324324324234423")

	//// AES-128-ECB, PKCS7_PADDING
	key := []byte("1234512345123451")
	dst, err := AesECBEncodeCrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(dst))
	assert.Equal(t, base64.StdEncoding.EncodeToString(dst), "SpfAShHImQhWjd/21Pgz2Q==")

}
