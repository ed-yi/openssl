package openssl

import (
	"encoding/base64"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)


func TestMD5(t *testing.T)  {
	src :="helloworld"
	dst := Md5(src)
	assert.Equal(t, hex.EncodeToString(dst),"fc5e038d38a57032085441e7fe7010b0" )

	contextMD5 := base64.StdEncoding.EncodeToString([]byte(dst))
	t.Log(contextMD5)
}