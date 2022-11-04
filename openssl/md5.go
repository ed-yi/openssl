package openssl

import (
	"crypto/md5"
	"encoding/hex"
)

/**
* Description: MD5 is cryptographically broken and should not be used for secure applications.
* date: 2022/11/2 15:06
* @author: zhenglg 
* @since goland
*/


func Md5(str string) []byte  {
	h:= md5.New()
	_, _ = h.Write([]byte(str))
	//Sum返回的是MD5的检验和
	return h.Sum(nil)
}



func Md5ToString(str string) string  {
	return hex.EncodeToString(Md5(str))
}