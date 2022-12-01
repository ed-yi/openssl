package openssl

import "errors"

/*** =========================================
这是一个反填充的包
============================================*/

const (
	PKCS5_UNPADDING    = "UNPKCS5" // 目前已经弃用
	PKCS7_UNPADDING    = "UNPKCS7"
	ZEROS_UNPADDING    = "UNZEROS"
	ANSIX923_UNPADDING = "UNANSIX923"
	NONE_UNPADDING     = "UNNONE"
	ISO10126_UNPADDING = "UNISO10126"
)

func PKCS5UnPadding(originData []byte) ([]byte, error) {
	//这个方法已经弃用
	return PKCS7UnPadding(originData)
}

func PKCS7UnPadding(originData []byte) ([]byte, error) {
	if len(originData) <= 0 {
		return originData, errors.New("length is err")
	}
	length := len(originData)
	unpadding := int(originData[length-1])
	return originData[:length-unpadding], nil
}
func ZerosUnPadding(originData []byte) ([]byte, error) {
	if len(originData) <= 0 {
		return originData, errors.New("length is err")
	}
	length := len(originData)
	unpadding := int(originData[length-1])
	return originData[:length-unpadding], nil
}

/*
func ANSIX923UnPADDING(originData []byte) []byte {

}
func NONEUnPADDING(originData []byte) []byte {

}
func ISO10126UnPADDING(originData []byte) []byte {

}
*/
func UnPadding(unpadding string, originData []byte) ([]byte, error) {
	switch unpadding {
	case PKCS5_UNPADDING:
		originData, _ = PKCS5UnPadding(originData)
	case PKCS7_UNPADDING:
		originData, _ = PKCS7UnPadding(originData)
	case ZEROS_UNPADDING:
		originData, _ = ZerosUnPadding(originData)
		/*	case ANSIX923_UNPADDING:
				originData = ANSIX923UnPADDING(originData, blockSize)
			case NONE_UNPADDING:
				originData = NONEUnPADDING(originData, blockSize)
			case ISO10126_UNPADDING:
				originData = ISO10126UnPADDING(originData, blockSize)*/
	}
	return originData, nil
}
