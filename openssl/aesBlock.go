package openssl

import "crypto/cipher"

type ecb struct {
	b         cipher.Block
	blockSize int
}

func NewECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter ecb
type ecbDecrypter ecb

func NewECBEncodeCrypt(block cipher.Block) cipher.BlockMode {

	return (*ecbEncrypter)(NewECB(block))
}
func NewECBDecodeCrypt(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(NewECB(b))
}

func (x *ecbEncrypter) BlockSize() int {
	return x.blockSize
}
func (x *ecbDecrypter) BlockSize() int {
	return x.blockSize
}

func (x *ecbEncrypter) CryptBlocks(dst []byte, src []byte) {
	//判断这个src（已经填充过的src如果取余计算块的大小不为0.说明没填充完整）
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	//判断目标的大小是否小于src的长度大小。如果小则。。
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
func (x *ecbDecrypter) CryptBlocks(dst []byte, src []byte) {
	//判断这个src（已经填充过的src如果取余计算块的大小不为0.说明没填充完整）
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	//判断目标的大小是否小于src的长度大小。如果小则。。
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}

}
