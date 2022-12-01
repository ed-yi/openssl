package openssl

import "crypto/cipher"

func EcbEncodeCrypt(block cipher.Block, src []byte, padding string) (encryData []byte, err error) {
	//返回的是每一个分组的大小不同的规格128，192，256对应 32，48，64（bits）
	blockSize := block.BlockSize()
	//我们需要对我们的加密的密文进行填充
	src = Padding(padding, src, blockSize)
	encryData = make([]byte, len(src))
	ecb := NewECBEncodeCrypt(block)
	ecb.CryptBlocks(encryData, src)
	return encryData, nil
}
