package openssl

import "crypto/cipher"

func ECBEncodeCrypt(block cipher.Block, src []byte, padding string) (encryData []byte, err error) {
	blockSize := block.BlockSize()
	src = Padding(padding, src, blockSize)
	encryData = make([]byte, len(src))
	ecb := NewECBEncodeCrypt(block)
	ecb.CryptBlocks(encryData, src)
	return encryData, nil
}
