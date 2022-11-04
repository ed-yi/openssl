package openssl

import (
	"bytes"
)

/*** =========================================
*在玩Cipher的时候，其中创建Cipher对象的时候需要指定加密模式，指定为对称加密中的分组算法时，因为加密是以 块 为单位进行一次加密，所以要求数据是块的整数倍，如果不符合要求，则需要进行填充
ISO10126Padding（最常用）对应上面的 填充数据的最后一个字节为填充字节序列的长度
现在有3bytes，块大小为8bytes，需要填充5bytes，则最后一个为 05，其他全部为 00
原数据：66 6F 72 填充后的数据：66 6F 72 00 00 00 00 05
PKCS5Padding（对称加密最常用）：将数据填充到8的倍数，填充数据计算公式是，假如原数据长度为len，利用该方法填充后的长度是 len + (8 - (len % 8)), 填充的数据长度为 8 - (len % 8)，块大小固定为8字节，填充方式为上面的 填充数据为填充字节的长度
PKCS7Padding（对称加密最常用）：假设需要填充n (n>0) 个字节才对齐，填充n个字节，每个字节都是n ；如果数据本身就已经对齐了，则填充一块长度为块大小的数据，每个字节都是块大小；PKCS7填充字节的范围在 **1-255 **之间 ，填充方式为上面的 填充数据为填充字节的长度
zreo填充就简单了，填充全0
ANSIX923 在填充时首先获取需要填充的字节长度 = (块长度 – (数据长度 % 块长度)), 在填充字节序列中最后一个字节填充为需要填充的字节长度值, 填充字节中其余字节均填充数字零.
假定块长度为8 ，数据长度为 10,则填充字节数等于 6，数据等于 FF FF FF FF FF FF FF FF FF DD：
数据： FF FF FF FF FF FF FF FF FF
X923 填充后： FF FF FF FF FF FF FF FF | FF DD 00 00 00 00 00 06
============================================*/

const (
	PKCS5_PADDING = "PKCS5"
	PKCS7_PADDING = "PKCS7"
	ZEROS_PADDING = "ZEROS"
)

func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func PKCS7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}
func ZerosPadding(src []byte, blockSize int) []byte {
	paddingcount := blockSize - len(src)%blockSize
	if paddingcount == 0 {
		return src
	}
	return append(src, bytes.Repeat([]byte{byte(0)}, paddingcount)...)
}

func Padding(padding string, src []byte, blockSize int) []byte {
	switch padding {
	case PKCS5_PADDING:
		src = PKCS5Padding(src, blockSize)
	case PKCS7_PADDING:
		src = PKCS7Padding(src, blockSize)
	case ZEROS_PADDING:
		src = ZerosPadding(src, blockSize)
	}
	return src
}
