package openssl

import "bytes"

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
	PKCS5_PADDING    = "PKCS5" // 目前已经弃用
	PKCS7_PADDING    = "PKCS7"
	ZEROS_PADDING    = "ZEROS"
	ANSIX923_PADDING = "ANSIX923"
	NONE_PADDING     = "NONE"
	ISO10126_PADDING = "ISO10126"
)

func PKCS5Padding(src []byte, blockSize int) []byte {
	//这个方法已经弃用
	return PKCS7Padding(src, blockSize)
}

func PKCS7Padding(src []byte, blockSize int) []byte {
	//计算出所需要填充的数目
	padding := blockSize - len(src)%blockSize
	//一个块的大小默认是16位（采用16*8=128，aes-128长的密钥），如下，如果是9bute，按照aes的算法我们要填充到16个byte，如下
	//填充示例 原始：FF FF FF FF FF FF FF FF FF 填充：FF FF FF FF FF FF FF FF FF 07 07 07 07 07 07 07
	//这里的07 指的是 16（blocksize）-9（原始的padding）
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)

}
func ZerosPadding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(src, padtext...)
}

// 针对块大小为 8 的算法设计的填充模式，该标准已经被撤销。
/*func ANSIX923PADDING(src []byte, blockSize int) []byte {

}*/

// ，就是不填充，必须保证加密的key和data是8(DES)/16(AES)的整数倍。
/*func NONEPADDING(src []byte, blockSize int) []byte {

}*/
// 与位填充方案相同，适用于N字节的纯文本，并不常用
/*func ISO10126PADDING(src []byte, blockSize int) []byte {

}*/
func Padding(padding string, src []byte, blockSize int) []byte {
	switch padding {
	case PKCS5_PADDING:
		src = PKCS5Padding(src, blockSize)
	case PKCS7_PADDING:
		src = PKCS7Padding(src, blockSize)
	case ZEROS_PADDING:
		src = ZerosPadding(src, blockSize)
		/*	case ANSIX923_PADDING:
				src = ANSIX923PADDING(src, blockSize)
			case NONE_PADDING:
				src = NONEPADDING(src, blockSize)
			case ISO10126_PADDING:
				src = ISO10126PADDING(src, blockSize)*/
	}

	return src
}
