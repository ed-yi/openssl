/**
* Description: 这是一个关于aes的加密
* date: 2022/11/2 15:46
* @author: ed-yi
* @since goland
 */

package openssl

import (
	"crypto/aes"
)

/*** =========================================
*AES 是一种堆成的加密方式
有五种加密方式，分别是
CBC (Cipher Block Chainging)，ECB(Electronic Codebook Book)，CTR (Counter)，OCF (Output FeedBack)，CFB (Cipher FeedBack)
============================================*/

/*** =========================================
*填充的方式有6种，PKCS#5,PKCS#7, ISO 10126, ANSI X9.23 和 ZerosPadding
* 其中 ，PKCS#5,PKCS#7,缺几个字节就填几个缺的字节数。
如果当前数据已经是128bits的倍数了也得要填充，否则无法解密。
对于AES来说PKCS5Padding和PKCS7Padding是完全一样的，不同在于PKCS5限定了块大小为8bytes而PKCS7没有限定。因此对于AES来说两者完全相同，但
注意：在AES加密当中严格来说是不能使用pkcs5的，因为AES的块大小是16bytes而pkcs5只能用于8bytes，通常我们在AES加密中所说的pkcs5指的就是pkcs7！
============================================*/

/*
这个很好理解：将明文简单的按照128bit为一个分块进行切割，把每个分块分别进行AES加密，然后再将得到的密文简单的拼接一下即可。注意到AES加密只能加密128bit的分块，那问题就产生了：如果明文的长度不是128bit的倍数，就会存在一个分块不足128bit，那如何对这个分块进行加密？
。为了解决这个问题，我们发明了一种叫做填充的东西，这将会在后面具体讲解。OFB和CTR不需要填充！
说明：这是一个AES关于ECB电子密码本的加密方法 。
src ： 待加密的名文
key ： 加密密钥
padding ： 填充方式 看 27行
*/
func AesECBEncodeCrypt(src []byte, key []byte, padding string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return ECBEncodeCrypt(block, src, padding)
}

//func AesECBDecodeCrypt(src []byte, key []byte, padding string) ([]byte, error) {
//
//}
//func AesCBCEncodeCrypt(src []byte, key []byte, padding string) ([]byte, error) {
//
//}
//func AesCBCDecodeCrypt(src []byte, key []byte, padding string) ([]byte, error) {
//
//}
