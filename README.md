# openssl
这是一个简单的关于加密的仓库，md5、aes 、des 、3des加密的一些操作

## MD5 加密
MD5消息摘要算法(MD5 Message-Digest Algorithm),一种被广泛使用的密码散列函数，可以产生出一个128位（16字节）的散列值（hash value），用于确保信息传输完整一致。
这里提供了两个方法

```go
//这个是以二进制输出
func Md5(str string) []byte 
//这个是输出字符串
func Md5ToString(str string) string 
```

