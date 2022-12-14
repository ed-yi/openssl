## AES 加密算法的简单说明

#### 规格：
- AES-128 

密钥长度：4 ， 分组长度：4
- AES-192 

密钥长度：6 ， 分组长度：4

- AES-256 

密钥长度：8 ， 分组长度：4


填充的方法有如下几类 

1、Nopadding 

故名思意就是没有填充，不过选择这种填充方式要保证明文的数据是128bit的整数倍。 

2、Zeropadding 

这种填充模式下，若明文数据不是128bit的整数倍则会将余下的数据后补充足量的00，直到是128bit。若正好是128bit的整数倍，则补充128bit的00。 

3、PKCS #5 

这种模式就是缺几个字节填充几个字节的数，这个数就是缺少的字节数（比如缺10个字节，填充10个字节的10），如果不需要填充，则添加一个分组，分组中填充的数是分组大小，比如分组大小为128bit，则填充16个字节的16。分好组之后，每一组都会经过数轮运算，直到所有的分组都被加密完。 

4、PKCS #7 

这种模式和PKCS #5几乎是一模一样，为一不同的是它没有block必须是16byte的要求。 

5、ISO 10126 

这种模式下，会将余下不足16byte的数据之后补充随机数，但是在最后一位会标明补充的数的的个数。 

6、ANSI X9.23 

和ISO 10126类似，不过不是补充随机数而是补充00。
