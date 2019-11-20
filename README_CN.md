# Certificate

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

可以很容易的创建自签名证书或者签发新的子证书.

  - 常用的增强型密钥用法可以用或运算符结合(EnhKeyUsage.h).
  - 可以指定其他增强型密钥用法或其他证书扩展.

# 实现

  - 标记为"不可导出私钥"的证书也可以导出到文件(.cer+.pvk或.pfx)
    导出原理参考: [Source]
    ```c++
    *(DWORD*)(*(DWORD*)(*(DWORD*)(hCryptKey + 0x2C) ^ 0xE35A172C) + 8) |= CRYPT_EXPORTABLE | CRYPT_ARCHIVABLE;
  - 证书的生成代码部分参考: [makecert.c]
  - 可以从文件导入证书,也可以从证书存储中导入证书, 也可以导出到这些地方.
  - 较完整的错误代码,可以快速定位出错原因.


License
----
MIT


   [makecert.c]: <https://github.com/thishome153/RRStudio/blob/14a244160d47007759a66769254b0b46bd2f8f4b/cspConsole/makecert.c>
   [Source]: <https://www.nccgroup.trust/globalassets/our-research/uk/whitepapers/exporting_non-exportable_rsa_keys.pdf>
