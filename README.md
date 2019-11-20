# Certificate

* [中文版](./README_CN.md)

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

a simple digital certificate class.

  - Commonly used enhanced key usage can be combined with an operator (EnhKeyUsage.h).
  - You can specify additional enhanced key usage or other certificate extensions.

# Features

  - Certificates marked as "non-exportable private key" can also be exported to file (.cer+.pvk or .pfx).
    "Exporting a Private Key Marked as Unexportable" Principle Reference:    [Source]
    ```c++
    *(DWORD*)(*(DWORD*)(*(DWORD*)(hCryptKey + 0x2C) ^ 0xE35A172C) + 8) |= CRYPT_EXPORTABLE | CRYPT_ARCHIVABLE;
  - Certificate generation part of the reference:  [makecert.c]
  - You can import a certificate from a file, import a certificate from a certificate store, or export to these places.
  - Complete error code to quickly locate the cause of the error.

License
----
MIT


   [makecert.c]: <https://github.com/thishome153/RRStudio/blob/14a244160d47007759a66769254b0b46bd2f8f4b/cspConsole/makecert.c>
   [Source]: <https://www.nccgroup.trust/globalassets/our-research/uk/whitepapers/exporting_non-exportable_rsa_keys.pdf>
