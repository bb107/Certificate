@echo off
"C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\pvk2pfx.exe" -spc CodeSigning.cer -pvk CodeSigning.pvk -pfx CodeSigning.pfx

"C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\pvk2pfx.exe" -spc CodeSigningCA.cer -pvk CodeSigningCA.pvk -pfx CodeSigningCA.pfx

"C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\pvk2pfx.exe" -spc RootCA.cer -pvk RootCA.pvk -pfx RootCA.pfx

"C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\pvk2pfx.exe" -spc SSL.cer -pvk SSL.pvk -pfx SSL.pfx

"C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\pvk2pfx.exe" -spc SSLCA.cer -pvk SSLCA.pvk -pfx SSLCA.pfx

"C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\pvk2pfx.exe" -spc SSLClient.cer -pvk SSLClient.pvk -pfx SSLClient.pfx

pause