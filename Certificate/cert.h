#pragma once

BOOL WINAPI MapFile(
	LPCSTR	pwszFileName,
	DWORD* pcb,
	LPBYTE* ppb
);

VOID WINAPI ConvertBinaryToHexString(
	_In_ ULONG cb,
	_In_reads_bytes_(cb) LPVOID pv,
	_Out_writes_z_((cb + 1) * 2) LPSTR sz
);


BOOL WINAPI OpenX509CertificateFromFile(
	_Out_ PCERT_INFO* Certificate,
	_In_ LPCSTR CertificateFileName
);

VOID WINAPI CloseX509Certificate(
	_In_opt_ _Post_ptr_invalid_ PCERT_INFO Certificate
);

BOOL WINAPI IssuerSignCertificate(
	_Out_ LPBYTE* SignedCertificate,
	_Out_ LPDWORD SignedCertificateSize,
	_In_ PCERT_INFO CertToBeSigned,
	_In_ HANDLE KeyHandle
);
