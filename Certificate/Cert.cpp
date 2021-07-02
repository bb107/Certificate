#include "stdafx.h"
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib,"Rpcrt4.lib")

BOOL WINAPI MapFile(
	LPCSTR	pwszFileName,
	DWORD* pcb,
	LPBYTE* ppb) {
	HANDLE hFile = nullptr;
	HANDLE hFileMapping = nullptr;

	LPBYTE pbData = nullptr;
	DWORD cbData = 0;
	DWORD cbHighSize = 0;
	BOOL success = FALSE;

	if (!pcb || !ppb || !pwszFileName)
		return FALSE;

	__try {
		*ppb = nullptr;
		*pcb = 0;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	hFile = CreateFileA(
		pwszFileName,
		GENERIC_READ,
		FILE_SHARE_READ,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);
	if (hFile != INVALID_HANDLE_VALUE) {
		cbData = GetFileSize(hFile, &cbHighSize);
		if (cbData != 0xffffffff && cbHighSize == 0) {
			hFileMapping = CreateFileMapping(
				hFile,
				nullptr,
				PAGE_READONLY,
				0,
				0,
				nullptr
			);
			if (hFileMapping) {
				pbData = (LPBYTE)MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, cbData);
				if (pbData) {
					*pcb = cbData;
					*ppb = pbData;

					success = TRUE;
				}

				CloseHandle(hFileMapping);
			}
		}

		CloseHandle(hFile);
	}

	return success;
}

VOID WINAPI ConvertBinaryToHexString(
	_In_ ULONG cb,
	_In_reads_bytes_(cb) LPVOID pv,
	_Out_writes_z_((cb + 1) * 2) LPSTR sz) {
	BYTE* pb = (BYTE*)pv;

	union BITS {
		struct {
			BYTE Low4 : 4;
			BYTE High4 : 4;
		};
		BYTE Value;
	};

	for (ULONG i = 0; i < cb; i++) {
		BITS bits;

		bits.Value = *pb++;
		*sz++ = (bits.High4 <= 9) ? bits.High4 + '0' : (bits.High4 - 10) + 'A';
		*sz++ = (bits.Low4 <= 9) ? bits.Low4 + '0' : (bits.Low4 - 10) + 'A';
	}

	*sz++ = 0;
}

BOOL WINAPI OpenX509CertificateFromFile(
	_Out_ PCERT_INFO* Certificate,
	_In_ LPCSTR CertificateFileName) {

	HANDLE heap = GetProcessHeap();
	LPBYTE fileBuffer = nullptr;
	DWORD fileBufferLength = 0;

	PCERT_INFO CertInfo = nullptr;
	DWORD CertInfoLength = 0;
	BOOL success = FALSE;

	__try {
		*Certificate = nullptr;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	do {
		if (!MapFile(CertificateFileName, &fileBufferLength, &fileBuffer))break;

		CryptDecodeObject(
			X509_ASN_ENCODING,
			X509_CERT_TO_BE_SIGNED,
			fileBuffer,
			fileBufferLength,
			0,
			CertInfo,
			&CertInfoLength
		);
		if (!CertInfoLength)break;

		CertInfo = (PCERT_INFO)HeapAlloc(heap, 0, CertInfoLength);
		if (!CertInfo)break;

		if (!CryptDecodeObject(
			X509_ASN_ENCODING,
			X509_CERT_TO_BE_SIGNED,
			fileBuffer,
			fileBufferLength,
			0,
			CertInfo,
			&CertInfoLength
		))break;

		success = TRUE;
	} while (false);

	if (!success) {
		HeapFree(heap, 0, CertInfo);
	}
	else {
		__try {
			*Certificate = CertInfo;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
	}

	if (fileBuffer) {
		UnmapViewOfFile(fileBuffer);
	}

	return success;
}

/*
BOOL WINAPI OpenX509CertificateFromStore(
	_Out_ PCERT_INFO* Certificate,
	_In_ LPCSTR StoreName,
	_In_ LPCSTR CommonName) {

	__try {
		*Certificate = nullptr;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	PX509CERTIFICATE cert = nullptr;
	HCERTSTORE store = nullptr;
	PCCERT_CONTEXT context = nullptr;
	LPBYTE Buffer = nullptr;
	DWORD Length = 0;
	HANDLE heap = GetProcessHeap();
	BOOL success = FALSE;

	do {
		store = CertOpenSystemStoreA(0, StoreName);
		if (!store)break;

		context = CertFindCertificateInStore(
			store,
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			0,
			CERT_FIND_SUBJECT_STR_A,
			CommonName,
			nullptr
		);
		if (!context)break;

		cert = (PX509CERTIFICATE)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(X509CERTIFICATE));
		if (!cert)break;

		cert->Source.Store = TRUE;

		Length = strlen(StoreName) + 1;
		cert->CertStoreName = LPSTR(HeapAlloc(heap, 0, Length));
		if (!cert->CertStoreName)break;

		RtlCopyMemory(
			(LPVOID)cert->CertStoreName,
			StoreName,
			Length
		);

		CryptDecodeObject(
			context->dwCertEncodingType,
			X509_CERT_TO_BE_SIGNED,
			context->pbCertEncoded,
			context->cbCertEncoded,
			0,
			cert->EncodedCert,
			&Length
		);
		if (!Length)break;

		cert->EncodedCert = (PCERT_INFO)HeapAlloc(heap, 0, Length);
		if (!cert->EncodedCert)break;

		if (!CryptDecodeObject(
			context->dwCertEncodingType,
			X509_CERT_TO_BE_SIGNED,
			context->pbCertEncoded,
			context->cbCertEncoded,
			0,
			cert->EncodedCert,
			&Length
		))break;

		success = TRUE;

		AttachPrivateKeyForCertificateFromStore(cert, context);

	} while (false);

	if (!success) {
		CloseX509Certificate(cert);
	}
	else {
		__try {
			*Certificate = cert;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
	}

	if (context)CertFreeCertificateContext(context);

	if (store)CertCloseStore(store, 0);

	return success;
}

BOOL WINAPI AttachPrivateKeyForCertificateFromFile(
	_Inout_ PCERT_INFO Certificate,
	_In_ LPCSTR CertificatePvkFileName) {

	HANDLE heap = GetProcessHeap();
	LPBYTE pbPvk = nullptr;
	DWORD cbPvk = 0;
	HCRYPTPROV hProv = 0;
	HCRYPTKEY hKey = 0;
	BOOL success = FALSE;
	
	GUID id;
	CHAR KeyContainerName[(sizeof(GUID) + 1) * 2];

	if (UuidCreate(&id));
	ConvertBinaryToHexString(sizeof(id), &id, KeyContainerName);

	do {
		if (!MapFile(CertificatePvkFileName, &cbPvk, &pbPvk))break;
		
		PCERT_PUBLIC_KEY_INFO pub = nullptr;
		DWORD len = 0;

		PFILE_HDR hdr = PFILE_HDR(pbPvk);
		if (cbPvk < sizeof(FILE_HDR) ||
			hdr->dwMagic != PVK_MAGIC ||
			hdr->dwVersion != PVK_FILE_VERSION_0 ||
			hdr->dwEncryptType ||
			hdr->cbEncryptData ||
			!hdr->cbPvk)break;

		if (!CryptAcquireContextA(&hProv, KeyContainerName, nullptr, PROV_RSA_FULL, CRYPT_NEWKEYSET))break;

		if (!CryptImportKey(hProv, pbPvk + sizeof(FILE_HDR), hdr->cbPvk, 0, 0, &hKey))break;

		CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, pub, &len);
		if (!len)break;

		pub = (PCERT_PUBLIC_KEY_INFO)HeapAlloc(heap, 0, len);
		if (!pub)break;

		success = CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, pub, &len) &&
			CertComparePublicKeyInfo(X509_ASN_ENCODING, &Certificate->EncodedCert->SubjectPublicKeyInfo, pub);

		HeapFree(heap, 0, pub);

	} while (false);

	if (success) {
		__try {
			HeapFree(heap, 0, Certificate->PrivateKey);

			Certificate->KeyLength = cbPvk;
			Certificate->PrivateKey = (LPBYTE)HeapAlloc(heap, 0, cbPvk);
			if (!Certificate->PrivateKey) {
				success = FALSE;
			}
			else {
				RtlCopyMemory(
					Certificate->PrivateKey,
					pbPvk,
					cbPvk
				);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			success = FALSE;
		}
	}

	if (pbPvk)UnmapViewOfFile(pbPvk);

	if (hKey)CryptDestroyKey(hKey);

	if (hProv) {
		CryptReleaseContext(hProv, 0);
		CryptAcquireContextA(&hProv, KeyContainerName, nullptr, 0, CRYPT_DELETEKEYSET);
	}
	return success;
}

BOOL WINAPI AttachPrivateKeyForCertificateFromStore(
	_Inout_ PCERT_INFO Certificate,
	_In_opt_ PCCERT_CONTEXT CertContext) {

	CERT_PUBLIC_KEY_INFO CapturedPublicKeyInfo{};
	PX509CERTIFICATE cert = Certificate;
	HCERTSTORE store = nullptr;
	HCRYPTPROV hProv = 0;
	HCRYPTKEY hKey = 0;
	DWORD KeySpec;
	BOOL Free = FALSE;
	BOOL success = FALSE;
	DWORD Length = 0;
	LPBYTE Buffer = nullptr;
	HANDLE heap = GetProcessHeap();

	__try {
		if (!cert) {
			if (!cert->CertStoreName || !cert->EncodedCert)return FALSE;

			RtlMoveMemory(
				&CapturedPublicKeyInfo,
				&cert->EncodedCert->SubjectPublicKeyInfo,
				sizeof(CERT_PUBLIC_KEY_INFO)
			);

			RtlMoveMemory(
				CapturedPublicKeyInfo.PublicKey.pbData,
				CapturedPublicKeyInfo.PublicKey.pbData,
				CapturedPublicKeyInfo.PublicKey.cbData
			);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	do {
		if (!CertContext) {
			store = CertOpenSystemStoreA(0, cert->CertStoreName);
			if (!store)break;

			CertContext = CertFindCertificateInStore(
				store,
				X509_ASN_ENCODING,
				0,
				CERT_FIND_PUBLIC_KEY,
				&CapturedPublicKeyInfo,
				nullptr
			);
			if (!CertContext)break;
		}

		if (!CryptAcquireCertificatePrivateKey(
			CertContext,
			0,
			nullptr,
			&hProv,
			&KeySpec,
			&Free
		))break;

		if (!CryptGetUserKey(hProv, KeySpec, &hKey))break;

		// make key exportable
		*(size_t*)(*(size_t*)(*(size_t*)(hKey + OFFSET_1) ^ XOR_KEY) + OFFSET_2) |= CRYPT_EXPORTABLE | CRYPT_ARCHIVABLE;

		CryptExportKey(
			hKey,
			0,
			PRIVATEKEYBLOB,
			0,
			Buffer,
			&Length
		);
		if (!Length)break;

		Buffer = (LPBYTE)HeapAlloc(heap, 0, Length + sizeof(FILE_HDR));
		if (!Buffer)break;

		//
		// Fill file hdr
		//
		auto hdr = PFILE_HDR(Buffer);
		hdr->dwVersion = PVK_FILE_VERSION_0;
		hdr->dwMagic = PVK_MAGIC;
		hdr->cbPvk = Length;
		hdr->cbEncryptData = 0;
		hdr->dwEncryptType = PVK_NO_ENCRYPT;
		hdr->dwKeySpec = AT_SIGNATURE;

		if (!CryptExportKey(
			hKey,
			0,
			PRIVATEKEYBLOB,
			0,
			Buffer + sizeof(FILE_HDR),
			&Length)) {
			success = FALSE;
			break;
		}

		success = TRUE;

	} while (false);

	if (!success) {
		HeapFree(heap, 0, Buffer);
	}
	else {
		__try {

			HeapFree(heap, 0, cert->PrivateKey);

			cert->PrivateKey = Buffer;
			cert->KeyLength = Length + sizeof(FILE_HDR);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
	}

	if (hKey)CryptDestroyKey(hKey);

	if (hProv && Free)CryptReleaseContext(hProv, 0);

	if (store) {
		if (CertContext)CertFreeCertificateContext(CertContext);

		CertCloseStore(store, 0);
	}

	return success;
}
*/

VOID WINAPI CloseX509Certificate(_In_opt_ _Post_ptr_invalid_ PCERT_INFO Certificate) {

	HANDLE heap = GetProcessHeap();

	HeapFree(heap, 0, Certificate);

}

BOOL WINAPI IssuerSignCertificate(
	_Out_ LPBYTE* SignedCertificate,
	_Out_ LPDWORD SignedCertificateSize,
	_In_ PCERT_INFO CertToBeSigned,
	_In_ HANDLE KeyHandle) {

	HCRYPTPROV hProv = 0;
	HCRYPTKEY hKey = 0;
	LPBYTE ResultBuffer = nullptr;
	DWORD ResultBufferLength = 0;
	BOOL success = FALSE;
	HANDLE heap = GetProcessHeap();

	__try {
		*SignedCertificate = nullptr;
		*SignedCertificateSize = 0;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	if (!RSAKeyGetCryptProvHandle(&hProv, &hKey, KeyHandle))return FALSE;

	do {
		CryptSignAndEncodeCertificate(
			hProv,
			AT_SIGNATURE,
			X509_ASN_ENCODING,
			X509_CERT_TO_BE_SIGNED,
			CertToBeSigned,
			&CertToBeSigned->SignatureAlgorithm,
			nullptr,
			ResultBuffer,
			&ResultBufferLength
		);
		if (!ResultBufferLength)break;

		ResultBuffer = (LPBYTE)HeapAlloc(heap, 0, ResultBufferLength);
		if (!ResultBuffer)break;

		if (!CryptSignAndEncodeCertificate(
			hProv,
			AT_SIGNATURE,
			X509_ASN_ENCODING,
			X509_CERT_TO_BE_SIGNED,
			CertToBeSigned,
			&CertToBeSigned->SignatureAlgorithm,
			nullptr,
			ResultBuffer,
			&ResultBufferLength))break;

		success = TRUE;
	} while (false);

	if (success) {
		__try {
			*SignedCertificate = ResultBuffer;
			*SignedCertificateSize = ResultBufferLength;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
	}
	else {
		HeapFree(heap, 0, ResultBuffer);
	}

	RSAKeyReleaseCryptProvider(hProv, hKey);
	return success;
}
