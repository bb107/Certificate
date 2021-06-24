#include "cert.h"
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib,"Rpcrt4.lib")

typedef struct _FILE_HDR {
	DWORD dwMagic;
	DWORD dwVersion;
	DWORD dwKeySpec;
	DWORD dwEncryptType;
	DWORD cbEncryptData;
	DWORD cbPvk;
} FILE_HDR, * PFILE_HDR;

#define PVK_FILE_VERSION_0 0
#define PVK_MAGIC 0xb0b5f11e
#define PVK_NO_ENCRYPT 0

#define XOR_KEY_X86		0xE35A172CUL
#define OFFSET_1_X86	0x2C
#define OFFSET_2_X86	0x8
#define XOR_KEY_X64		0xE35A172CD96214A0UL
#define OFFSET_1_X64	0x58
#define OFFSET_2_X64	0xC
#ifdef _WIN64
#define XOR_KEY		XOR_KEY_X64
#define OFFSET_1	OFFSET_1_X64
#define OFFSET_2	OFFSET_2_X64
#else
#define XOR_KEY		XOR_KEY_X86
#define OFFSET_1	OFFSET_1_X86
#define OFFSET_2	OFFSET_2_X86
#endif

static BOOL WINAPI MapFile(
	LPCSTR	pwszFileName,
	DWORD* pcb,
	LPBYTE* ppb) {
	HANDLE hFile = nullptr;
	HANDLE hFileMapping = nullptr;

	LPBYTE pbData = nullptr;
	DWORD cbData = 0;
	DWORD cbHighSize = 0;

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

					return TRUE;
				}

				CloseHandle(hFileMapping);
			}
		}

		CloseHandle(hFile);
	}

	return FALSE;
}

static void ConvertBinaryToHexString(
	_In_ ULONG cb,
	_In_reads_bytes_(cb) void* pv,
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
	_Out_ PX509CERTIFICATE* Certificate,
	_In_ LPCSTR CertificateFileName,
	_In_opt_ LPCSTR CertificatePvkFileName) {

	__try {
		*Certificate = nullptr;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}

	HANDLE heap = GetProcessHeap();
	PX509CERTIFICATE cert = nullptr;
	LPBYTE pbCertFile = nullptr;
	DWORD cbCertFile = 0;
	BOOL success = FALSE;

	do {
		cert = (PX509CERTIFICATE)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(X509CERTIFICATE));
		if (!cert)break;

		cert->Source.File = TRUE;

		if (!MapFile(CertificateFileName, &cbCertFile, &pbCertFile))break;

		CryptDecodeObject(
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			X509_CERT_TO_BE_SIGNED,
			pbCertFile,
			cbCertFile,
			0,
			cert->EncodedCert,
			&cert->CertSize
		);
		if (!cert->CertSize)break;

		cert->EncodedCert = (PCERT_INFO)HeapAlloc(heap, 0, cert->CertSize);
		if (!cert->EncodedCert)break;

		if (!CryptDecodeObject(
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			X509_CERT_TO_BE_SIGNED,
			pbCertFile,
			cbCertFile,
			0,
			cert->EncodedCert,
			&cert->CertSize))break;

		if (CertificatePvkFileName) {
			if (!AttachPrivateKeyForCertificateFromFile(cert, CertificatePvkFileName))break;
		}

		success = TRUE;

	} while (false);

	if (pbCertFile)UnmapViewOfFile(pbCertFile);

	if (success) {
		__try {
			*Certificate = cert;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
	}
	else {
		if (cert) {
			HeapFree(heap, 0, cert->EncodedCert);
			HeapFree(heap, 0, cert);
		}
	}

	return success;
}

BOOL WINAPI OpenX509CertificateFromStore(
	_Out_ PX509CERTIFICATE* Certificate,
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
	_Inout_ PX509CERTIFICATE Certificate,
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
	_Inout_ PX509CERTIFICATE Certificate,
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

VOID WINAPI CloseX509Certificate(_In_opt_ _Post_ptr_invalid_ PX509CERTIFICATE Certificate) {

	HANDLE heap = GetProcessHeap();

	if (Certificate) {

		if (Certificate->Source.Create) {

			if (Certificate->EncodedCert) {
				HeapFree(heap, 0, Certificate->EncodedCert->Subject.pbData);

				for (DWORD i = 0; i < Certificate->EncodedCert->cExtension; ++i) {
					HeapFree(heap, 0, Certificate->EncodedCert->rgExtension[i].Value.pbData);
				}
				HeapFree(heap, 0, Certificate->EncodedCert->rgExtension);
			}

			HeapFree(heap, 0, Certificate->PublicKeyInfo);
		}
		else if (Certificate->Source.Store) {
			HeapFree(heap, 0, (LPVOID)Certificate->CertStoreName);
		}

		HeapFree(heap, 0, Certificate->EncodedCert);
		HeapFree(heap, 0, Certificate->PrivateKey);
		HeapFree(heap, 0, Certificate);
	}

}

static BOOL WINAPI GenerateRSAKeyPair(
	_In_ DWORD KeyLength,
	_Out_ LPBYTE* PvkBuffer,
	_Out_ LPDWORD PvkBufferLength,
	_Out_ PCERT_PUBLIC_KEY_INFO* PubBuffer) {
	__try {
		*PvkBuffer = nullptr;
		*PvkBufferLength = 0;
		*PubBuffer = nullptr;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	HANDLE heap = GetProcessHeap();
	GUID guid;
	CHAR buffer[(sizeof(guid) + 1) * 2];
	if (UuidCreate(&guid));
	ConvertBinaryToHexString(sizeof(guid), &guid, buffer);

	HCRYPTPROV hProv = 0;
	HCRYPTKEY hKey = 0;
	LPBYTE privateKeyBuffer = nullptr;
	DWORD privateKeyBufferLength = 0;
	PCERT_PUBLIC_KEY_INFO publicKeyBuffer = nullptr;
	DWORD publicKeyBufferLength = 0;
	BOOL success = FALSE;

	do {
		if (!CryptAcquireContextA(&hProv, buffer, nullptr, PROV_RSA_FULL, CRYPT_NEWKEYSET))break;

		if (!CryptGenKey(hProv, AT_SIGNATURE, CRYPT_EXPORTABLE | RSA_N_BITS_KEY(KeyLength), &hKey))break;

		CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, privateKeyBuffer, &privateKeyBufferLength);
		if (!privateKeyBufferLength)break;

		privateKeyBuffer = LPBYTE(HeapAlloc(heap, 0, privateKeyBufferLength + sizeof(FILE_HDR)));
		if (!privateKeyBuffer)break;

		auto hdr = PFILE_HDR(privateKeyBuffer);
		hdr->dwVersion = PVK_FILE_VERSION_0;
		hdr->dwMagic = PVK_MAGIC;
		hdr->cbPvk = privateKeyBufferLength;
		hdr->cbEncryptData = 0;
		hdr->dwEncryptType = PVK_NO_ENCRYPT;
		hdr->dwKeySpec = AT_SIGNATURE;

		if (!CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, privateKeyBuffer + sizeof(FILE_HDR), &privateKeyBufferLength))break;
		privateKeyBufferLength += sizeof(FILE_HDR);

		CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, publicKeyBuffer, &publicKeyBufferLength);
		if (!publicKeyBufferLength)break;

		publicKeyBuffer = PCERT_PUBLIC_KEY_INFO(HeapAlloc(heap, 0, publicKeyBufferLength));
		if (!publicKeyBuffer)break;

		if (!CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, publicKeyBuffer, &publicKeyBufferLength))break;

		success = TRUE;

	} while (false);

	if (hKey)CryptDestroyKey(hKey);

	if (hProv) {
		CryptReleaseContext(hProv, 0);
		CryptAcquireContextA(&hProv, buffer, nullptr, 0, CRYPT_DELETEKEYSET);
	}

	if (success) {
		__try {
			*PvkBuffer = privateKeyBuffer;
			*PvkBufferLength = privateKeyBufferLength;
			
			*PubBuffer = publicKeyBuffer;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
	}
	else {
		HeapFree(heap, 0, publicKeyBuffer);
		HeapFree(heap, 0, privateKeyBuffer);
	}

	return success;
}

//
//		ExtensionObject							pszObjId							lpszStructType
//	CERT_BASIC_CONSTRAINTS_INFO;		szOID_BASIC_CONSTRAINTS;				X509_BASIC_CONSTRAINTS
//	CERT_ALT_NAME_INFO;					szOID_SUBJECT_ALT_NAME;					X509_ALTERNATE_NAME
//	CRYPT_BIT_BLOB;						szOID_KEY_USAGE;						X509_KEY_USAGE
//	CERT_ENHKEY_USAGE;					szOID_ENHANCED_KEY_USAGE;				X509_ENHANCED_KEY_USAGE
//	CERT_AUTHORITY_KEY_ID_INFO;			szOID_AUTHORITY_KEY_IDENTIFIER;			X509_AUTHORITY_KEY_ID
//	SPC_SP_AGENCY_INFO;					SPC_SP_AGENCY_INFO_OBJID;				SPC_SP_AGENCY_INFO_OBJID
//
static LPCSTR preDefinedExtensions[] = {
	szOID_BASIC_CONSTRAINTS,
	szOID_SUBJECT_ALT_NAME,
	szOID_KEY_USAGE,
	szOID_ENHANCED_KEY_USAGE,
	szOID_AUTHORITY_KEY_IDENTIFIER,
	SPC_SP_AGENCY_INFO_OBJID
};

static BOOL WINAPI EncodeExtension(
	_Out_ PCERT_EXTENSION Extension,
	_In_ PVOID ExtensionObject,
	_In_ LPCSTR lpszStructType,
	_In_ LPCSTR pszObjId) {

	__try {
		RtlZeroMemory(
			Extension,
			sizeof(CERT_EXTENSION)
		);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	LPBYTE pbEncoded = nullptr;
	DWORD cbEncoded = 0;
	HANDLE heap = GetProcessHeap();

	CryptEncodeObject(
		X509_ASN_ENCODING,
		lpszStructType,
		ExtensionObject,
		pbEncoded,
		&cbEncoded
	);
	if (!cbEncoded)return FALSE;

	pbEncoded = LPBYTE(HeapAlloc(heap, 0, cbEncoded));
	if (!pbEncoded)return FALSE;

	if (!CryptEncodeObject(
		X509_ASN_ENCODING,
		lpszStructType,
		ExtensionObject,
		pbEncoded,
		&cbEncoded)) {
		HeapFree(heap, 0, pbEncoded);
		return FALSE;
	}

	__try {
		Extension->fCritical = FALSE;
		Extension->pszObjId = (LPSTR)pszObjId;
		Extension->Value.cbData = cbEncoded;
		Extension->Value.pbData = pbEncoded;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}
	return TRUE;
}

static BOOL WINAPI CaptureBasicConstraint(
	_In_ PBASIC_CONSTRAINT CapturedBasicConstraint,
	_Inout_ PCERT_EXTENSIONS CapturedExtensions) {
	if (CapturedBasicConstraint->MaxPathHeight || CapturedBasicConstraint->CertType) {
		CERT_BASIC_CONSTRAINTS_INFO info{};
		BYTE type = 0;

		if (CapturedBasicConstraint->CertType == 0) {
			type = CERT_CA_SUBJECT_FLAG | CERT_END_ENTITY_SUBJECT_FLAG;
		}
		else {
			if (CapturedBasicConstraint->Authority)type |= CERT_CA_SUBJECT_FLAG;
			if (CapturedBasicConstraint->End)type |= CERT_END_ENTITY_SUBJECT_FLAG;
		}

		info.SubjectType.pbData = &type;
		info.SubjectType.cbData = 1;

		if (type & CERT_END_ENTITY_SUBJECT_FLAG) {
			info.SubjectType.cUnusedBits = 6;
		}
		else {
			info.SubjectType.cUnusedBits = 7;
		}

		if (CapturedBasicConstraint->MaxPathHeight & 0x80000000) {
			info.fPathLenConstraint = FALSE;
		}
		else {
			info.fPathLenConstraint = TRUE;
			info.dwPathLenConstraint = CapturedBasicConstraint->MaxPathHeight;
		}

		return EncodeExtension(
			&CapturedExtensions->rgExtension[CapturedExtensions->cExtension++],
			&info,
			X509_BASIC_CONSTRAINTS,
			szOID_BASIC_CONSTRAINTS
		);
	}

	return TRUE;
}

static BOOL WINAPI CaptureKeyUsageRestriction(
	_In_ PKEY_USAGE_RESTRICTION CapturedKeyUsageRestriction,
	_Inout_ PCERT_EXTENSIONS CapturedExtensions) {

	CERT_KEY_USAGE_RESTRICTION_INFO KeyUsageInfo{};
	WORD bRestrictedKeyUsage = CapturedKeyUsageRestriction->KeyUsage.Flags;

	LPSTR Individual[1] = { (LPSTR)SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID };
	LPSTR Commercial[1] = { (LPSTR)SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID };
	CERT_POLICY_ID CertPolicyId[2]{};

	auto countSetBits = [](WORD n)->DWORD {
		DWORD count = 0;
		while (n) {
			count += n & 1;
			n >>= 1;
		}
		return count;
	};

	KeyUsageInfo.RestrictedKeyUsage.pbData = (LPBYTE)&bRestrictedKeyUsage;
	if (CapturedKeyUsageRestriction->KeyUsage.DecipherOnly) {
		KeyUsageInfo.RestrictedKeyUsage.cbData = 2;
		KeyUsageInfo.RestrictedKeyUsage.cUnusedBits = 16;
		bRestrictedKeyUsage &= 0xff;
		bRestrictedKeyUsage |= 0x8000;
	}
	else {
		KeyUsageInfo.RestrictedKeyUsage.cbData = 1;
		KeyUsageInfo.RestrictedKeyUsage.cUnusedBits = 8;
	}

	KeyUsageInfo.RestrictedKeyUsage.cUnusedBits -= countSetBits(CapturedKeyUsageRestriction->KeyUsage.Flags);

	if (CapturedKeyUsageRestriction->SigningAuthority.Individual) {
		CertPolicyId[KeyUsageInfo.cCertPolicyId].cCertPolicyElementId = 1;
		CertPolicyId[KeyUsageInfo.cCertPolicyId].rgpszCertPolicyElementId = Individual;
		KeyUsageInfo.cCertPolicyId++;
	}

	if (CapturedKeyUsageRestriction->SigningAuthority.Commercial) {
		CertPolicyId[KeyUsageInfo.cCertPolicyId].cCertPolicyElementId = 1;
		CertPolicyId[KeyUsageInfo.cCertPolicyId].rgpszCertPolicyElementId = Commercial;
		KeyUsageInfo.cCertPolicyId++;
	}

	if (KeyUsageInfo.cCertPolicyId > 0) {
		KeyUsageInfo.rgCertPolicyId = CertPolicyId;
	}

	return EncodeExtension(
		&CapturedExtensions->rgExtension[CapturedExtensions->cExtension++],
		&KeyUsageInfo,
		X509_KEY_USAGE_RESTRICTION,
		szOID_KEY_USAGE_RESTRICTION
	);
}

static BOOL WINAPI CaptureKeyUsage(
	_In_ PKEY_USAGE CapturedKeyUsage,
	_Inout_ PCERT_EXTENSIONS CapturedExtensions) {

	CERT_KEY_ATTRIBUTES_INFO KeyUsageInfo{};
	WORD bRestrictedKeyUsage = CapturedKeyUsage->Flags;

	auto countSetBits = [](WORD n)->DWORD {
		DWORD count = 0;
		while (n) {
			count += n & 1;
			n >>= 1;
		}
		return count;
	};

	KeyUsageInfo.IntendedKeyUsage.pbData = (LPBYTE)&bRestrictedKeyUsage;
	if (CapturedKeyUsage->DecipherOnly) {
		KeyUsageInfo.IntendedKeyUsage.cbData = 2;
		KeyUsageInfo.IntendedKeyUsage.cUnusedBits = 16;
		bRestrictedKeyUsage &= 0xff;
		bRestrictedKeyUsage |= 0x8000;
	}
	else {
		KeyUsageInfo.IntendedKeyUsage.cbData = 1;
		KeyUsageInfo.IntendedKeyUsage.cUnusedBits = 8;
	}

	KeyUsageInfo.IntendedKeyUsage.cUnusedBits -= countSetBits(CapturedKeyUsage->Flags);

	return EncodeExtension(
		&CapturedExtensions->rgExtension[CapturedExtensions->cExtension++],
		&KeyUsageInfo.IntendedKeyUsage,
		X509_KEY_USAGE,
		szOID_KEY_USAGE
	);
}

static BOOL WINAPI CaptureEnhancedKeyUsage(
	_In_ PEKU_LIST EkuList,
	_Inout_ PCERT_EXTENSIONS CapturedExtensions) {

	if (!EkuList->EkuCount)return TRUE;

	HANDLE heap = GetProcessHeap();
	BOOL result = FALSE;
	CERT_ENHKEY_USAGE eku{};

	__try {
		eku.cUsageIdentifier = EkuList->EkuCount;
		eku.rgpszUsageIdentifier = (LPSTR*)&EkuList->Ekus[0];

		result = EncodeExtension(
			&CapturedExtensions->rgExtension[CapturedExtensions->cExtension++],
			&eku,
			X509_ENHANCED_KEY_USAGE,
			szOID_ENHANCED_KEY_USAGE
		);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		result = FALSE;
	}

	return result;
}

static BOOL WINAPI CaptureAuthorityKeyIdentifier(
	_In_ PCERT_INFO IssuerCert,
	_Inout_ PCERT_EXTENSIONS CapturedExtensions) {

	CERT_AUTHORITY_KEY_ID_INFO KeyIdInfo{};
	HCRYPTPROV hProv = 0;
	LPBYTE hash = nullptr;
	DWORD len = 0;
	BOOL success = FALSE;
	HANDLE heap = GetProcessHeap();

	do {
		if (!CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))break;

		CryptHashPublicKeyInfo(
			hProv,
			0,
			0,
			X509_ASN_ENCODING,
			&IssuerCert->SubjectPublicKeyInfo,
			hash,
			&len
		);
		if (!len)break;

		hash = (LPBYTE)HeapAlloc(heap, 0, len);
		if (!hash)break;

		if (!CryptHashPublicKeyInfo(
			hProv,
			0,
			0,
			X509_ASN_ENCODING,
			&IssuerCert->SubjectPublicKeyInfo,
			hash,
			&len
		))break;

		__try {
			KeyIdInfo.CertIssuer = IssuerCert->Issuer;
			KeyIdInfo.CertSerialNumber = IssuerCert->SerialNumber;
			KeyIdInfo.KeyId.cbData = len;
			KeyIdInfo.KeyId.pbData = hash;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			break;
		}

		success = EncodeExtension(
			&CapturedExtensions->rgExtension[CapturedExtensions->cExtension++],
			&KeyIdInfo,
			X509_AUTHORITY_KEY_ID,
			szOID_AUTHORITY_KEY_IDENTIFIER
		);

	} while (false);
	
	if (hProv) {
		CryptReleaseContext(hProv, 0);
	}

	HeapFree(heap, 0, hash);
	return success;
}

static BOOL WINAPI CapturePolicyLink(
	_In_ LPCWSTR PolicyLink,
	_Inout_ PCERT_EXTENSIONS CapturedExtensions) {

	SPC_LINK SpcLink{};
	SPC_SP_AGENCY_INFO AgencyInfo{};

	SpcLink.dwLinkChoice = SPC_URL_LINK_CHOICE;
	SpcLink.pwszUrl = (LPWSTR)PolicyLink;
	AgencyInfo.pPolicyInformation = &SpcLink;

	if (!EncodeExtension(
		&CapturedExtensions->rgExtension[CapturedExtensions->cExtension++],
		&AgencyInfo,
		SPC_SP_AGENCY_INFO_OBJID,
		SPC_SP_AGENCY_INFO_OBJID)) {
		return FALSE;
	}

	return TRUE;
}

static BOOL WINAPI CaptureDnsName(
	_In_ PDNS_NAME_LIST DNSName,
	_Inout_ PCERT_EXTENSIONS CapturedExtensions) {

	CERT_ALT_NAME_INFO AltNameInfo{};
	PCERT_ALT_NAME_ENTRY AltNameEntry = nullptr;
	HANDLE heap = GetProcessHeap();

	AltNameEntry = (PCERT_ALT_NAME_ENTRY)HeapAlloc(heap, 0, sizeof(CERT_ALT_NAME_ENTRY) * DNSName->dwNames);
	if (!AltNameEntry)return FALSE;

	AltNameInfo.cAltEntry = DNSName->dwNames;
	AltNameInfo.rgAltEntry = AltNameEntry;

	for (DWORD i = 0; i < DNSName->dwNames; ++i) {
		AltNameEntry[i].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
		AltNameEntry[i].pwszDNSName = (LPWSTR)DNSName->Names[i];
	}

	BOOL result = EncodeExtension(
		&CapturedExtensions->rgExtension[CapturedExtensions->cExtension++],
		&AltNameInfo,
		X509_ALTERNATE_NAME,
		szOID_SUBJECT_ALT_NAME
	);

	HeapFree(heap, 0, AltNameEntry);
	return result;
}

static BOOL WINAPI SignCertificateByPrivateKey(
	_Out_ LPBYTE* SignedCertificate,
	_Out_ LPDWORD SignedCertificateSize,
	_In_ PCERT_INFO CertToBeSigned,
	_In_ LPBYTE PrivateKey,
	_In_ DWORD PrivateKeyLength) {

	__try {
		*SignedCertificate = nullptr;
		*SignedCertificateSize = 0;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	HCRYPTPROV hProv = 0;
	HCRYPTKEY hKey = 0;
	CHAR KeyContainerName[(sizeof(GUID) + 1) * 2];
	HANDLE heap = GetProcessHeap();
	GUID Guid;
	LPBYTE ResultBuffer = nullptr;
	DWORD ResultBufferLength = 0;
	BOOL success = FALSE;

	if (UuidCreate(&Guid));
	ConvertBinaryToHexString(sizeof(Guid), &Guid, KeyContainerName);

	do {
		if (!CryptAcquireContextA(&hProv, KeyContainerName, nullptr, PROV_RSA_FULL, CRYPT_NEWKEYSET))break;

		if (PrivateKeyLength < sizeof(FILE_HDR))break;
		auto hdr = PFILE_HDR(PrivateKey);

		if (hdr->dwMagic != PVK_MAGIC || hdr->dwVersion != PVK_FILE_VERSION_0 || hdr->dwEncryptType || hdr->cbEncryptData || !hdr->cbPvk)break;

		if (!CryptImportKey(hProv, PrivateKey + sizeof(FILE_HDR), hdr->cbPvk, 0, 0, &hKey))break;

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

	if (hKey) {
		CryptDestroyKey(hKey);
	}

	if (hProv) {
		CryptReleaseContext(hProv, 0);
		CryptAcquireContextA(&hProv, KeyContainerName, nullptr, 0, CRYPT_DELETEKEYSET);
	}

	if (!success) {
		HeapFree(heap, 0, ResultBuffer);
	}
	else {
		__try {
			*SignedCertificate = ResultBuffer;
			*SignedCertificateSize = ResultBufferLength;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
	}
	return success;
}

NTSTATUS WINAPI CreateX509Certificate(
	_Out_ PX509CERTIFICATE* SubjectCertificate,
	_Out_ LPBYTE* SignedCertificate,
	_Out_ LPDWORD SignedCertificateSize,
	_In_opt_ PX509CERTIFICATE IssuerCertificate,
	_In_ LPCSTR SubjectX500Name,
	_In_ PKEY_INFO KeyInfo,
	_In_opt_ FILETIME* NotBeforeDate,
	_In_opt_ FILETIME* NotAfterDate,
	_In_opt_ PCRYPT_INTEGER_BLOB SerialNumber,
	_In_opt_ PBASIC_CONSTRAINT BasicConstraint,
	_In_opt_ PKEY_USAGE KeyUsage,
	_In_opt_ LPCWSTR PolicyLink,
	_In_opt_ PDNS_NAME_LIST DNSName,
	_In_opt_ PEKU_LIST EkuList,
	_In_opt_ PCERT_EXTENSIONS OtherExtensions) {

	HANDLE heap = GetProcessHeap();
	NTSTATUS status = STATUS_SUCCESS;
	GUID UniqueSerialNumber{};
	KEY_INFO CapturedKeyInfo;
	CERT_NAME_BLOB CapturedSubjectName{};
	FILETIME CapturedNotBefore{};
	FILETIME CapturedNotAfter{};
	CRYPT_INTEGER_BLOB CapturedSerialNumber{};
	BASIC_CONSTRAINT CapturedBasicConstraint{};
	KEY_USAGE CapturedKeyUsage{};
	CERT_EXTENSIONS CapturedExtensions{};

	__try {
		*SubjectCertificate = nullptr;
		*SignedCertificate = nullptr;
		*SignedCertificateSize = 0;

		if (IssuerCertificate) {
			if (!IssuerCertificate->CertSize || !IssuerCertificate->EncodedCert || !IssuerCertificate->KeyLength || !IssuerCertificate->PrivateKey) {
				return STATUS_INVALID_PARAMETER_4;
			}
		}

		if (!SubjectX500Name)return STATUS_INVALID_PARAMETER_5;

		CapturedKeyInfo = *KeyInfo;

		if (NotBeforeDate) {
			CapturedNotBefore = *NotBeforeDate;
		}
		else {
			GetSystemTimeAsFileTime(&CapturedNotBefore);
		}

		if (NotAfterDate) {
			CapturedNotAfter = *NotAfterDate;
		}
		else {
			SYSTEMTIME st{};
			st.wYear = 2039;
			st.wMonth = 12;
			st.wDay = 31;
			st.wHour = 23;
			st.wMinute = 59;
			st.wSecond = 59;
			SystemTimeToFileTime(&st, &CapturedNotAfter);
		}

		if (SerialNumber) {
			CapturedSerialNumber = *SerialNumber;
		}
		else {
			if (UuidCreate(&UniqueSerialNumber));
			CapturedSerialNumber.cbData = sizeof(GUID);
			CapturedSerialNumber.pbData = LPBYTE(&UniqueSerialNumber);
		}

		if (BasicConstraint) {
			CapturedBasicConstraint = *BasicConstraint;
		}

		if (KeyUsage) {
			CapturedKeyUsage = *KeyUsage;
		}

		if (OtherExtensions) {
			for (DWORD i = 0; i < OtherExtensions->cExtension; ++i) {
				for (DWORD j = 0; j < sizeof(preDefinedExtensions) / sizeof(LPCSTR); ++j) {
					if (!strcmp(OtherExtensions->rgExtension[i].pszObjId, preDefinedExtensions[j])) {
						return STATUS_INVALID_PARAMETER;
					}
				}
			}
		}

		CapturedExtensions.rgExtension = (PCERT_EXTENSION)HeapAlloc(
			heap,
			HEAP_ZERO_MEMORY,
			sizeof(CERT_EXTENSION) * (sizeof(preDefinedExtensions) / sizeof(LPCSTR) + (OtherExtensions ? OtherExtensions->cExtension : 0))
		);
		if (!CapturedExtensions.rgExtension)return STATUS_NO_MEMORY;

		do {
			CertStrToNameA(
				X509_ASN_ENCODING,
				SubjectX500Name,
				CERT_NAME_STR_REVERSE_FLAG,
				nullptr,
				CapturedSubjectName.pbData,
				&CapturedSubjectName.cbData,
				nullptr
			);
			if (!CapturedSubjectName.cbData) {
				status = STATUS_INVALID_PARAMETER_5;
				break;
			}

			CapturedSubjectName.pbData = LPBYTE(HeapAlloc(heap, 0, CapturedSubjectName.cbData));
			if (!CapturedSubjectName.pbData) {
				status = STATUS_NO_MEMORY;
				break;
			}

			if (!CertStrToNameA(
				X509_ASN_ENCODING,
				SubjectX500Name,
				CERT_NAME_STR_REVERSE_FLAG,
				nullptr,
				CapturedSubjectName.pbData,
				&CapturedSubjectName.cbData,
				nullptr)) {
				status = STATUS_INVALID_PARAMETER_5;
				break;
			}

		} while (false);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}

	if (status != STATUS_SUCCESS) {
		HeapFree(heap, 0, CapturedSubjectName.pbData);
		HeapFree(heap, 0, CapturedExtensions.rgExtension);
		return status;
	}

	PX509CERTIFICATE Certificate = nullptr;
	PCERT_INFO cert = nullptr;

	CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm{};

	do {
		status = STATUS_UNSUCCESSFUL;

		Certificate = (PX509CERTIFICATE)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(X509CERTIFICATE));
		if (!Certificate)break;

		Certificate->Source.Create = TRUE;

		Certificate->EncodedCert = cert = (PCERT_INFO)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(CERT_INFO));
		if (!cert)break;

		cert->dwVersion = CERT_V3;

		cert->SerialNumber = CapturedSerialNumber;

		status = STATUS_SUCCESS;
		switch (CapturedKeyInfo.SignatureAlgorithm) {
		case SIGNATURE_ALGORITHM::md5RSA:
			SignatureAlgorithm.pszObjId = (LPSTR)szOID_RSA_MD5RSA;
			break;
		case SIGNATURE_ALGORITHM::sha1RSA:
			SignatureAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA1RSA;
			break;
		case SIGNATURE_ALGORITHM::sha256RSA:
			SignatureAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;
			break;
		case SIGNATURE_ALGORITHM::sha384RSA:
			SignatureAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA384RSA;
			break;
		case SIGNATURE_ALGORITHM::sha512RSA:
			SignatureAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA512RSA;
			break;
		default:
			status = STATUS_INVALID_PARAMETER_3;
			break;
		}

		if (status != STATUS_SUCCESS)break;
		status = STATUS_UNSUCCESSFUL;

		cert->SignatureAlgorithm = SignatureAlgorithm;

		if (IssuerCertificate) {
			cert->Issuer = IssuerCertificate->EncodedCert->Subject;
		}
		else {
			cert->Issuer = CapturedSubjectName;
		}

		cert->NotBefore = CapturedNotBefore;
		cert->NotAfter = CapturedNotAfter;

		cert->Subject = CapturedSubjectName;

		if (!GenerateRSAKeyPair(CapturedKeyInfo.RSAKeyLength, &Certificate->PrivateKey, &Certificate->KeyLength, &Certificate->PublicKeyInfo))break;

		cert->SubjectPublicKeyInfo = *Certificate->PublicKeyInfo;

		cert->IssuerUniqueId = {};
		cert->SubjectUniqueId = {};

		if (BasicConstraint && !CaptureBasicConstraint(&CapturedBasicConstraint, &CapturedExtensions))break;

		if (KeyUsage && !CaptureKeyUsage(&CapturedKeyUsage, &CapturedExtensions))break;

		if (EkuList && !CaptureEnhancedKeyUsage(EkuList, &CapturedExtensions))break;

		if (IssuerCertificate) {
			if (!CaptureAuthorityKeyIdentifier(IssuerCertificate->EncodedCert, &CapturedExtensions))break;
		}
		else {
			if (!CaptureAuthorityKeyIdentifier(Certificate->EncodedCert, &CapturedExtensions))break;
		}

		if (PolicyLink && !CapturePolicyLink(PolicyLink, &CapturedExtensions))break;

		if (DNSName && !CaptureDnsName(DNSName, &CapturedExtensions))break;

		if (OtherExtensions) {
			RtlCopyMemory(
				&CapturedExtensions.rgExtension[CapturedExtensions.cExtension],
				&OtherExtensions->rgExtension[0],
				sizeof(CERT_EXTENSION) * OtherExtensions->cExtension
			);

			CapturedExtensions.cExtension += OtherExtensions->cExtension;
		}

		cert->cExtension = CapturedExtensions.cExtension;
		cert->rgExtension = CapturedExtensions.rgExtension;

		if (!SignCertificateByPrivateKey(
			SignedCertificate,
			SignedCertificateSize,
			Certificate->EncodedCert,
			IssuerCertificate ? IssuerCertificate->PrivateKey : Certificate->PrivateKey,
			IssuerCertificate ? IssuerCertificate->KeyLength : Certificate->KeyLength
		))break;

		status = STATUS_SUCCESS;
	} while (false);

	if (status != STATUS_SUCCESS) {
		CloseX509Certificate(Certificate);
	}
	else {
		__try {
			*SubjectCertificate = Certificate;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
	}

	return status;
}
