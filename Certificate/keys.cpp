#include "stdafx.h"

#define RSA_KEY_MAGIC	'RSAK'

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

#define RSA_N_BITS_KEY(n)	(DWORD(WORD(n))<<16)

typedef struct _RSA_KEY {

	DWORD Magic;

	DWORD KeyBufferSize;
	LPBYTE KeyBuffer;

	PCERT_PUBLIC_KEY_INFO PublicKeyBuffer;

}RSA_KEY, * PRSA_KEY;

static PRSA_KEY WINAPI HandleToRSAKey(_In_ HANDLE KeyHandle) {
	PRSA_KEY result = (PRSA_KEY)KeyHandle;

	__try {
		if (result->Magic == RSA_KEY_MAGIC)return result;
		SetLastError(ERROR_INVALID_HANDLE);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}

	return nullptr;
}

BOOL WINAPI OpenRSAKeyFromFile(
	_Out_ PHANDLE KeyHandle,
	_In_ LPCSTR KeyFileName) {
	
	HANDLE heap = GetProcessHeap();
	BOOL success = FALSE;
	PRSA_KEY key = nullptr;

	LPBYTE pbPvk = nullptr;
	DWORD cbPvk = 0;
	DWORD cbPub = 0;

	HCRYPTPROV hProv = 0;
	HCRYPTKEY hKey = 0;

	GUID id;
	CHAR KeyContainerName[(sizeof(GUID) + 1) * 2];
	if (UuidCreate(&id));
	ConvertBinaryToHexString(sizeof(id), &id, KeyContainerName);

	__try {
		*KeyHandle = nullptr;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	do {
		if (!MapFile(KeyFileName, &cbPvk, &pbPvk))break;

		key = (PRSA_KEY)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(RSA_KEY));
		if (!key)break;

		key->Magic = RSA_KEY_MAGIC;

		PFILE_HDR hdr = PFILE_HDR(pbPvk);
		if (cbPvk < sizeof(FILE_HDR) ||
			hdr->dwMagic != PVK_MAGIC ||
			hdr->dwVersion != PVK_FILE_VERSION_0 ||
			hdr->dwEncryptType ||
			hdr->cbEncryptData ||
			!hdr->cbPvk)break;

		if (!CryptAcquireContextA(&hProv, KeyContainerName, nullptr, PROV_RSA_FULL, CRYPT_NEWKEYSET))break;

		if (!CryptImportKey(hProv, pbPvk + sizeof(FILE_HDR), hdr->cbPvk, 0, 0, &hKey))break;

		key->KeyBufferSize = cbPvk;
		key->KeyBuffer = (LPBYTE)HeapAlloc(heap, 0, cbPvk);
		if (!key->KeyBuffer)break;

		RtlCopyMemory(
			key->KeyBuffer,
			pbPvk,
			cbPvk
		);

		CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, key->PublicKeyBuffer, &cbPub);
		if (!cbPub)break;

		key->PublicKeyBuffer = (PCERT_PUBLIC_KEY_INFO)HeapAlloc(heap, 0, cbPub);
		if (!key->PublicKeyBuffer)break;

		success = CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, key->PublicKeyBuffer, &cbPub);

	} while (false);

	if (success) {
		__try {
			*KeyHandle = key;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
	}
	else {
		if (key) {
			HeapFree(heap, 0, key->KeyBuffer);
			HeapFree(heap, 0, key->PublicKeyBuffer);
			HeapFree(heap, 0, key);
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

BOOL WINAPI CreateRSAKey(
	_Out_ PHANDLE KeyHandle,
	_In_ DWORD KeyLength) {

	HCRYPTPROV hProv = 0;
	HCRYPTKEY hKey = 0;

	GUID guid;
	CHAR buffer[(sizeof(guid) + 1) * 2];
	if (UuidCreate(&guid));
	ConvertBinaryToHexString(sizeof(guid), &guid, buffer);

	PRSA_KEY key = nullptr;
	HANDLE heap = GetProcessHeap();
	DWORD PublicKeyInfoLength = 0;
	BOOL success = FALSE;

	__try {
		*KeyHandle = nullptr;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
	
	do {
		key = (PRSA_KEY)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(RSA_KEY));
		if (!key)break;

		key->Magic = RSA_KEY_MAGIC;

		if (!CryptAcquireContextA(&hProv, buffer, nullptr, PROV_RSA_FULL, CRYPT_NEWKEYSET))break;

		if (!CryptGenKey(hProv, AT_SIGNATURE, CRYPT_EXPORTABLE | RSA_N_BITS_KEY(KeyLength), &hKey))break;

		CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, key->KeyBuffer, &key->KeyBufferSize);
		if (!key->KeyBufferSize)break;

		key->KeyBuffer = LPBYTE(HeapAlloc(heap, 0, key->KeyBufferSize + sizeof(FILE_HDR)));
		if (!key->KeyBuffer)break;

		auto hdr = PFILE_HDR(key->KeyBuffer);
		hdr->dwVersion = PVK_FILE_VERSION_0;
		hdr->dwMagic = PVK_MAGIC;
		hdr->cbPvk = key->KeyBufferSize;
		hdr->cbEncryptData = 0;
		hdr->dwEncryptType = PVK_NO_ENCRYPT;
		hdr->dwKeySpec = AT_SIGNATURE;

		if (!CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, key->KeyBuffer + sizeof(FILE_HDR), &key->KeyBufferSize))break;
		key->KeyBufferSize += sizeof(FILE_HDR);

		CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, key->PublicKeyBuffer, &PublicKeyInfoLength);
		if (!PublicKeyInfoLength)break;

		key->PublicKeyBuffer = PCERT_PUBLIC_KEY_INFO(HeapAlloc(heap, 0, PublicKeyInfoLength));
		if (!key->PublicKeyBuffer)break;

		if (!CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, key->PublicKeyBuffer, &PublicKeyInfoLength))break;
		success = TRUE;
	} while (false);

	if (hProv) {
		CryptReleaseContext(hProv, 0);
		CryptAcquireContextA(&hProv, buffer, nullptr, 0, CRYPT_DELETEKEYSET);
	}

	if (hKey) {
		CryptDestroyKey(hKey);
	}

	if (success) {
		__try {
			*KeyHandle = key;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
	}
	else {
		if (key) {
			HeapFree(heap, 0, key->KeyBuffer);
			HeapFree(heap, 0, key->PublicKeyBuffer);
			HeapFree(heap, 0, key);
		}
	}

	return success;
}

BOOL WINAPI CloseRSAKey(_In_opt_ _Post_ptr_invalid_ HANDLE KeyHandle) {
	
	if (KeyHandle) {
		PRSA_KEY key = HandleToRSAKey(KeyHandle);
		HANDLE heap = GetProcessHeap();

		if (!key)return FALSE;

		HeapFree(heap, 0, key->KeyBuffer);
		HeapFree(heap, 0, key->PublicKeyBuffer);
		HeapFree(heap, 0, key);
		return TRUE;
	}

	return FALSE;
}

PCERT_PUBLIC_KEY_INFO WINAPI RSAKeyGetPublicKeyInfo(_In_ HANDLE KeyHandle) {
	PRSA_KEY key = HandleToRSAKey(KeyHandle);

	if (key)return key->PublicKeyBuffer;
	return nullptr;
}

BOOL WINAPI RSAKeyGetCryptProvHandle(
	_Out_ HCRYPTPROV* CryptProv,
	_Out_ HCRYPTKEY* CryptKey,
	_In_ HANDLE KeyHandle) {

	__try {
		*CryptProv = 0;
		*CryptKey = 0;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	PRSA_KEY key = HandleToRSAKey(KeyHandle);

	if (!key)return FALSE;

	HCRYPTPROV hProv = 0;
	HCRYPTKEY hKey = 0;
	HANDLE heap = GetProcessHeap();
	CHAR KeyContainerName[(sizeof(GUID) + 1) * 2];
	GUID Guid;

	if (UuidCreate(&Guid));
	ConvertBinaryToHexString(sizeof(Guid), &Guid, KeyContainerName);

	do {
		if (key->KeyBufferSize < sizeof(FILE_HDR))break;

		auto hdr = PFILE_HDR(key->KeyBuffer);
		if (hdr->dwMagic != PVK_MAGIC || hdr->dwVersion != PVK_FILE_VERSION_0 || hdr->dwEncryptType || hdr->cbEncryptData || !hdr->cbPvk)break;
		
		if (!CryptAcquireContextA(&hProv, KeyContainerName, nullptr, PROV_RSA_FULL, CRYPT_NEWKEYSET))break;

		if (!CryptImportKey(hProv, key->KeyBuffer + sizeof(FILE_HDR), hdr->cbPvk, 0, 0, &hKey))break;

		__try {
			*CryptProv = hProv;
			*CryptKey = hKey;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
		return TRUE;
	} while (false);

	if (hKey) {
		CryptDestroyKey(hKey);
	}

	if (hProv) {
		CryptReleaseContext(hProv, 0);
		CryptAcquireContextA(&hProv, KeyContainerName, nullptr, 0, CRYPT_DELETEKEYSET);
	}
	return FALSE;
}

VOID WINAPI RSAKeyReleaseCryptProvider(
	_In_opt_ HCRYPTPROV CryptProv,
	_In_opt_ HCRYPTKEY CryptKey) {

	LPBYTE name = nullptr;
	DWORD len = 0;
	HANDLE heap = GetProcessHeap();

	if (CryptProv) {
		CryptGetProvParam(
			CryptProv,
			PP_CONTAINER,
			name,
			&len,
			0
		);
		if (!len)return;

		name = (LPBYTE)HeapAlloc(heap, 0, len);
		if (!name)return;

		if (!CryptGetProvParam(
			CryptProv,
			PP_CONTAINER,
			name,
			&len,
			0)) {
			HeapFree(heap, 0, name);
			return;
		}

		CryptReleaseContext(CryptProv, 0);
		CryptAcquireContextA(&CryptProv, (LPCSTR)name, nullptr, 0, CRYPT_DELETEKEYSET);
		HeapFree(heap, 0, name);
	}

	if (CryptKey) {
		CryptDestroyKey(CryptKey);
	}
	
	return;
}

BOOL WINAPI RSAKeySave(
	_In_ HANDLE KeyHandle,
	_In_ COMMON_WRITE_ROUTINE WriteRoutine,
	_In_ LPCVOID Parameter) {

	PRSA_KEY key = HandleToRSAKey(KeyHandle);

	if (!key || !key->KeyBuffer)return FALSE;

	return WriteRoutine(Parameter, key->KeyBuffer, key->KeyBufferSize);
}
