#include "Certificate.h"
#include <vector>
#pragma comment(lib,"crypt32.lib")
#pragma comment(lib,"Rpcrt4.lib")
#pragma warning(disable:4996)
#pragma warning(disable:4267)	//std::vector::size() size_t to DWORD

Certificate::Certificate() {
	RtlZeroMemory(this, sizeof(*this));
}

Certificate::Certificate(Certificate& _existed) {
	this->operator=(_existed);
}

Certificate::Certificate(LPCSTR szCommonName, LPCSTR szStoreName) {
	RtlZeroMemory(this, sizeof(*this));
	NTSTATUS status = FromStoreA(szCommonName, szStoreName);
	if (!NT_SUCCESS(status))throw new CertificateException(status);
}
Certificate::Certificate(LPCWSTR wszCommonName, LPCWSTR wszStoreName) {
	RtlZeroMemory(this, sizeof(*this));
	NTSTATUS status = FromStoreW(wszCommonName, wszStoreName);
	if (!NT_SUCCESS(status))throw new CertificateException(status);
}

Certificate::Certificate(LPCSTR szX500Name, SignAlgorithm SigAlg, WORD wKeyBits, WORD wKeyType, BYTE bKeyUsage,
	PSYSTEMTIME lpExpireTime, DWORD dwCommonEnhancedKeyUsage, PADD_ENHKEY_SET lpOtherEnhKeyUsage) {
	RtlZeroMemory(this, sizeof(*this));
	NTSTATUS status = this->operator()(szX500Name, nullptr, SignSha1RSA, wKeyBits,
		wKeyType, bKeyUsage, TRUE, 0, lpExpireTime, dwCommonEnhancedKeyUsage, lpOtherEnhKeyUsage, nullptr);
	if (!NT_SUCCESS(status))throw new CertificateException(status);
}
Certificate::Certificate(LPCWSTR wszX500Name, SignAlgorithm SigAlg,	WORD wKeyBits, WORD wKeyType, BYTE bKeyUsage,
	PSYSTEMTIME lpExpireTime, DWORD dwCommonEnhancedKeyUsage, PADD_ENHKEY_SET lpOtherEnhKeyUsage) {
	RtlZeroMemory(this, sizeof(*this));
	NTSTATUS status = this->operator()(wszX500Name, nullptr, SignSha1RSA, wKeyBits,
		wKeyType, bKeyUsage, TRUE, 0, lpExpireTime, dwCommonEnhancedKeyUsage, lpOtherEnhKeyUsage, nullptr);
	if (!NT_SUCCESS(status))throw new CertificateException(status);
}

Certificate::~Certificate() {
	this->FromStoreEnd();
	this->ReleaseContexts();
}

void Certificate::ReleaseContexts() {
	if (this->m_hCryptProv && this->m_CallFree)CryptReleaseContext(this->m_hCryptProv, 0);
	if (this->m_pCertContext)CertFreeCertificateContext(this->m_pCertContext);
	if (this->m_CryptContainer)delete[]this->m_CryptContainer;
	if (this->m_hCertStore)CertCloseStore(this->m_hCertStore, 0);
	if (this->m_hCryptKey)CryptDestroyKey(this->m_hCryptKey);
	if (this->m_pStoreName)delete[]this->m_pStoreName;
	RtlZeroMemory(this, sizeof(*this));
}

NTSTATUS Certificate::FromStoreA(LPCSTR szCommonName, HCERTSTORE hCertStore) {
	size_t szCommonNameLen = strlen(szCommonName) + 1;
	LPWSTR wszCommonName = new WCHAR[szCommonNameLen];
	mbstowcs(wszCommonName, szCommonName, szCommonNameLen);
	NTSTATUS success = FromStoreW(wszCommonName, hCertStore);
	delete[]wszCommonName;
	return success;
}
NTSTATUS Certificate::FromStoreW(LPCWSTR wszCommonName, HCERTSTORE hCertStore) {
	//Release the last search context
	this->FromStoreEnd();
	_SEARCH_CONTEXT* context = new _SEARCH_CONTEXT;
	context->store = hCertStore;
	context->cert = CertFindCertificateInStore(context->store, ENCODING_TYPE, 0, CERT_FIND_SUBJECT_STR_W, wszCommonName, NULL);
	if (!context->cert) {
		delete context;
		return STATUS_CN_NOT_FOUND;
	}

	//Release old contexts
	this->ReleaseContexts();

	context->wszCN = wcscpy(new WCHAR[wcslen(wszCommonName) + 1], wszCommonName);
	context->StoreClosable = FALSE;
	this->m_search_context = context;
	this->m_pCertContext = context->cert;
	if (!CryptAcquireCertificatePrivateKey(context->cert, 0, nullptr, &this->m_hCryptProv, &this->m_dwKeySpec, &this->m_CallFree) ||
		!CryptGetUserKey(this->m_hCryptProv, this->m_dwKeySpec, &this->m_hCryptKey))return STATUS_NO_KEY;
	*(size_t*)(*(size_t*)(*(size_t*)(this->m_hCryptKey + OFFSET_1) ^ XOR_KEY) + OFFSET_2) |= CRYPT_EXPORTABLE | CRYPT_ARCHIVABLE;
	return STATUS_SUCCESS;
}

NTSTATUS Certificate::FromStoreA(LPCSTR szCommonName, LPCSTR szStoreName) {
	size_t szStoreNameLen = strlen(szStoreName) + 1,
		szCommonNameLen = strlen(szCommonName) + 1;
	LPWSTR wszStoreName = new WCHAR[szStoreNameLen],
		wszCommonName = new WCHAR[szCommonNameLen];
	mbstowcs(wszStoreName, szStoreName, szStoreNameLen);
	mbstowcs(wszCommonName, szCommonName, szCommonNameLen);
	NTSTATUS success = FromStoreW(wszCommonName, wszStoreName);
	delete[]wszCommonName;
	delete[]wszStoreName;
	return success;
}
NTSTATUS Certificate::FromStoreW(LPCWSTR wszCommonName, LPCWSTR wszStoreName) {
	//Release the last search context
	this->FromStoreEnd();

	//Create new search context
	_SEARCH_CONTEXT* context = new _SEARCH_CONTEXT;
	context->store = CertOpenStore(CERT_STORE_PROV_SYSTEM,
		ENCODING_TYPE, NULL,
		CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
		wszStoreName);
	if (!context->store) {
		delete context;
		return STATUS_OPEN_STORE;
	}
	context->cert = CertFindCertificateInStore(context->store, ENCODING_TYPE, 0, CERT_FIND_SUBJECT_STR_W, wszCommonName, NULL);
	if (!context->cert) {
		CertCloseStore(context->store, 0);
		delete context;
		return STATUS_CN_NOT_FOUND;
	}

	//Release old contexts
	this->ReleaseContexts();

	context->wszCN = wcscpy(new WCHAR[wcslen(wszCommonName) + 1], wszCommonName);
	context->StoreClosable = TRUE;
	this->m_search_context = context;
	this->m_pCertContext = context->cert;
	if (!CryptAcquireCertificatePrivateKey(context->cert, 0, nullptr, &this->m_hCryptProv, &this->m_dwKeySpec, &this->m_CallFree) ||
		!CryptGetUserKey(this->m_hCryptProv, this->m_dwKeySpec, &this->m_hCryptKey))return STATUS_NO_KEY;
	*(size_t*)(*(size_t*)(*(size_t*)(this->m_hCryptKey + OFFSET_1) ^ XOR_KEY) + OFFSET_2) |= CRYPT_EXPORTABLE | CRYPT_ARCHIVABLE;
	return STATUS_SUCCESS;
}

NTSTATUS Certificate::FromStoreNext() {
	_SEARCH_CONTEXT* context = this->m_search_context;
	if (!context)return STATUS_NEW_SEARCH;

	PCCERT_CONTEXT cert = CertFindCertificateInStore(context->store, ENCODING_TYPE, 0, CERT_FIND_SUBJECT_STR_W, context->wszCN, context->cert);
	if (!cert) return STATUS_SEARCH_END;

	this->ReleaseContexts();
	context->cert = cert;
	this->m_search_context = context;
	this->m_pCertContext = context->cert;
	if (!CryptAcquireCertificatePrivateKey(context->cert, 0, nullptr, &this->m_hCryptProv, &this->m_dwKeySpec, &this->m_CallFree) ||
		!CryptGetUserKey(this->m_hCryptProv, this->m_dwKeySpec, &this->m_hCryptKey))return STATUS_NO_KEY;
	*(size_t*)(*(size_t*)(*(size_t*)(this->m_hCryptKey + OFFSET_1) ^ XOR_KEY) + OFFSET_2) |= CRYPT_EXPORTABLE | CRYPT_ARCHIVABLE;
	return STATUS_SUCCESS;
}

NTSTATUS Certificate::FromStoreEnd() {
	if (!this->m_search_context)return STATUS_NEW_SEARCH;
	if (this->m_search_context->store && this->m_search_context->StoreClosable)CertCloseStore(this->m_search_context->store, 0);
	if (this->m_search_context->wszCN)delete[]this->m_search_context->wszCN;
	delete this->m_search_context;
	this->m_search_context = nullptr;
	return STATUS_SUCCESS;
}

NTSTATUS Certificate::FromFileA(LPCSTR szCertFileName, LPCSTR szPvkFileName, LPCSTR szPvkPasswd) {
	size_t szCertFileNameLen = strlen(szCertFileName) + 1,
		szPvkFileNameLen = strlen(szPvkFileName) + 1,
		szPvkPasswdLen = strlen(szPvkPasswd) + 1;
	LPWSTR wszCertFileName = new WCHAR[szCertFileNameLen],
		wszPvkFileName = new WCHAR[szPvkFileNameLen],
		wszPvkPasswd = new WCHAR[szPvkPasswdLen];
	mbstowcs(wszCertFileName, szCertFileName, szCertFileNameLen);
	mbstowcs(wszPvkFileName, szPvkFileName, szPvkFileNameLen);
	mbstowcs(wszPvkPasswd, szPvkPasswd, szPvkPasswdLen);
	NTSTATUS success = FromFileW(wszCertFileName, wszPvkFileName, wszPvkPasswd);
	delete[]wszCertFileName;
	delete[]wszPvkFileName;
	delete[]wszPvkPasswd;
	return success;
}
NTSTATUS Certificate::FromFileW(LPCWSTR wszCertFileName, LPCWSTR wszPvkFileName, LPCWSTR wszPvkPasswd) {
	if (!wszCertFileName || (!wszPvkFileName && wszPvkPasswd) || (wszPvkFileName && !wszPvkPasswd))return STATUS_INVALID_PARAMETER;
	HANDLE hFile = CreateFileW(wszCertFileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hFile)return STATUS_OPEN_FILE;
	DWORD dwSize = GetFileSize(hFile, nullptr);
	LPBYTE pData = new BYTE[dwSize];
	if (!ReadFile(hFile, pData, dwSize, nullptr, nullptr)) {
		delete[]pData;
		CloseHandle(hFile);
		return STATUS_READ_FILE;
	}
	CloseHandle(hFile);
	hFile = nullptr;

	HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_MEMORY, ENCODING_TYPE, 0, 0, nullptr);
	PCCERT_CONTEXT pCertContext = nullptr;
	if (!hStore) {
		delete[]pData;
		return STATUS_OPEN_STORE;
	}
	if (!CertAddEncodedCertificateToStore(hStore, ENCODING_TYPE, pData, dwSize, CERT_STORE_ADD_REPLACE_EXISTING, &pCertContext)) {
		delete[]pData;
		CertCloseStore(hStore, 0);
		return STATUS_ADD_TO_STORE;
	}
	delete[]pData;
	pData = nullptr;
	dwSize = 0;

	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	HCRYPTKEY hExchangeKey = 0, hKey = 0;
	DWORD dwKeySpec = 0;
	LPWSTR wszContainer = nullptr;
	if (wszPvkFileName) {
		try {
			UUID uuid;
			BOOL success;
			CRYPT_KEY_PROV_INFO CryptKeyProvInfo = { 0 };
			if (!(hFile = CreateFileW(wszPvkFileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)))
				throw STATUS_OPEN_FILE;
			dwSize = GetFileSize(hFile, nullptr);
			pData = new BYTE[dwSize];
			if (!ReadFile(hFile, pData, dwSize, nullptr, nullptr))throw STATUS_READ_FILE;
			CloseHandle(hFile);
			hFile = nullptr;
			if (!CryptAcquireContextW(&hProv, L"BoringsoftOriginal", nullptr, PROV_RSA_FULL, 0) &&
				!CryptAcquireContextW(&hProv, L"BoringsoftOriginal", nullptr, PROV_RSA_FULL, CRYPT_NEWKEYSET))
				throw STATUS_CRYPT_PROVIDER;
			success = CryptGenRandom(hProv, sizeof(uuid), (LPBYTE)&uuid);
			CryptReleaseContext(hProv, 0);
			CryptAcquireContextA(&hProv, "BoringsoftOriginal", nullptr, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
			if (!success) throw STATUS_GEN_RANDOM;
			if (RPC_S_OK != UuidToStringW(&uuid, (RPC_WSTR*)(&wszContainer))) throw STATUS_RPC_CALL;
			if (!CryptAcquireContextW(&hProv, wszContainer, nullptr, PROV_RSA_FULL, CRYPT_NEWKEYSET))
				throw STATUS_CRYPT_PROVIDER;
			if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))throw STATUS_CREATE_HASH;
			if (!CryptHashData(hHash, (BYTE*)wszPvkPasswd, wcslen(wszPvkPasswd), 0))throw STATUS_HASH_DATA;
			if (!CryptDeriveKey(hProv, CALG_RC4, hHash, CRYPT_EXPORTABLE, &hExchangeKey))throw STATUS_DERIVE_KEY;
			if (!CryptImportKey(hProv, pData, dwSize, hExchangeKey, CRYPT_EXPORTABLE, &hKey))throw STATUS_BAD_EXCHANGE_KEY;
			delete[]pData;
			pData = nullptr;
			if (!CryptGetKeyParam(hKey, KP_ALGID, (LPBYTE)&dwKeySpec, &(dwSize = sizeof(DWORD)), 0))throw STATUS_GET_KEY_PARAM;
			switch (dwKeySpec) {
			case CALG_DH_SF:
			case CALG_RSA_KEYX:dwKeySpec = AT_KEYEXCHANGE; break;
			case CALG_DSS_SIGN:
			case CALG_RSA_SIGN:dwKeySpec = AT_SIGNATURE; break;
			}
			CryptKeyProvInfo.dwKeySpec = dwKeySpec;
			CryptKeyProvInfo.dwProvType = PROV_RSA_FULL;
			CryptKeyProvInfo.pwszContainerName = wszContainer;
			if (!CertSetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &CryptKeyProvInfo))
				throw STATUS_SET_CERT_PROP_KEY_ID;
		}
		catch (NTSTATUS status) {
			CertDeleteCertificateFromStore(pCertContext);
			CertCloseStore(hStore, 0);
			if (hFile)CloseHandle(hFile);
			if (pData)delete[]pData;
			if (hExchangeKey)CryptDestroyKey(hExchangeKey);
			if (hKey)CryptDestroyKey(hKey);
			if (hHash)CryptDestroyHash(hHash);
			if (hProv) {
				CryptReleaseContext(hProv, 0);
				if (wszContainer) {
					CryptAcquireContextW(&hProv, wszContainer, nullptr, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
					RpcStringFreeW((RPC_WSTR*)(&wszContainer));
				}
			}
			return status;
		}
		CryptDestroyHash(hHash);
		CryptDestroyKey(hExchangeKey);
	}

	this->FromStoreEnd();
	this->ReleaseContexts();

	this->m_pCertContext = pCertContext;
	this->m_hCertStore = hStore;
	if (wszPvkFileName) {
		this->m_CallFree = TRUE;
		this->m_CryptContainer = wcscpy(new wchar_t[wcslen(wszContainer) + 1], wszContainer);
		this->m_dwKeySpec = dwKeySpec;
		this->m_hCryptKey = hKey;
		this->m_hCryptProv = hProv;
		RpcStringFreeW((RPC_WSTR*)(&wszContainer));
		return STATUS_SUCCESS;
	}
	return STATUS_NO_KEY;
}

NTSTATUS Certificate::ToStoreA(LPCSTR szStoreName) const {
	if (!this->m_pCertContext)return STATUS_INVALID_CERTIFICATE_CONTEXT;
	HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, ENCODING_TYPE, NULL,
		CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER, szStoreName);
	if (!hStore)return STATUS_OPEN_STORE;
	NTSTATUS status = ToStore(hStore);
	CertCloseStore(hStore, 0);
	return status;
}
NTSTATUS Certificate::ToStoreW(LPCWSTR wszStoreName) const {
	if (!this->m_pCertContext)return STATUS_INVALID_CERTIFICATE_CONTEXT;
	HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, ENCODING_TYPE, NULL,
		CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER, wszStoreName);
	if (!hStore)return STATUS_OPEN_STORE;
	NTSTATUS status = ToStore(hStore);
	CertCloseStore(hStore, 0);
	return status;
}
NTSTATUS Certificate::ToStore(HCERTSTORE hStore) const {
	PCCERT_CONTEXT pNewContext;
	if (!CertAddCertificateContextToStore(hStore, this->m_pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, &pNewContext))
		return STATUS_ADD_TO_STORE;
	CRYPT_KEY_PROV_INFO CryptKeyProvInfo = { 0 };
	PCRYPT_KEY_PROV_INFO pCryptKeyProvInfo = &CryptKeyProvInfo;
	DWORD dwSize = sizeof(CryptKeyProvInfo);
	BOOL pvk_success = FALSE;
	CryptKeyProvInfo.dwKeySpec = this->m_dwKeySpec;
	CryptKeyProvInfo.dwProvType = PROV_RSA_FULL;
	if (this->m_CryptContainer) {
		CryptKeyProvInfo.pwszContainerName = this->m_CryptContainer;
	}
	else {
		if (!CertGetCertificateContextProperty(this->m_pCertContext, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &dwSize))pCryptKeyProvInfo = nullptr;
		else {
			pCryptKeyProvInfo = reinterpret_cast<PCRYPT_KEY_PROV_INFO>(new char[dwSize]);
			if (!CertGetCertificateContextProperty(this->m_pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pCryptKeyProvInfo, &dwSize)) {
				delete[]reinterpret_cast<LPVOID>(pCryptKeyProvInfo);
				pCryptKeyProvInfo = nullptr;
			}
		}
	}
	if (pCryptKeyProvInfo) {
		pvk_success = CertSetCertificateContextProperty(pNewContext, CERT_KEY_PROV_INFO_PROP_ID, 0, pCryptKeyProvInfo);
		if (pCryptKeyProvInfo != &CryptKeyProvInfo)delete[]reinterpret_cast<LPVOID>(pCryptKeyProvInfo);
	}
	CertFreeCertificateContext(pNewContext);
	return pvk_success ? STATUS_SUCCESS : STATUS_NO_KEY;
}

NTSTATUS Certificate::ToFileA(LPCSTR szCertFileName, LPCSTR szPvkFileName, LPCSTR szPvkPasswd) const {
	size_t szCertFileNameLen = strlen(szCertFileName) + 1,
		szPvkFileNameLen = strlen(szPvkFileName) + 1,
		szPvkPasswdLen = strlen(szPvkPasswd) + 1;
	LPWSTR wszCertFileName = new WCHAR[szCertFileNameLen],
		wszPvkFileName = new WCHAR[szPvkFileNameLen],
		wszPvkPasswd = new WCHAR[szPvkPasswdLen];
	mbstowcs(wszCertFileName, szCertFileName, szCertFileNameLen);
	mbstowcs(wszPvkFileName, szPvkFileName, szPvkFileNameLen);
	mbstowcs(wszPvkPasswd, szPvkPasswd, szPvkPasswdLen);
	NTSTATUS success = ToFileW(wszCertFileName, wszPvkFileName, wszPvkPasswd);
	delete[]wszCertFileName;
	delete[]wszPvkFileName;
	delete[]wszPvkPasswd;
	return success;
}
NTSTATUS Certificate::ToFileW(LPCWSTR wszCertFileName, LPCWSTR wszPvkFileName, LPCWSTR wszPvkPasswd) const {
	if (!wszCertFileName || ((!wszCertFileName) && wszPvkPasswd))return STATUS_INVALID_PARAMETER;
	if (!this->m_pCertContext)return STATUS_INVALID_CERTIFICATE_CONTEXT;
	HANDLE hFile = CreateFileW(wszCertFileName, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, nullptr);
	BOOL success;
	if (!hFile)return STATUS_CREATE_FILE;
	success = WriteFile(hFile, this->m_pCertContext->pbCertEncoded, this->m_pCertContext->cbCertEncoded, nullptr, nullptr);
	CloseHandle(hFile);
	if (!success) return STATUS_WRITE_FILE;

	HCRYPTHASH hHash = 0;
	HCRYPTKEY hExchangeKey = 0, pvk = this->m_hCryptKey;
	LPBYTE lpPrivateKeyBlob = nullptr;
	hFile = nullptr;
	try {
		if (wszPvkFileName) {
			DWORD dwSize = 0;
			if (!pvk || !this->m_hCryptProv)throw STATUS_INVALID_CRYPT_HANDLE;
			if (!CryptCreateHash(this->m_hCryptProv, CALG_SHA1, 0, 0, &hHash))throw STATUS_CREATE_HASH;
			if (!CryptHashData(hHash, (BYTE*)wszPvkPasswd, wcslen(wszPvkPasswd), 0))throw STATUS_HASH_DATA;
			if (!CryptDeriveKey(this->m_hCryptProv, CALG_RC4, hHash, CRYPT_EXPORTABLE, &hExchangeKey))throw STATUS_DERIVE_KEY;
			if (!CryptExportKey(pvk, hExchangeKey, PRIVATEKEYBLOB, 0, nullptr, &dwSize))throw STATUS_EXPORT_PRIV_KEY;
			lpPrivateKeyBlob = new BYTE[dwSize];
			if (!CryptExportKey(pvk, hExchangeKey, PRIVATEKEYBLOB, 0, lpPrivateKeyBlob, &dwSize))throw STATUS_EXPORT_PRIV_KEY;
			if (!(hFile = CreateFileW(wszPvkFileName, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
				FILE_ATTRIBUTE_NORMAL, nullptr)))throw STATUS_CREATE_FILE;
			if (!WriteFile(hFile, lpPrivateKeyBlob, dwSize, nullptr, nullptr))throw STATUS_WRITE_FILE;
			CloseHandle(hFile);
			CryptDestroyKey(hExchangeKey);
			CryptDestroyHash(hHash);
			delete[]lpPrivateKeyBlob;
		}
	}
	catch (NTSTATUS status) {
		if (hFile)CloseHandle(hFile);
		if (hHash)CryptDestroyHash(hHash);
		if (hExchangeKey)CryptDestroyKey(hExchangeKey);
		if (lpPrivateKeyBlob)delete[]lpPrivateKeyBlob;
		return status;
	}
	return STATUS_SUCCESS;
}

NTSTATUS Certificate::FromPfxA(LPCSTR szFileName, LPCSTR szPasswd) {
	size_t szFileNameLen = strlen(szFileName) + 1,
		szPasswdLen = strlen(szPasswd) + 1;
	LPWSTR wszFileName = new WCHAR[szFileNameLen],
		wszPasswd = new WCHAR[szPasswdLen];
	mbstowcs(wszFileName, szFileName, szFileNameLen);
	mbstowcs(wszPasswd, szPasswd, szPasswdLen);
	NTSTATUS success = FromPfxW(wszFileName, wszPasswd);
	delete[]wszFileName;
	delete[]wszPasswd;
	return success;
}
NTSTATUS Certificate::FromPfxW(LPCWSTR wszFileName, LPCWSTR wszPasswd) {
	if (!wszFileName || !wszPasswd)return STATUS_INVALID_PARAMETER;

	CRYPT_DATA_BLOB pPfx = { 0 };
	HANDLE hPfx = nullptr;
	HCERTSTORE hStore = nullptr;
	PCCERT_CONTEXT pCertContext = nullptr;
	HCRYPTPROV hProv = 0;
	HCRYPTKEY hKey = 0;
	DWORD dwKeySpec = 0;
	LPWSTR wszContainer = nullptr;
	PCRYPT_KEY_PROV_INFO CryptKeyProvInfo = nullptr;

	try {
		DWORD dwSize = 0;
		hPfx = CreateFileW(wszFileName, GENERIC_READ, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (!hPfx)throw STATUS_CREATE_FILE;
		pPfx.cbData = GetFileSize(hPfx, nullptr);
		pPfx.pbData = new BYTE[pPfx.cbData];
		if (!ReadFile(hPfx, pPfx.pbData, pPfx.cbData, nullptr, nullptr))throw STATUS_READ_FILE;
		if (!PFXIsPFXBlob(&pPfx))throw STATUS_FILE_TYPE;
		if (!PFXVerifyPassword(&pPfx, wszPasswd, 0))throw STATUS_BAD_EXCHANGE_KEY;
		if (!(hStore = PFXImportCertStore(&pPfx, wszPasswd, CRYPT_EXPORTABLE | CRYPT_USER_KEYSET)))throw STATUS_IMPORT_PFX;
		if (!(pCertContext = CertEnumCertificatesInStore(hStore, nullptr))) return STATUS_ENUM_STORE;
		if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &dwSize))
			throw STATUS_GET_CERT_PROP_KEY_ID;
		CryptKeyProvInfo = reinterpret_cast<PCRYPT_KEY_PROV_INFO>(new char[dwSize]);
		if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, CryptKeyProvInfo, &dwSize))
			throw STATUS_GET_CERT_PROP_KEY_ID;
		dwKeySpec = CryptKeyProvInfo->dwKeySpec;
		wszContainer = wcscpy(new wchar_t[wcslen(CryptKeyProvInfo->pwszContainerName) + 1], CryptKeyProvInfo->pwszContainerName);
		if (!CryptAcquireContextW(&hProv, CryptKeyProvInfo->pwszContainerName, CryptKeyProvInfo->pwszProvName, PROV_RSA_FULL, 0))
			throw STATUS_CRYPT_PROVIDER;
		if (CryptGetUserKey(hProv, dwKeySpec, &hKey))
			*(size_t*)(*(size_t*)(*(size_t*)(hKey + OFFSET_1) ^ XOR_KEY) + OFFSET_2) |= CRYPT_EXPORTABLE | CRYPT_ARCHIVABLE;
	}
	catch (NTSTATUS status) {
		if (pPfx.pbData)delete[]pPfx.pbData;
		if (hPfx)CloseHandle(hPfx);
		if (CryptKeyProvInfo)delete[]reinterpret_cast<LPVOID>(CryptKeyProvInfo);
		if (wszContainer)delete[]wszContainer;
		if (hStore)CertCloseStore(hStore, 0);
		if (pCertContext)CertFreeCertificateContext(pCertContext);
		return status;
	}

	delete[]pPfx.pbData;
	CloseHandle(hPfx);
	delete[]reinterpret_cast<LPVOID>(CryptKeyProvInfo);

	this->FromStoreEnd();
	this->ReleaseContexts();

	this->m_CallFree = (this->m_hCryptProv = hProv) ? TRUE : FALSE;
	this->m_CryptContainer = wszContainer;
	this->m_dwKeySpec = dwKeySpec;
	this->m_hCertStore = hStore;
	this->m_hCryptKey = hKey;
	this->m_pCertContext = pCertContext;
	
	return STATUS_SUCCESS;
}

NTSTATUS Certificate::ToPfxA(LPCSTR szFileName, LPCSTR szPasswd) const {
	size_t szFileNameLen = strlen(szFileName) + 1,
		szPasswdLen = strlen(szPasswd) + 1;
	LPWSTR wszFileName = new WCHAR[szFileNameLen],
		wszPasswd = new WCHAR[szPasswdLen];
	mbstowcs(wszFileName, szFileName, szFileNameLen);
	mbstowcs(wszPasswd, szPasswd, szPasswdLen);
	NTSTATUS success = ToPfxW(wszFileName, wszPasswd);
	delete[]wszFileName;
	delete[]wszPasswd;
	return success;
}
NTSTATUS Certificate::ToPfxW(LPCWSTR wszFileName, LPCWSTR wszPasswd) const {
	if (!wszFileName || !wszPasswd)return STATUS_INVALID_PARAMETER;

	CRYPT_DATA_BLOB pPfx = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	HCERTSTORE hStore = nullptr;
	HANDLE hPfx = nullptr;
	
	try {
		hStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, CERT_STORE_CREATE_NEW_FLAG, 0);
		if (!hStore)throw STATUS_OPEN_STORE;
		hPfx = CreateFileW(wszFileName, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (!hPfx)throw STATUS_CREATE_FILE;
		if (!NT_SUCCESS(status = this->ToStore(hStore))) throw status;
		if (!PFXExportCertStoreEx(hStore, &pPfx, wszPasswd, nullptr,
			EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY))
			throw STATUS_EXPORT_PFX;
		pPfx.pbData = new BYTE[pPfx.cbData];
		if (!PFXExportCertStoreEx(hStore, &pPfx, wszPasswd, nullptr,
			EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY))
			throw STATUS_EXPORT_PFX;
		if (!WriteFile(hPfx, pPfx.pbData, pPfx.cbData, nullptr, nullptr))throw STATUS_WRITE_FILE;
	}
	catch (NTSTATUS status) {
		if (hStore)CertCloseStore(hStore, 0);
		if (hPfx)CloseHandle(hPfx);
		if (pPfx.pbData)delete[]pPfx.pbData;
		return status;
	}
	CertCloseStore(hStore, 0);
	CloseHandle(hPfx);
	delete[]pPfx.pbData;

	return STATUS_SUCCESS;
}

NTSTATUS Certificate::operator()(LPCSTR szX500Name, const Certificate* IssuerCertificate, SignAlgorithm SigAlg,
	WORD wKeyBits, WORD wKeyType, BYTE bKeyUsage, BYTE bIsCA, WORD wPathConstraint,
	PSYSTEMTIME lpExpireTime, DWORD dwCommonEnhancedKeyUsage, PADD_ENHKEY_SET lpOtherEnhKeyUsage, PCERT_EXTENSIONS lpOtherExtensions) {
	size_t szX500NameLen = strlen(szX500Name) + 1;
	LPWSTR wszX500Name = new WCHAR[szX500NameLen];
	mbstowcs(wszX500Name, szX500Name, szX500NameLen);
	NTSTATUS success = this->operator()(wszX500Name, IssuerCertificate, SigAlg, wKeyBits, wKeyType, bKeyUsage, bIsCA, wPathConstraint,
		lpExpireTime, dwCommonEnhancedKeyUsage, lpOtherEnhKeyUsage, lpOtherExtensions);
	delete[]wszX500Name;
	return success;
}
NTSTATUS Certificate::operator()(LPCWSTR wszX500Name, const Certificate* IssuerCertificate, SignAlgorithm SigAlg,
	WORD wKeyBits, WORD wKeyType, BYTE bKeyUsage, BYTE bIsCA, WORD wPathConstraint,
	PSYSTEMTIME lpExpireTime, DWORD dwCommonEnhancedKeyUsage, PADD_ENHKEY_SET lpOtherEnhKeyUsage, PCERT_EXTENSIONS lpOtherExtensions) {
	//Check if Issuer Certificate is invalid
	if (IssuerCertificate && ((!IssuerCertificate->m_hCryptProv) || (!IssuerCertificate->m_pCertContext)))return STATUS_ISSUER_CERTIFICATE;

	//Subject name
	CERT_NAME_BLOB SubjectName = { 0 };
	if (!CertStrToNameW(ENCODING_TYPE, wszX500Name, CERT_X500_NAME_STR, nullptr, nullptr, &SubjectName.cbData, nullptr))
		return STATUS_X500_CONVERT;
	SubjectName.pbData = new BYTE[SubjectName.cbData];
	if (!CertStrToNameW(ENCODING_TYPE, wszX500Name, CERT_X500_NAME_STR, nullptr, SubjectName.pbData, &SubjectName.cbData, nullptr)) {
		delete[]SubjectName.pbData;
		return STATUS_X500_CONVERT;
	}
	
	//prepare for crypt provider
	HCRYPTPROV hProv = 0;
	HCRYPTKEY hKey = 0;
	LPWSTR wszContainer = nullptr;
	try {
		UUID uid;
		BOOL success;
		if (!CryptAcquireContextA(&hProv, "Boringsoft", nullptr, PROV_RSA_FULL, 0) &&
			!CryptAcquireContextA(&hProv, "Boringsoft", nullptr, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			throw STATUS_CRYPT_PROVIDER;
		success = CryptGenRandom(hProv, sizeof(uid), reinterpret_cast<LPBYTE>(&uid));
		CryptReleaseContext(hProv, 0);
		CryptAcquireContextA(&hProv, "Boringsoft", nullptr, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
		if (!success) throw STATUS_GEN_RANDOM;
		if (RPC_S_OK != UuidToStringW(&uid, (RPC_WSTR*)(&wszContainer))) throw STATUS_RPC_CALL;
		if (!CryptAcquireContextW(&hProv, wszContainer, nullptr, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			throw STATUS_CRYPT_PROVIDER;
		if (!CryptGenKey(hProv, wKeyType, CRYPT_EXPORTABLE | (wKeyBits << 16), &hKey)) {
			CryptReleaseContext(hProv, 0);
			CryptAcquireContextW(&hProv, wszContainer, nullptr, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
			throw STATUS_GEN_KEY;
		}
	}
	catch (NTSTATUS status) {
		delete[]SubjectName.pbData;
		if (wszContainer)RpcStringFreeW((RPC_WSTR*)(&wszContainer));
		return status;
	}

	//CertInfo
	CERT_INFO CertInfo;
	std::vector<PCERT_EXTENSION>CertExtensionList(0);
	PCERT_PUBLIC_KEY_INFO pCertPublicKeyInfo = nullptr;
	CRYPT_DATA_BLOB CertKeyIdentifier = { 0 };
	RtlZeroMemory(&CertInfo, sizeof(CertInfo));
	CertInfo.dwVersion = CERT_V3;
	CertInfo.Subject = SubjectName;
	CertInfo.Issuer = IssuerCertificate ? IssuerCertificate->m_pCertContext->pCertInfo->Subject : SubjectName;
	try {
		PCERT_EXTENSION pCertExtension = nullptr;

		//Cert time and serial number
		{
			SYSTEMTIME SystemTime;
			if (!CryptGenRandom(hProv, CertInfo.SerialNumber.cbData = 8, CertInfo.SerialNumber.pbData = new BYTE[8]))
				throw STATUS_GEN_RANDOM;
			switch (SigAlg) {
			case SignMD5RSA:
				CertInfo.SignatureAlgorithm.pszObjId = (LPSTR)szOID_RSA_MD5RSA; break;
			case SignSha1RSA:
				CertInfo.SignatureAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA1RSA; break;
			case SignSha256RSA:
				CertInfo.SignatureAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA256RSA; break;
			default:
				throw STATUS_BAD_SIGN_ALG;
			}
			GetSystemTimeAsFileTime(&CertInfo.NotBefore);
			GetSystemTime(&SystemTime);
			SystemTime.wYear += 40;
			SystemTimeToFileTime(lpExpireTime ? lpExpireTime : &SystemTime, &CertInfo.NotAfter);
		}

		//public key info and key identifier (extension)
		{
			DWORD dwInfoLen = 0;
			if (!CryptExportPublicKeyInfo(hProv, wKeyType, ENCODING_TYPE, nullptr, &dwInfoLen))
				throw STATUS_EXPORT_PUB_KEY;
			pCertPublicKeyInfo = reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(new char[dwInfoLen]);
			if (!CryptExportPublicKeyInfo(hProv, wKeyType, ENCODING_TYPE, pCertPublicKeyInfo, &dwInfoLen))
				throw STATUS_EXPORT_PUB_KEY;
			CertInfo.SubjectPublicKeyInfo = *pCertPublicKeyInfo;

			HCRYPTHASH hHash = 0;
			if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))throw STATUS_CREATE_HASH;
			if (!CryptHashData(hHash, reinterpret_cast<LPBYTE>(pCertPublicKeyInfo), dwInfoLen, 0))
				throw STATUS_HASH_DATA;
			if (!CryptGetHashParam(hHash, HP_HASHVAL, nullptr, &CertKeyIdentifier.cbData, 0))throw STATUS_GET_HASH_VAL;
			CertKeyIdentifier.pbData = new BYTE[CertKeyIdentifier.cbData];
			if (!CryptGetHashParam(hHash, HP_HASHVAL, CertKeyIdentifier.pbData, &CertKeyIdentifier.cbData, 0))
				throw STATUS_GET_HASH_VAL;
			pCertExtension = new CERT_EXTENSION;
			RtlZeroMemory(pCertExtension, sizeof(*pCertExtension));
			if (!CryptEncodeObject(ENCODING_TYPE, szOID_SUBJECT_KEY_IDENTIFIER, &CertKeyIdentifier,
				nullptr, &(pCertExtension->Value.cbData))) {
				delete pCertExtension;
				throw STATUS_ENCODE_KEY_ID;
			}
			pCertExtension->Value.pbData = new BYTE[pCertExtension->Value.cbData];
			if (!CryptEncodeObject(ENCODING_TYPE, szOID_SUBJECT_KEY_IDENTIFIER, &CertKeyIdentifier,
				pCertExtension->Value.pbData, &(pCertExtension->Value.cbData))) {
				delete[]pCertExtension->Value.pbData;
				delete pCertExtension;
				throw STATUS_ENCODE_KEY_ID;
			}
			pCertExtension->pszObjId = (LPSTR)szOID_SUBJECT_KEY_IDENTIFIER;
			pCertExtension->fCritical = FALSE;
			CertExtensionList.push_back(pCertExtension);
		}

		//key usage (extension)
		{
			CRYPT_BIT_BLOB KeyUsage = { 1,&bKeyUsage };
			pCertExtension = new CERT_EXTENSION;
			RtlZeroMemory(pCertExtension, sizeof(*pCertExtension));
			if (!CryptEncodeObject(ENCODING_TYPE, X509_KEY_USAGE, &KeyUsage, nullptr, &pCertExtension->Value.cbData)) {
				delete pCertExtension;
				throw STATUS_ENCODE_KEY_USAGE;
			}
			pCertExtension->Value.pbData = new BYTE[pCertExtension->Value.cbData];
			if (!CryptEncodeObject(ENCODING_TYPE, X509_KEY_USAGE, &KeyUsage, pCertExtension->Value.pbData, &pCertExtension->Value.cbData)) {
				delete[]pCertExtension->Value.pbData;
				delete pCertExtension;
				throw STATUS_ENCODE_KEY_USAGE;
			}
			pCertExtension->fCritical = FALSE;
			pCertExtension->pszObjId = (LPSTR)szOID_KEY_USAGE;
			CertExtensionList.push_back(pCertExtension);
		}

		//Enhanced Key usage (extension)
		if (dwCommonEnhancedKeyUsage || (lpOtherEnhKeyUsage && lpOtherEnhKeyUsage->dwUsage)) {
			DWORD dwEnhUseCount = lpOtherEnhKeyUsage ? lpOtherEnhKeyUsage->dwUsage : 0;
			for (DWORD i = 1, count = 1; count <= 32; count++, i <<= 1) {
				if (dwCommonEnhancedKeyUsage & i)dwEnhUseCount++;
			}
			PCERT_ENHKEY_USAGE pCertEnhKeyUsage = reinterpret_cast<PCERT_ENHKEY_USAGE>(new char[sizeof(DWORD) * 2 + sizeof(LPSTR) * (dwEnhUseCount + 1)]);
			pCertEnhKeyUsage->cUsageIdentifier = dwEnhUseCount;
			pCertEnhKeyUsage->rgpszUsageIdentifier = (LPSTR*)(((size_t)&pCertEnhKeyUsage->rgpszUsageIdentifier) + sizeof(LPSTR));
			if (lpOtherEnhKeyUsage) {
				RtlCopyMemory(pCertEnhKeyUsage->rgpszUsageIdentifier, 
					lpOtherEnhKeyUsage->UsageIdentifiers, 
					sizeof(LPSTR) * lpOtherEnhKeyUsage->dwUsage);
				dwEnhUseCount -= lpOtherEnhKeyUsage->dwUsage;
			}
			for (DWORD i = 1, count = 1, index = (lpOtherEnhKeyUsage ? lpOtherEnhKeyUsage->dwUsage - 1 : 0); count <= 32; i <<= 1, count++) {
				if (dwCommonEnhancedKeyUsage & i) {
					pCertEnhKeyUsage->rgpszUsageIdentifier[index++] = EnhancedKeyUsageList[count - 1];
				}
			}

			pCertExtension = new CERT_EXTENSION;
			RtlZeroMemory(pCertExtension, sizeof(*pCertExtension));
			if (!CryptEncodeObject(ENCODING_TYPE, X509_ENHANCED_KEY_USAGE, pCertEnhKeyUsage, nullptr, &pCertExtension->Value.cbData)) {
				delete pCertExtension;
				delete[]reinterpret_cast<LPVOID>(pCertEnhKeyUsage);
				throw STATUS_ENCODE_KEY_ENH_USAGE;
			}
			pCertExtension->Value.pbData = new BYTE[pCertExtension->Value.cbData];
			if (!CryptEncodeObject(ENCODING_TYPE, X509_ENHANCED_KEY_USAGE, pCertEnhKeyUsage, pCertExtension->Value.pbData, &pCertExtension->Value.cbData)) {
				delete[]pCertExtension->Value.pbData;
				delete pCertExtension;
				delete[]reinterpret_cast<LPVOID>(pCertEnhKeyUsage);
				throw STATUS_ENCODE_KEY_ENH_USAGE;
			}
			delete[]reinterpret_cast<LPVOID>(pCertEnhKeyUsage);
			pCertExtension->fCritical = FALSE;
			pCertExtension->pszObjId = (LPSTR)szOID_ENHANCED_KEY_USAGE;
			CertExtensionList.push_back(pCertExtension);
		}

		//Basic Constraints (extension)
		{
			CERT_BASIC_CONSTRAINTS2_INFO BasicConstraint = { bIsCA,wPathConstraint ? TRUE : FALSE,wPathConstraint };
			pCertExtension = new CERT_EXTENSION;
			RtlZeroMemory(pCertExtension, sizeof(*pCertExtension));
			if (!CryptEncodeObject(ENCODING_TYPE, X509_BASIC_CONSTRAINTS2, &BasicConstraint, nullptr, &pCertExtension->Value.cbData)) {
				delete pCertExtension;
				throw STATUS_ENCODE_KEY_USAGE;
			}
			pCertExtension->Value.pbData = new BYTE[pCertExtension->Value.cbData];
			if (!CryptEncodeObject(ENCODING_TYPE, X509_BASIC_CONSTRAINTS2, &BasicConstraint, pCertExtension->Value.pbData, &pCertExtension->Value.cbData)) {
				delete[]pCertExtension->Value.pbData;
				delete pCertExtension;
				throw STATUS_ENCODE_KEY_USAGE;
			}
			pCertExtension->fCritical = FALSE;
			pCertExtension->pszObjId = (LPSTR)szOID_BASIC_CONSTRAINTS2;
			CertExtensionList.push_back(pCertExtension);
		}

		//Cert authority key id (extension)
		{
			CERT_AUTHORITY_KEY_ID_INFO CertAuthorityKeyId;
			//CertAuthorityKeyId.KeyId = CertKeyIdentifier;
			PCRYPT_DATA_BLOB DataBlob = nullptr;
			
			if (IssuerCertificate) {
				PCERT_EXTENSION KeyId = CertFindExtension(szOID_SUBJECT_KEY_IDENTIFIER,
					IssuerCertificate->m_pCertContext->pCertInfo->cExtension,
					IssuerCertificate->m_pCertContext->pCertInfo->rgExtension);
				DWORD dwSize = 0;
				if (KeyId) {
					if (!CryptDecodeObject(ENCODING_TYPE, szOID_SUBJECT_KEY_IDENTIFIER,
						KeyId->Value.pbData, KeyId->Value.cbData, 0, nullptr, &dwSize))throw STATUS_DECODE_KEY_ID;
					DataBlob = reinterpret_cast<PCRYPT_DATA_BLOB>(new char[dwSize]);
					if (!CryptDecodeObject(ENCODING_TYPE, szOID_SUBJECT_KEY_IDENTIFIER,
						KeyId->Value.pbData, KeyId->Value.cbData, 0, DataBlob, &dwSize)) {
						delete[]reinterpret_cast<LPVOID>(DataBlob);
						throw STATUS_DECODE_KEY_ID;
					}
				}
			}
			if (DataBlob || ((!DataBlob) && (!IssuerCertificate))) {
				CertAuthorityKeyId.KeyId = DataBlob ? *DataBlob : CertKeyIdentifier;
				CertAuthorityKeyId.CertIssuer = (IssuerCertificate ?
					IssuerCertificate->m_pCertContext->pCertInfo->Subject : SubjectName);
				CertAuthorityKeyId.CertSerialNumber = (IssuerCertificate ?
					IssuerCertificate->m_pCertContext->pCertInfo->SerialNumber : CertInfo.SerialNumber);
				pCertExtension = new CERT_EXTENSION;
				if (!CryptEncodeObject(ENCODING_TYPE, X509_AUTHORITY_KEY_ID, &CertAuthorityKeyId,
					nullptr, &pCertExtension->Value.cbData)) {
					if (DataBlob)delete[]reinterpret_cast<LPVOID>(DataBlob);
					delete pCertExtension;
					throw STATUS_ENCODE_AUTH_KEY_ID;
				}
				pCertExtension->Value.pbData = new BYTE[pCertExtension->Value.cbData];
				if (!CryptEncodeObject(ENCODING_TYPE, X509_AUTHORITY_KEY_ID, &CertAuthorityKeyId,
					pCertExtension->Value.pbData, &pCertExtension->Value.cbData)) {
					if (DataBlob)delete[]reinterpret_cast<LPVOID>(DataBlob);
					delete[]pCertExtension->Value.pbData;
					delete pCertExtension;
					throw STATUS_ENCODE_AUTH_KEY_ID;
				}
				if (DataBlob)delete[]reinterpret_cast<LPVOID>(DataBlob);
				pCertExtension->fCritical = FALSE;
				pCertExtension->pszObjId = (LPSTR)szOID_AUTHORITY_KEY_IDENTIFIER;
				CertExtensionList.push_back(pCertExtension);
			}
		}

		//CertExtensionList to CertExtension
		{
			CertInfo.cExtension = CertExtensionList.size() + (lpOtherExtensions ? lpOtherExtensions->cExtension : 0);
			CertInfo.rgExtension = new CERT_EXTENSION[CertInfo.cExtension];
			if (lpOtherExtensions)
				RtlCopyMemory(CertInfo.rgExtension, lpOtherExtensions->rgExtension,
					sizeof(CERT_EXTENSION) * lpOtherExtensions->cExtension);
			for (DWORD dwExtensionCount = lpOtherExtensions ? lpOtherExtensions->cExtension : 0;
				dwExtensionCount < CertInfo.cExtension; dwExtensionCount++) {
				CertInfo.rgExtension[dwExtensionCount] =
					*CertExtensionList[dwExtensionCount - (lpOtherExtensions ? lpOtherExtensions->cExtension : 0)];
				delete CertExtensionList[dwExtensionCount];
			}
			CertExtensionList.clear();
		}

	}
	catch (NTSTATUS status) {
		delete[]SubjectName.pbData;
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProv, 0);
		CryptAcquireContextW(&hProv, wszContainer, nullptr, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
		if (CertInfo.SerialNumber.pbData)delete[]CertInfo.SerialNumber.pbData;
		if (pCertPublicKeyInfo)delete[]pCertPublicKeyInfo;
		if (CertKeyIdentifier.pbData)delete[]CertKeyIdentifier.pbData;
		for (std::vector<PCERT_EXTENSION>::const_iterator i = CertExtensionList.cbegin(); i != CertExtensionList.end(); i++) {
			PCERT_EXTENSION tmp = (*i);
			if (tmp->Value.pbData)delete[]tmp->Value.pbData;
			delete tmp;
		}
		CertExtensionList.clear();
		if (CertInfo.rgExtension) {
			for (DWORD i = 0; i < CertInfo.cExtension; i++) {
				if (CertInfo.rgExtension[i].Value.pbData)delete[]CertInfo.rgExtension[i].Value.pbData;
			}
		}
		RpcStringFreeW((RPC_WSTR*)(&wszContainer));
		return status;
	}

	//Sign certificate
	LPBYTE pbCertEncoded = nullptr;
	DWORD cbCertEncoded = 0;
	BOOL success =
		CryptSignAndEncodeCertificate(IssuerCertificate ? IssuerCertificate->m_hCryptProv : hProv,
			IssuerCertificate ? IssuerCertificate->m_dwKeySpec : wKeyType, ENCODING_TYPE, X509_CERT_TO_BE_SIGNED, &CertInfo,
			IssuerCertificate ? &(IssuerCertificate->m_pCertContext->pCertInfo->SignatureAlgorithm) : &(CertInfo.SignatureAlgorithm)
			, nullptr, nullptr, &cbCertEncoded) &&
		CryptSignAndEncodeCertificate(IssuerCertificate ? IssuerCertificate->m_hCryptProv : hProv,
			IssuerCertificate ? IssuerCertificate->m_dwKeySpec : wKeyType, ENCODING_TYPE, X509_CERT_TO_BE_SIGNED, &CertInfo,
			IssuerCertificate ? &(IssuerCertificate->m_pCertContext->pCertInfo->SignatureAlgorithm) : &(CertInfo.SignatureAlgorithm)
			, nullptr, pbCertEncoded = new BYTE[cbCertEncoded], &cbCertEncoded);
	//Clean
	delete[]SubjectName.pbData;
	delete[]CertInfo.SerialNumber.pbData;
	delete[]pCertPublicKeyInfo;
	delete[]CertKeyIdentifier.pbData;
	if (CertInfo.rgExtension) {
		for (DWORD i = 0; i < CertInfo.cExtension; i++) {
			if (CertInfo.rgExtension[i].Value.pbData)delete[]CertInfo.rgExtension[i].Value.pbData;
		}
	}
	if (!success) {
		if (pbCertEncoded)delete[]pbCertEncoded;
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProv, 0);
		CryptAcquireContextW(&hProv, wszContainer, nullptr, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
		RpcStringFreeW((RPC_WSTR*)(&wszContainer));
		return STATUS_SIGN_CERTIFICATE;
	}

	//Create Cert store in memory
	HCERTSTORE hTmpStore = CertOpenStore(CERT_STORE_PROV_MEMORY, ENCODING_TYPE, 0, 0, nullptr);
	PCCERT_CONTEXT pTmpContext = nullptr;
	CRYPT_KEY_PROV_INFO CryptKeyProvInfo = { 0 };
	try {
		if (!hTmpStore) throw STATUS_OPEN_STORE;
		if (!CertAddEncodedCertificateToStore(hTmpStore, ENCODING_TYPE,
			pbCertEncoded, cbCertEncoded, CERT_STORE_ADD_REPLACE_EXISTING, &pTmpContext)) {
			CertCloseStore(hTmpStore, 0);
			throw STATUS_ADD_TO_STORE;
		}
		CryptKeyProvInfo.dwKeySpec = wKeyType;
		CryptKeyProvInfo.dwProvType = PROV_RSA_FULL;
		CryptKeyProvInfo.pwszContainerName = wszContainer;
		if (!CertSetCertificateContextProperty(pTmpContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &CryptKeyProvInfo)) {
			CertFreeCertificateContext(pTmpContext);
			CertCloseStore(hTmpStore, 0);
			throw STATUS_SET_CERT_PROP_KEY_ID;
		}
	}
	catch (NTSTATUS status) {
		delete[]pbCertEncoded;
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProv, 0);
		CryptAcquireContextW(&hProv, wszContainer, nullptr, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
		RpcStringFreeW((RPC_WSTR*)(&wszContainer));
		return status;
	}

	if (this->m_search_context)this->FromStoreEnd();
	this->ReleaseContexts();

	this->m_CallFree = TRUE;
	this->m_CryptContainer = wcscpy(new wchar_t[wcslen(wszContainer) + 1], wszContainer);
	this->m_dwKeySpec = wKeyType;
	this->m_hCertStore = hTmpStore;
	this->m_hCryptKey = hKey;
	this->m_hCryptProv = hProv;
	this->m_pCertContext = pTmpContext;
	this->m_pStoreName = nullptr;
	RpcStringFreeW((RPC_WSTR*)(&wszContainer));

	return STATUS_SUCCESS;
}

Certificate* Certificate::IssueCertificate(LPCSTR szX500Name, SignAlgorithm SigAlg, WORD wKeyBits,
	WORD wKeyType, BYTE bKeyUsage, BYTE bIsCA, WORD wPathConstraint, PSYSTEMTIME lpExpireTime,
	DWORD dwCommonEnhancedKeyUsage, PADD_ENHKEY_SET lpOtherEnhKeyUsage, PCERT_EXTENSIONS lpOtherExtensions) const {
	Certificate* subject = new Certificate;
	if (NT_SUCCESS((*subject)(szX500Name, this, SigAlg, wKeyBits, wKeyType, bKeyUsage,
		bIsCA, wPathConstraint, lpExpireTime, dwCommonEnhancedKeyUsage,
		lpOtherEnhKeyUsage, lpOtherExtensions)))return subject;
	delete subject;
	return nullptr;
}
Certificate* Certificate::IssueCertificate(LPCWSTR wszX500Name, SignAlgorithm SigAlg, WORD wKeyBits,
	WORD wKeyType, BYTE bKeyUsage, BYTE bIsCA, WORD wPathConstraint, PSYSTEMTIME lpExpireTime,
	DWORD dwCommonEnhancedKeyUsage, PADD_ENHKEY_SET lpOtherEnhKeyUsage, PCERT_EXTENSIONS lpOtherExtensions) const {
	Certificate* subject = new Certificate;
	if (NT_SUCCESS((*subject)(wszX500Name, this, SigAlg, wKeyBits, wKeyType, bKeyUsage,
		bIsCA, wPathConstraint, lpExpireTime, dwCommonEnhancedKeyUsage,
		lpOtherEnhKeyUsage, lpOtherExtensions)))return subject;
	delete subject;
	return nullptr;
}

Certificate& Certificate::operator=(Certificate& __right) {
	if (__right.m_pCertContext) {
		this->m_pCertContext = CertDuplicateCertificateContext(__right.m_pCertContext);
		if (!this->m_pCertContext)throw new CertificateException(STATUS_INVALID_CERTIFICATE_CONTEXT);
	}
	if (__right.m_hCryptProv) {
		CryptAcquireCertificatePrivateKey(this->m_pCertContext, 0, nullptr, &this->m_hCryptProv, &this->m_dwKeySpec, &m_CallFree);
	}
	this->m_CryptContainer = __right.m_CryptContainer ? wcscpy(new wchar_t[wcslen(__right.m_CryptContainer) + 1], __right.m_CryptContainer) : nullptr;
	this->m_pStoreName = __right.m_pStoreName ? wcscpy(new wchar_t[wcslen(__right.m_pStoreName) + 1], __right.m_pStoreName) : nullptr;
	if (__right.m_hCryptKey)CryptDuplicateKey(__right.m_hCryptKey, nullptr, 0, &this->m_hCryptKey);
	if (__right.m_hCertStore) {
		this->m_hCertStore = CertOpenStore(
			this->m_pStoreName ? CERT_STORE_PROV_SYSTEM : CERT_STORE_PROV_MEMORY, ENCODING_TYPE, 0, 0, this->m_pStoreName);
	}
	if (this->m_hCryptKey)*(size_t*)(*(size_t*)(*(size_t*)(this->m_hCryptKey + OFFSET_1) ^ XOR_KEY) + OFFSET_2) |= CRYPT_EXPORTABLE | CRYPT_ARCHIVABLE;
	return *this;
}

NTSTATUS Certificate::DestroyKeyAndDeleteKeySet() {
	if (this->m_hCryptKey) {
		CryptDestroyKey(this->m_hCryptKey);
		this->m_hCryptKey = 0;
		this->m_dwKeySpec = 0;
	}
	if (this->m_hCryptProv) {
		CryptReleaseContext(this->m_hCryptProv, 0);
		this->m_hCryptProv;
	}
	if (this->m_CryptContainer) {
		CryptAcquireContextW(&this->m_hCryptProv, this->m_CryptContainer, nullptr, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
	}
	return STATUS_SUCCESS;
}

PCCERT_CONTEXT Certificate::AcquireCertContext() const {
	if (!this->m_pCertContext)return nullptr;
	return CertDuplicateCertificateContext(this->m_pCertContext);
}

NTSTATUS Certificate::RemoveFromStoreAndDestroyKeySet() {
	if (!this->m_pCertContext)return STATUS_INVALID_CERTIFICATE_CONTEXT;
	PCRYPT_KEY_PROV_INFO pCryptKeyProvInfo = nullptr;
	DWORD dwSize = 0;
	HCRYPTPROV hProv;
	this->DestroyKeyAndDeleteKeySet();
	if (CertGetCertificateContextProperty(this->m_pCertContext, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &dwSize)) {
		pCryptKeyProvInfo = reinterpret_cast<PCRYPT_KEY_PROV_INFO>(new char[dwSize]);
		if (!CertGetCertificateContextProperty(this->m_pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pCryptKeyProvInfo, &dwSize)) {
			delete[]reinterpret_cast<LPVOID>(pCryptKeyProvInfo);
			pCryptKeyProvInfo = nullptr;
		}
		CryptAcquireContextW(&hProv, pCryptKeyProvInfo->pwszContainerName, pCryptKeyProvInfo->pwszProvName, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
		delete[]reinterpret_cast<LPVOID>(pCryptKeyProvInfo);
	}
	return this->RemoveFromStore();
}

NTSTATUS Certificate::RemoveFromStore() {
	if (!this->m_pCertContext)return STATUS_INVALID_CERTIFICATE_CONTEXT;
	CertDeleteCertificateFromStore(this->m_pCertContext);
	this->ReleaseContexts();
	return STATUS_SUCCESS;
}

Certificate::_SEARCH_CONTEXT::_SEARCH_CONTEXT() {
	RtlZeroMemory(this, sizeof(*this));
}
