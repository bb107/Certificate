#pragma once
/*
	"Exporting a Private Key Marked as Unexportable" Principle Reference:
		*(DWORD*)(*(DWORD*)(*(DWORD*)(hCryptKey + 0x2C) ^ 0xE35A172C) + 8) |= CRYPT_EXPORTABLE | CRYPT_ARCHIVABLE;
	https://www.nccgroup.trust/globalassets/our-research/uk/whitepapers/exporting_non-exportable_rsa_keys.pdf
*/
#include <Windows.h>
#include <wincrypt.h>
#include "EnhKeyUsage.h"
#include "Exceptions.h"

enum SignAlgorithm {
	SignMD5RSA,
	SignSha1RSA,
	SignSha256RSA,
};

#define ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define ALL_KEY_USAGE  (CERT_DIGITAL_SIGNATURE_KEY_USAGE|CERT_NON_REPUDIATION_KEY_USAGE|CERT_KEY_ENCIPHERMENT_KEY_USAGE|CERT_DATA_ENCIPHERMENT_KEY_USAGE|\
CERT_KEY_AGREEMENT_KEY_USAGE | CERT_KEY_CERT_SIGN_KEY_USAGE | CERT_OFFLINE_CRL_SIGN_KEY_USAGE | CERT_CRL_SIGN_KEY_USAGE | CERT_ENCIPHER_ONLY_KEY_USAGE)
#define ALL_KEY_ENHANCED_USAGE	0xffffffffL

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

/*
"CN=Boring Root CA, O=Boring, OU=Boring, L=ShenZhen, S=GuangDong, C=China"

CN: CommonName
OU: OrganizationalUnit
O: Organization
L: Locality
S: StateOrProvinceName
C: CountryName
*/

//CertEnumSystemStore()
#define STORE_MY "my"
#define STORE_CA "ca"
#define STORE_ROOT "root"
#define STORE_SPC "spc"

class __declspec(dllexport) Certificate {
protected:
	//Certificate's Store
	HCERTSTORE m_hCertStore;
	//Certificate Context
	PCCERT_CONTEXT m_pCertContext;
	//Private Key Provider 
	HCRYPTPROV m_hCryptProv;
	//Handle of Private Key
	HCRYPTKEY m_hCryptKey;
	//Private Key Type(Alogrithm)
	DWORD m_dwKeySpec;
	//if m_hCryptProv Need Free
	BOOL m_CallFree;
	//Store's Name (if (m_hCertStore != nullptr) && (m_pStoreName == nullptr), Store is in memory.)
	LPWSTR m_pStoreName;
	//m_hCryptProvider's Container Name
	LPWSTR m_CryptContainer;

	struct _SEARCH_CONTEXT {
		HCERTSTORE store;
		LPWSTR wszCN;
		BOOL StoreClosable;
		PCCERT_CONTEXT cert;
		_SEARCH_CONTEXT();
	};
	//Cert Searching Context
	_SEARCH_CONTEXT*m_search_context;

public:
	//Default
	Certificate();
	Certificate(Certificate& _existed);

	//Open a certificate from store
	Certificate(LPCSTR szCommonName, LPCSTR szStoreName);
	Certificate(LPCWSTR wszCommonName, LPCWSTR wszStoreName);
       
	//Create a self-signed certificate
	Certificate(LPCSTR szX500Name, SignAlgorithm SigAlg = SignSha1RSA, WORD wKeyBits = 1024, WORD wKeyType = AT_SIGNATURE, BYTE bKeyUsage = ALL_KEY_USAGE,
		PSYSTEMTIME lpExpireTime = nullptr, DWORD dwCommonEnhancedKeyUsage = 0, PADD_ENHKEY_SET lpOtherEnhKeyUsage = nullptr);
	Certificate(LPCWSTR szX500Name, SignAlgorithm SigAlg = SignSha1RSA, WORD wKeyBits = 1024, WORD wKeyType = AT_SIGNATURE, BYTE bKeyUsage = ALL_KEY_USAGE,
		PSYSTEMTIME lpExpireTime = nullptr, DWORD dwCommonEnhancedKeyUsage = 0, PADD_ENHKEY_SET lpOtherEnhKeyUsage = nullptr);

	~Certificate();

	//Release CertContext and CryptProvider
	void ReleaseContexts();

	//Search and (re-)open a certificate from store
	NTSTATUS FromStoreA(LPCSTR szCommonName, HCERTSTORE hCertStore);
	NTSTATUS FromStoreW(LPCWSTR wszCommonName, HCERTSTORE hCertStore);
	NTSTATUS FromStoreA(LPCSTR szCommonName, LPCSTR szStoreName);
	NTSTATUS FromStoreW(LPCWSTR wszCommonName, LPCWSTR wszStoreName);
	NTSTATUS FromStoreNext();	//Search next
	NTSTATUS FromStoreEnd();	//Stop search and release search context

	//Open a certificate from file
	NTSTATUS FromFileA(LPCSTR szCertFileName, LPCSTR szPvkFileName = nullptr, LPCSTR szPvkPasswd = nullptr);
	NTSTATUS FromFileW(LPCWSTR wszCertFileName, LPCWSTR wszPvkFileName = nullptr, LPCWSTR wszPvkPasswd = nullptr);

	//Save current cert context to store
	NTSTATUS ToStoreA(LPCSTR szStoreName)const;
	NTSTATUS ToStoreW(LPCWSTR wszStoreName)const;
	NTSTATUS ToStore(HCERTSTORE hStore)const;

	//Save current cert context and pvk to file
	NTSTATUS ToFileA(LPCSTR szCertFileName, LPCSTR szPvkFileName = nullptr, LPCSTR szPvkPasswd = nullptr)const;
	NTSTATUS ToFileW(LPCWSTR wszCertFileName, LPCWSTR wszPvkFileName = nullptr, LPCWSTR wszPvkPasswd = nullptr)const;

	//Open cert from pfx file
	NTSTATUS FromPfxA(LPCSTR szFileName, LPCSTR szPasswd);
	NTSTATUS FromPfxW(LPCWSTR wszFileName, LPCWSTR wszPasswd);

	//Save current cert context to a pfx file
	NTSTATUS ToPfxA(LPCSTR szFileName, LPCSTR szPasswd)const;
	NTSTATUS ToPfxW(LPCWSTR wszFileName, LPCWSTR wszPasswd)const;

	////Save to file cannot save private key (if it exists)
	//NTSTATUS operator>>(HANDLE hOutputFile)const;
	//NTSTATUS operator>>(HCERTSTORE hCertStore)const;

	//(Re-)create a self-signed certificate or apply for a certificate
	NTSTATUS operator()(LPCSTR szX500Name, Certificate* IssuerCertificate = nullptr, SignAlgorithm SigAlg = SignSha1RSA,
		WORD wKeyBits = 1024, WORD wKeyType = AT_SIGNATURE, BYTE bKeyUsage = ALL_KEY_USAGE, BYTE bIsCA = FALSE, WORD wPathConstraint = 0,
		PSYSTEMTIME lpExpireTime = nullptr, DWORD dwCommonEnhancedKeyUsage = 0, PADD_ENHKEY_SET lpOtherEnhKeyUsage = nullptr,
		PCERT_EXTENSIONS lpOtherExtensions = nullptr);
	NTSTATUS operator()(LPCWSTR wszX500Name, Certificate* IssuerCertificate = nullptr, SignAlgorithm SigAlg = SignSha1RSA,
		WORD wKeyBits = 1024, WORD wKeyType = AT_SIGNATURE, BYTE bKeyUsage = ALL_KEY_USAGE, BYTE bIsCA = FALSE, WORD wPathConstraint = 0,
		PSYSTEMTIME lpExpireTime = nullptr, DWORD dwCommonEnhancedKeyUsage = 0, PADD_ENHKEY_SET lpOtherEnhKeyUsage = nullptr,
		PCERT_EXTENSIONS lpOtherExtensions = nullptr);

	//Assignment operator
	Certificate& operator=(Certificate& __right);

	//Destroy Private key in memory
	NTSTATUS DestroyKeyAndDeleteKeySet();

	//Get the cert_context, Call CertFreeCertificateContext() free
	PCCERT_CONTEXT AcquireCertContext()const;

	//Remove cert from store and destroy private key in memory
	//!!!DANGEROUS!!!
	NTSTATUS RemoveFromStoreAndDestroyKeySet();

	//Remove cert from store
	NTSTATUS RemoveFromStore();
};
