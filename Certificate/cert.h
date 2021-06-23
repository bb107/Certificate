#pragma once
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <wincrypt.h>
#include <WinTrust.h>

#define RSA_N_BITS_KEY(n)	(DWORD(WORD(n))<<16)

enum class SIGNATURE_ALGORITHM :WORD {
	md5RSA,
	sha1RSA,
	sha256RSA,
	sha384RSA,
	sha512RSA
};

typedef struct _SERIAL_NUMBER {
	DWORD cbData;
	LPBYTE pbData;
}SERIAL_NUMBER, * PSERIAL_NUMBER;

typedef struct _EKU_LIST {
	DWORD EkuCount;
	LPCSTR Ekus[ANYSIZE_ARRAY];
}EKU_LIST, * PEKU_LIST;

typedef struct _BASIC_CONSTRAINT {
	DWORD MaxPathHeight;

	struct {
		union {
			struct {
				BYTE End : 1;
				BYTE Authority : 1;
			};

			BYTE CertType;
		};
		
		BYTE Reserved[3];
	};

}BASIC_CONSTRAINT, * PBASIC_CONSTRAINT;

typedef union _KEY_USAGE {
	struct {
		WORD EncipherOnly : 1;
		WORD OfflineClrSign : 1;
		WORD KeyCertSign : 1;
		WORD KeyAgreement : 1;
		WORD DataEncipherment : 1;
		WORD KeyEncipherment : 1;
		WORD NonRepudiation : 1;
		WORD DigitalSignature : 1;
		WORD DecipherOnly : 1;
	};

	WORD Flags;
}KEY_USAGE;

typedef union _SIGNING_AUTHORITY {
	struct {
		WORD Individual : 1;
		WORD Commercial : 1;
	};

	WORD Flags;
}SIGNING_AUTHORITY;

typedef struct _KEY_USAGE_RESTRICTION {
	KEY_USAGE KeyUsage;
	SIGNING_AUTHORITY SigningAuthority;
}KEY_USAGE_RESTRICTION, * PKEY_USAGE_RESTRICTION;

typedef struct _KEY_INFO {
	SIGNATURE_ALGORITHM SignatureAlgorithm;
	WORD RSAKeyLength;
}KEY_INFO, * PKEY_INFO;

typedef struct _DNS_NAME_LIST {
	DWORD dwNames;
	LPCWSTR Names[ANYSIZE_ARRAY];
}DNS_NAME_LIST, * PDNS_NAME_LIST;

typedef struct _X509CERTIFICATE {
	LPBYTE PrivateKey;
	DWORD KeyLength;

	DWORD CertSize;
	PCERT_INFO EncodedCert;

	PCERT_PUBLIC_KEY_INFO PublicKeyInfo;

	union {
		struct {
			DWORD Create : 1;
		};

		DWORD Flags;
	};
}X509CERTIFICATE, * PX509CERTIFICATE;



BOOL WINAPI OpenX509Certificate(
	_Out_ PX509CERTIFICATE* Certificate,
	_In_ LPCSTR CertificateFileName,
	_In_opt_ LPCSTR CertificatePvkFileName
);

VOID WINAPI CloseX509Certificate(
	_In_opt_ _Post_ptr_invalid_ PX509CERTIFICATE Certificate
);

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
	_In_opt_ PKEY_USAGE_RESTRICTION KeyUsageRestriction,
	_In_opt_ LPCWSTR PolicyLink,
	_In_opt_ PDNS_NAME_LIST DNSName,
	_In_opt_ PEKU_LIST EkuList,
	_In_opt_ PCERT_EXTENSIONS OtherExtensions
);
