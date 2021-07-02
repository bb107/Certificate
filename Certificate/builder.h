#pragma once

BOOL WINAPI CreateX509CertBuilderFromCertFile(
	_Out_ PHANDLE X509CertBuilderHandle,
	_In_ LPCSTR FileName
);

BOOL WINAPI CreateX509CertBuilder(
	_Out_ PHANDLE X509CertBuilderHandle,
	_In_opt_ PCERT_INFO ExistsCert
);

BOOL WINAPI CloseX509CertBuilder(_In_opt_ _Post_ptr_invalid_ HANDLE X509CertBuilderHandle);


#define X509_CERT_SUBJECT_TYPE_CA		CERT_CA_SUBJECT_FLAG
#define X509_CERT_SUBJECT_TYPE_END		CERT_END_ENTITY_SUBJECT_FLAG

BOOL WINAPI X509CertBuilderSetBasicConstraint(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ DWORD PathLenConstraint,
	_In_ DWORD SubjectType,
	_In_ BOOL Critical
);


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
		WORD Reserved : 7;
		WORD DecipherOnly : 1;
	};

	WORD Flags;
}KEY_USAGE, * PKEY_USAGE;

BOOL WINAPI X509CertBuilderSetKeyUsage(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ KEY_USAGE KeyUsage,
	_In_ BOOL Critical
);


#define X509_CERT_POLICY_QUALIFIER_CPS				szOID_PKIX_POLICY_QUALIFIER_CPS
#define X509_CERT_POLICY_QUALIFIER_USERNOTICE		szOID_PKIX_POLICY_QUALIFIER_USERNOTICE

typedef struct _CERT_POLICY_QUALIFIER {
	LPCSTR PolicyQualifierId;

	LPCSTR Qualifier;
}CERT_POLICY_QUALIFIER, * PCERT_POLICY_QUALIFIER;

typedef struct _CERT_POLICY {
	LPCSTR PolicyIdentifier;

	DWORD dwPolicyQualifier;
	PCERT_POLICY_QUALIFIER PolicyQualifiers;
}CERT_POLICY, * PCERT_POLICY;

typedef struct _CERT_POLICY_LIST {
	DWORD dwPolicyInfo;
	PCERT_POLICY Policies;
}CERT_POLICY_LIST, * PCERT_POLICY_LIST;

BOOL WINAPI X509CertBuilderSetPolicies(
	_In_ HANDLE X509CertBuilderHandle,
	_In_reads_bytes_(Policies->dwPolicyInfo * sizeof(CERT_POLICY_INFO)) PCERT_POLICY_LIST Policies,
	_In_ BOOL Critical
);


#define X509_CERT_SAN_TYPE_DNS		CERT_ALT_NAME_DNS_NAME
//#define X509_CERT_SAN_TYPE_IP		CERT_ALT_NAME_IP_ADDRESS

typedef struct _CERT_SAN {
	DWORD type;

	LPCSTR SAN;
}CERT_SAN, * PCERT_SAN;

typedef struct _CERT_SAN_LIST {
	DWORD dwSAN;

	PCERT_SAN SANs;
}CERT_SAN_LIST, * PCERT_SAN_LIST;

BOOL WINAPI X509CertBuilderSetSubjectAlternativeName(
	_In_ HANDLE X509CertBuilderHandle,
	_In_reads_bytes_(SANs->dwSAN * sizeof(CERT_SAN)) PCERT_SAN_LIST SANs,
	_In_ BOOL Critical
);


typedef struct _CERT_ENHANCED_KEY_USAGE_LIST {
	DWORD dwEnhancedKeyUsage;
	LPCSTR EKUs[ANYSIZE_ARRAY];
}CERT_ENHANCED_KEY_USAGE_LIST, * PCERT_ENHANCED_KEY_USAGE_LIST;

BOOL WINAPI X509CertBuilderSetEnhancedKeyUsage(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ PCERT_ENHANCED_KEY_USAGE_LIST EnhancedKeyUsageList,
	_In_ BOOL Critical
);


#define X509_CERT_CRL_DIST_POINT_NAME_URL		CERT_ALT_NAME_URL

typedef struct _CERT_CRL_DIST_POINT_NAME {
	DWORD dwType;

	LPCSTR Name;
}CERT_CRL_DIST_POINT_NAME, * PCERT_CRL_DIST_POINT_NAME, CERT_AUTHORITY_INFO_ACCESS_LOCATION, * PCERT_AUTHORITY_INFO_ACCESS_LOCATION;

#define X509_CERT_CRL_DIST_POINT_NAME_TYPE_FULL_NAME		CRL_DIST_POINT_FULL_NAME

typedef struct _CERT_CRL_DIST_POINT_NAME_LIST {
	DWORD dwName;
	DWORD dwType;

	CERT_CRL_DIST_POINT_NAME Names[ANYSIZE_ARRAY];
}CERT_CRL_DIST_POINT_NAME_LIST, * PCERT_CRL_DIST_POINT_NAME_LIST;

typedef union _CERT_CRL_REASON {
	struct {
		WORD PrivilegeWithdrawn : 1;
		WORD CertificateHold : 1;
		WORD CessationOfOperation : 1;
		WORD Superseded : 1;
		WORD AffiliationChanged : 1;
		WORD CA_Compromise : 1;
		WORD KeyCompromise : 1;
		WORD Unused : 1;

		WORD Reserved : 7;
		WORD AA_Compromise : 1;
	};

	WORD Flags;
}CERT_CRL_REASON;

typedef struct _CERT_CRL_NAME_LIST {
	DWORD dwName;

	CERT_CRL_DIST_POINT_NAME Names[ANYSIZE_ARRAY];
}CERT_CRL_NAME_LIST, * PCERT_CRL_NAME_LIST;

typedef struct _CERT_CRL_DIST_POINT {
	PCERT_CRL_DIST_POINT_NAME_LIST DistPointNames;
	CERT_CRL_REASON ReasonFlags;
	PCERT_CRL_NAME_LIST CRLIssuer;
}CERT_CRL_DIST_POINT, * PCERT_CRL_DIST_POINT;

typedef struct _CERT_CRL_DIST_POINT_LIST {
	DWORD dwCRL;

	CERT_CRL_DIST_POINT CRLs[ANYSIZE_ARRAY];
}CERT_CRL_DIST_POINT_LIST, * PCERT_CRL_DIST_POINT_LIST;

BOOL WINAPI X509CertBuilderSetCRL(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ PCERT_CRL_DIST_POINT_LIST CRLs,
	_In_ BOOL Critical
);


#define X509_CERT_AUTHORITY_INFO_ACCESS_LOCATION_URL		CERT_ALT_NAME_URL

#define X509_CERT_AYTHORITY_INFO_ACCESS_METHOD_CA_ISSUERS	szOID_PKIX_CA_ISSUERS
#define X509_CERT_AYTHORITY_INFO_ACCESS_METHOD_OCSP			szOID_PKIX_OCSP

typedef struct _CERT_AUTHORITY_INFO_ACCESS_ENTRY {
	LPCSTR AccessMethod;

	CERT_AUTHORITY_INFO_ACCESS_LOCATION AccessLocation;
}CERT_AUTHORITY_INFO_ACCESS_ENTRY, * PCERT_AUTHORITY_INFO_ACCESS_ENTRY;

typedef struct _CERT_AUTHORITY_INFO_ACCESS_LIST {
	DWORD dwAccDescr;

	CERT_AUTHORITY_INFO_ACCESS_ENTRY AccDescrs[ANYSIZE_ARRAY];
}CERT_AUTHORITY_INFO_ACCESS_LIST, * PCERT_AUTHORITY_INFO_ACCESS_LIST;

BOOL WINAPI X509CertBuilderSetAuthorityInfoAccess(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ PCERT_AUTHORITY_INFO_ACCESS_LIST AuthorityInfoAccessList,
	_In_ BOOL Critical
);

BOOL WINAPI X509CertBuilderSetAuthorityKeyIdentifier(
	_In_ HANDLE X509CertBuilderHandle,
	_In_opt_ PCERT_ALT_NAME_INFO Issuer,
	_In_opt_ PCRYPT_INTEGER_BLOB IssuerSerialNumber,
	_In_ HANDLE KeyHandle,
	_In_ BOOL Critical
);

BOOL WINAPI X509CertBuilderSetSubjectKeyIdentifier(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ HANDLE KeyHandle,
	_In_ BOOL Critical
);

BOOL WINAPI X509CertBuilderSetEffectiveTime(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ PSYSTEMTIME NotBefore,
	_In_ PSYSTEMTIME NotAfter
);

BOOL WINAPI X509CertBuilderSetSerialNumber(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ PCRYPT_INTEGER_BLOB SerialNumber
);

BOOL WINAPI X509CertBuilderSetSubjectName(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ LPCSTR SubjectX500Name
);

BOOL WINAPI X509CertBuilderSetIssuerName(
	_In_ HANDLE X509CertBuilderHandle,
	_In_opt_ PCERT_NAME_BLOB IssuerName
);


enum class SIGNATURE_ALGORITHM :WORD {
	md5RSA,
	sha1RSA,
	sha256RSA,
	sha384RSA,
	sha512RSA
};

BOOL WINAPI X509CertBuilderSetSignatureAlgorithm(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ SIGNATURE_ALGORITHM SignatureAlgorithm,
	_In_opt_ PCRYPT_OBJID_BLOB Parameters
);

BOOL WINAPI X509CertBuilderSetSubjectPublicKeyInfo(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ HANDLE KeyHandle
);

BOOL WINAPI X509CertBuilderCreateCertInfo(
	_Out_ PCERT_INFO* CertInfo,
	_In_ HANDLE X509CertBuilderHandle
);

BOOL WINAPI X509CertBuilderFreeCertInfo(_In_opt_ _Post_ptr_invalid_ PCERT_INFO CertInfo);
