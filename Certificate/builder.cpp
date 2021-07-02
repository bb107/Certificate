#include "stdafx.h"

#define X509_CERT_BUILDER_MAGIC				0x05099050

#define CERT_EXTENSION_BASIC_CONSTRAINT				0x00000001
#define CERT_EXTENSION_KEY_USAGE					0x00000002
#define CERT_EXTENSION_CERT_POLICIES				0x00000004
#define CERT_EXTENSION_SUBJECT_ALTERNATIVE_NAME		0x00000008
#define CERT_EXTENSION_ENHANCED_KEY_USAGE			0x00000010
#define CERT_EXTENSION_CRL_DISTRIBUTION_POINT		0x00000020
#define CERT_EXTENSION_AUTHORITY_INFO_ACCESS		0x00000040
//#define CERT_EXTENSION_SCTS							0x00000080
#define CERT_EXTENSION_AUTHORITY_KET_IDENTIFIER		0x00000100
#define CERT_EXTENSION_SUBJECT_KEY_IDENTIFIER		0x00000200

#define CERT_EXTENSION_BASIC_CONSTRAINT_INDEX			0
#define CERT_EXTENSION_KEY_USAGE_INDEX					1
#define CERT_EXTENSION_CERT_POLICIES_INDEX				2
#define CERT_EXTENSION_SUBJECT_ALTERNATIVE_NAME_INDEX	3
#define CERT_EXTENSION_ENHANCED_KEY_USAGE_INDEX			4
#define CERT_EXTENSION_CRL_DISTRIBUTION_POINT_INDEX		5
#define CERT_EXTENSION_AUTHORITY_INFO_ACCESS_INDEX		6
//#define CERT_EXTENSION_SCTS_INDEX						7
#define CERT_EXTENSION_AUTHORITY_KET_IDENTIFIER_INDEX	8
#define CERT_EXTENSION_SUBJECT_KEY_IDENTIFIER_INDEX		9

const LPCSTR CERT_EXTENSION_OIDS[] = {
	szOID_BASIC_CONSTRAINTS,
	szOID_KEY_USAGE,
	szOID_CERT_POLICIES,
	szOID_SUBJECT_ALT_NAME2,
	szOID_ENHANCED_KEY_USAGE,
	szOID_CRL_DIST_POINTS,
	szOID_AUTHORITY_INFO_ACCESS,
	"not implemented oid",
	szOID_AUTHORITY_KEY_IDENTIFIER2,
	szOID_SUBJECT_KEY_IDENTIFIER
};

#define CERT_EXTENSION_COUNT						10


typedef struct _X509_CERT_BUILDER {
	DWORD Magic;

	union {
		struct {
			WORD ExtensionsMask;

			WORD TimeIsSet : 1;
			WORD Reserved : 15;
		}s1;

		DWORD Mask;
	}u1;

	CERT_NAME_BLOB IssuerName;
	CERT_NAME_BLOB SubjectX500Name;
	FILETIME NotBeforeDate;
	FILETIME NotAfterDate;
	CRYPT_INTEGER_BLOB SerialNumber;
	CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
	CERT_PUBLIC_KEY_INFO PublicKeyInfo;

	CERT_EXTENSION Extension[CERT_EXTENSION_COUNT];
}X509_CERT_BUILDER, * PX509_CERT_BUILDER;

static PX509_CERT_BUILDER WINAPI HandleToX509CertBuilder(_In_ HANDLE X509CertBuilderHandle) {
	PX509_CERT_BUILDER builder = PX509_CERT_BUILDER(X509CertBuilderHandle);

	__try {
		if (builder->Magic != X509_CERT_BUILDER_MAGIC) {
			SetLastError(ERROR_INVALID_HANDLE);
			return nullptr;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return nullptr;
	}

	return builder;
}

static BOOL WINAPI EncodeIA5String(
	_In_ LPCSTR lpString,
	_Out_ PCRYPT_OBJID_BLOB EncodedString) {

	HANDLE heap = GetProcessHeap();
	CERT_NAME_VALUE q;
	q.dwValueType = CERT_RDN_IA5_STRING;
	q.Value.cbData = strlen(lpString);
	q.Value.pbData = (LPBYTE)lpString;

	EncodedString->cbData = 0;
	EncodedString->pbData = nullptr;

	CryptEncodeObject(
		X509_ASN_ENCODING,
		X509_ANY_STRING,
		&q,
		EncodedString->pbData,
		&EncodedString->cbData
	);
	if (!EncodedString->cbData)return FALSE;

	EncodedString->pbData = (LPBYTE)HeapAlloc(heap, 0, EncodedString->cbData);
	if (!EncodedString->pbData)return FALSE;

	if (!CryptEncodeObject(
		X509_ASN_ENCODING,
		X509_ANY_STRING,
		&q,
		EncodedString->pbData,
		&EncodedString->cbData)) {
		HeapFree(heap, 0, EncodedString->pbData);
		return FALSE;
	}

	return TRUE;
}

static LPWSTR toUnicode(LPCSTR lpString) {

	LPWSTR buffer = nullptr;
	HANDLE heap = GetProcessHeap();

	int len = MultiByteToWideChar(CP_ACP, 0, lpString, -1, nullptr, 0);
	if (len) {
		buffer = (LPWSTR)HeapAlloc(heap, 0, len * sizeof(WCHAR));
		if (buffer) {
			MultiByteToWideChar(CP_ACP, 0, lpString, -1, buffer, len);
		}
	}

	return buffer;
}

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

static BOOL WINAPI HashPublicKeyInfo(
	_In_ PCERT_PUBLIC_KEY_INFO CertPublicKeyInfo,
	_Out_ LPBYTE* PublicKeyHash,
	_Out_ LPDWORD HashLength) {
	HCRYPTPROV hProv = 0;
	LPBYTE hash = nullptr;
	DWORD len = 0;
	BOOL success = FALSE;
	HANDLE heap = GetProcessHeap();
	CERT_PUBLIC_KEY_INFO publicKey;

	__try {
		*PublicKeyHash = nullptr;
		*HashLength = 0;

		RtlCopyMemory(
			&publicKey,
			CertPublicKeyInfo,
			sizeof(CERT_PUBLIC_KEY_INFO)
		);

		RtlMoveMemory(
			publicKey.PublicKey.pbData,
			publicKey.PublicKey.pbData,
			publicKey.PublicKey.cbData
		);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	do {
		if (!CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))break;

		CryptHashPublicKeyInfo(
			hProv,
			0,
			0,
			X509_ASN_ENCODING,
			&publicKey,
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
			&publicKey,
			hash,
			&len
		))break;

		success = TRUE;
	} while (false);

	if (hProv) {
		CryptReleaseContext(hProv, 0);
	}

	if (!success) {
		HeapFree(heap, 0, hash);
	}
	else {
		__try {
			*PublicKeyHash = hash;
			*HashLength = len;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
	}
	return success;
}


BOOL WINAPI CreateX509CertBuilderFromCertFile(
	_Out_ PHANDLE X509CertBuilderHandle,
	_In_ LPCSTR FileName) {

	BOOL success = FALSE;
	PCERT_INFO cert = nullptr;

	__try {
		*X509CertBuilderHandle = nullptr;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	if (OpenX509CertificateFromFile(&cert, FileName)) {
		success = CreateX509CertBuilder(X509CertBuilderHandle, cert);
		CloseX509Certificate(cert);
	}

	return success;
}

BOOL WINAPI CreateX509CertBuilder(
	_Out_ PHANDLE X509CertBuilderHandle,
	_In_opt_ PCERT_INFO ExistsCert) {

	__try {
		*X509CertBuilderHandle = nullptr;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	BOOL success = FALSE;
	HANDLE heap = GetProcessHeap();
	PX509_CERT_BUILDER builder = (PX509_CERT_BUILDER)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(X509_CERT_BUILDER));
	
	do {
		if (!builder)break;

		builder->Magic = X509_CERT_BUILDER_MAGIC;

		if (ExistsCert) {
			__try {
				do {
					builder->IssuerName.cbData = ExistsCert->Issuer.cbData;
					if (builder->IssuerName.cbData) {
						builder->IssuerName.pbData = (LPBYTE)HeapAlloc(heap, 0, builder->IssuerName.cbData);
						if (!builder->IssuerName.pbData)break;
					}

					RtlCopyMemory(
						builder->IssuerName.pbData,
						ExistsCert->Issuer.pbData,
						builder->IssuerName.cbData
					);

					RtlCopyMemory(
						&builder->NotBeforeDate,
						&ExistsCert->NotBefore,
						sizeof(FILETIME)
					);

					RtlCopyMemory(
						&builder->NotAfterDate,
						&ExistsCert->NotAfter,
						sizeof(FILETIME)
					);

					builder->u1.s1.TimeIsSet = TRUE;

					RtlCopyMemory(
						&builder->PublicKeyInfo,
						&ExistsCert->SubjectPublicKeyInfo,
						sizeof(CERT_PUBLIC_KEY_INFO)
					);

					if (builder->PublicKeyInfo.Algorithm.Parameters.cbData) {
						builder->PublicKeyInfo.Algorithm.Parameters.pbData = (LPBYTE)HeapAlloc(heap, 0, builder->PublicKeyInfo.Algorithm.Parameters.cbData);
						if (!builder->PublicKeyInfo.Algorithm.Parameters.pbData)break;

						RtlCopyMemory(
							builder->PublicKeyInfo.Algorithm.Parameters.pbData,
							ExistsCert->SubjectPublicKeyInfo.Algorithm.Parameters.pbData,
							builder->PublicKeyInfo.Algorithm.Parameters.cbData
						);
					}

					if (builder->PublicKeyInfo.PublicKey.cbData) {
						builder->PublicKeyInfo.PublicKey.pbData = (LPBYTE)HeapAlloc(heap, 0, builder->PublicKeyInfo.PublicKey.cbData);
						if (!builder->PublicKeyInfo.PublicKey.pbData)break;

						RtlCopyMemory(
							builder->PublicKeyInfo.PublicKey.pbData,
							ExistsCert->SubjectPublicKeyInfo.PublicKey.pbData,
							builder->PublicKeyInfo.PublicKey.cbData
						);
					}

					RtlCopyMemory(
						&builder->SerialNumber,
						&ExistsCert->SerialNumber,
						sizeof(CRYPT_INTEGER_BLOB)
					);

					if (builder->SerialNumber.cbData) {
						builder->SerialNumber.pbData = (LPBYTE)HeapAlloc(heap, 0, builder->SerialNumber.cbData);
						if (!builder->SerialNumber.pbData)break;

						RtlCopyMemory(
							builder->SerialNumber.pbData,
							ExistsCert->SerialNumber.pbData,
							builder->SerialNumber.cbData
						);
					}

					RtlCopyMemory(
						&builder->SignatureAlgorithm,
						&ExistsCert->SignatureAlgorithm,
						sizeof(CRYPT_ALGORITHM_IDENTIFIER)
					);

					if (builder->SignatureAlgorithm.Parameters.cbData) {
						builder->SignatureAlgorithm.Parameters.pbData = (LPBYTE)HeapAlloc(heap, 0, builder->SignatureAlgorithm.Parameters.cbData);
						if (!builder->SignatureAlgorithm.Parameters.pbData)break;

						RtlCopyMemory(
							builder->SignatureAlgorithm.Parameters.pbData,
							ExistsCert->SignatureAlgorithm.Parameters.pbData,
							builder->SignatureAlgorithm.Parameters.cbData
						);
					}

					RtlCopyMemory(
						&builder->SubjectX500Name,
						&ExistsCert->Subject,
						sizeof(CERT_NAME_BLOB)
					);

					if (builder->SubjectX500Name.cbData) {
						builder->SubjectX500Name.pbData = (LPBYTE)HeapAlloc(heap, 0, builder->SubjectX500Name.cbData);
						if (!builder->SubjectX500Name.pbData)break;

						RtlCopyMemory(
							builder->SubjectX500Name.pbData,
							ExistsCert->Subject.pbData,
							builder->SubjectX500Name.cbData
						);
					}

					BOOL fail = FALSE;
					for (DWORD i = 0; i < ExistsCert->cExtension; ++i) {
						for (DWORD j = 0; j < CERT_EXTENSION_COUNT; ++j) {
							if (!strcmp(ExistsCert->rgExtension[i].pszObjId, CERT_EXTENSION_OIDS[j])) {
								if (builder->u1.s1.ExtensionsMask & (1 << j)) {
									HeapFree(heap, 0, builder->Extension[j].Value.pbData);
								}

								RtlCopyMemory(
									&builder->Extension[j],
									&ExistsCert->rgExtension[i],
									sizeof(CERT_EXTENSION)
								);

								if (builder->Extension[j].Value.cbData) {
									builder->Extension[j].Value.pbData = (LPBYTE)HeapAlloc(heap, 0, builder->Extension[j].Value.cbData);
									if (!builder->Extension[j].Value.pbData) {
										fail = TRUE;
										break;
									}

									RtlCopyMemory(
										builder->Extension[j].Value.pbData,
										ExistsCert->rgExtension[i].Value.pbData,
										builder->Extension[j].Value.cbData
									);
								}

								builder->u1.s1.ExtensionsMask |= (1 << j);
							}

							if (fail)break;
						}

						if (fail)break;
					}
					if (fail)break;

					success = TRUE;
				} while (false);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				;
			}

			if (!success)break;
		}

		success = TRUE;
	} while (false);

	if (success) {
		__try {
			*X509CertBuilderHandle = builder;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			success = FALSE;
		}
	}

	if (!success) {
		CloseX509CertBuilder(builder);
	}
	return success;
}

BOOL WINAPI CloseX509CertBuilder(_In_opt_ _Post_ptr_invalid_ HANDLE X509CertBuilderHandle) {

	if (!X509CertBuilderHandle)return FALSE;

	HANDLE heap = GetProcessHeap();
	PX509_CERT_BUILDER builder = HandleToX509CertBuilder(X509CertBuilderHandle);

	if (!builder)return FALSE;

	HeapFree(heap, 0, builder->IssuerName.pbData);
	HeapFree(heap, 0, builder->PublicKeyInfo.Algorithm.Parameters.pbData);
	HeapFree(heap, 0, builder->PublicKeyInfo.PublicKey.pbData);
	HeapFree(heap, 0, builder->SerialNumber.pbData);
	HeapFree(heap, 0, builder->SignatureAlgorithm.Parameters.pbData);
	HeapFree(heap, 0, builder->SubjectX500Name.pbData);

	for (DWORD i = 0; i < CERT_EXTENSION_COUNT; ++i) {
		HeapFree(heap, 0, builder->Extension[i].Value.pbData);
	}
	HeapFree(heap, 0, builder);

	return TRUE;
}

BOOL WINAPI X509CertBuilderSetBasicConstraint(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ DWORD PathLenConstraint,
	_In_ DWORD SubjectType,
	_In_ BOOL Critical) {

	CERT_EXTENSION extension{};
	CERT_BASIC_CONSTRAINTS_INFO info{};
	HANDLE heap = GetProcessHeap();
	PX509_CERT_BUILDER builder = HandleToX509CertBuilder(X509CertBuilderHandle);

	if (!builder)return FALSE;

	if (SubjectType == 0) {
		SubjectType = CERT_CA_SUBJECT_FLAG | CERT_END_ENTITY_SUBJECT_FLAG;
	}

	info.SubjectType.pbData = (LPBYTE)&SubjectType;
	info.SubjectType.cbData = 1;

	if (PathLenConstraint & 0x80000000) {
		info.fPathLenConstraint = FALSE;
	}
	else {
		info.fPathLenConstraint = TRUE;
		info.dwPathLenConstraint = PathLenConstraint;
	}

	if (EncodeExtension(
		&extension,
		&info,
		X509_BASIC_CONSTRAINTS,
		szOID_BASIC_CONSTRAINTS)) {
		__try {
			if (builder->u1.s1.ExtensionsMask & CERT_EXTENSION_BASIC_CONSTRAINT) {
				HeapFree(heap, 0, builder->Extension[CERT_EXTENSION_BASIC_CONSTRAINT_INDEX].Value.pbData);
			}

			extension.fCritical = Critical;

			RtlCopyMemory(
				&builder->Extension[CERT_EXTENSION_BASIC_CONSTRAINT_INDEX],
				&extension,
				sizeof(CERT_EXTENSION)
			);

			builder->u1.s1.ExtensionsMask |= CERT_EXTENSION_BASIC_CONSTRAINT;
			return TRUE;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			HeapFree(heap, 0, extension.Value.pbData);
		}
	}

	return FALSE;
}

BOOL WINAPI X509CertBuilderSetKeyUsage(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ KEY_USAGE KeyUsage,
	_In_ BOOL Critical) {

	CERT_EXTENSION extension{};
	CERT_KEY_ATTRIBUTES_INFO KeyUsageInfo{};
	WORD bRestrictedKeyUsage = KeyUsage.Flags;
	PX509_CERT_BUILDER builder = HandleToX509CertBuilder(X509CertBuilderHandle);
	HANDLE heap = GetProcessHeap();

	if (!builder)return FALSE;

	KeyUsageInfo.IntendedKeyUsage.pbData = (LPBYTE)&bRestrictedKeyUsage;
	if (KeyUsage.DecipherOnly) {
		KeyUsageInfo.IntendedKeyUsage.cbData = 2;
		bRestrictedKeyUsage &= 0xff;
		bRestrictedKeyUsage |= 0x8000;
	}
	else {
		KeyUsageInfo.IntendedKeyUsage.cbData = 1;
	}

	if (EncodeExtension(
		&extension,
		&KeyUsageInfo.IntendedKeyUsage,
		X509_KEY_USAGE,
		szOID_KEY_USAGE)) {
		__try {
			if (builder->u1.s1.ExtensionsMask & CERT_EXTENSION_KEY_USAGE) {
				HeapFree(heap, 0, builder->Extension[CERT_EXTENSION_KEY_USAGE_INDEX].Value.pbData);
			}

			extension.fCritical = Critical;

			RtlCopyMemory(
				&builder->Extension[CERT_EXTENSION_KEY_USAGE_INDEX],
				&extension,
				sizeof(CERT_EXTENSION)
			);

			builder->u1.s1.ExtensionsMask |= CERT_EXTENSION_KEY_USAGE;

			return TRUE;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			HeapFree(heap, 0, extension.Value.pbData);
		}
	}

	return FALSE;
}

BOOL WINAPI X509CertBuilderSetPolicies(
	_In_ HANDLE X509CertBuilderHandle,
	_In_reads_bytes_(Policies->dwPolicyInfo * sizeof(CERT_POLICY_INFO)) PCERT_POLICY_LIST Policies,
	_In_ BOOL Critical) {

	CERT_EXTENSION extension{};
	CERT_POLICIES_INFO policies{};
	HANDLE heap = GetProcessHeap();
	PX509_CERT_BUILDER builder = HandleToX509CertBuilder(X509CertBuilderHandle);

	auto freePolicies = [&policies, heap]() {
		for (DWORD i = 0; i < policies.cPolicyInfo; ++i) {
			for (DWORD j = 0; j < policies.rgPolicyInfo[i].cPolicyQualifier; ++j) {
				HeapFree(heap, 0, policies.rgPolicyInfo[i].rgPolicyQualifier[j].Qualifier.pbData);
			}
			HeapFree(heap, 0, policies.rgPolicyInfo[i].rgPolicyQualifier);
		}

		HeapFree(heap, 0, policies.rgPolicyInfo);
	};

	if (!builder)return FALSE;

	__try {
		policies.cPolicyInfo = Policies->dwPolicyInfo;
		policies.rgPolicyInfo = (PCERT_POLICY_INFO)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(CERT_POLICY_INFO) * policies.cPolicyInfo);

		do {
			if (!policies.rgPolicyInfo) {
				SetLastError(ERROR_INSUFFICIENT_BUFFER);
				break;
			}

			BOOL success = TRUE;
			for (DWORD i = 0; i < policies.cPolicyInfo; ++i) {
				auto& src = Policies->Policies[i];
				auto& dst = policies.rgPolicyInfo[i];

				dst.pszPolicyIdentifier = (LPSTR)src.PolicyIdentifier;
				dst.cPolicyQualifier = src.dwPolicyQualifier;
				if (dst.cPolicyQualifier) {
					dst.rgPolicyQualifier = (PCERT_POLICY_QUALIFIER_INFO)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(CERT_POLICY_QUALIFIER_INFO) * dst.cPolicyQualifier);
					if (!dst.rgPolicyQualifier) {
						SetLastError(ERROR_INSUFFICIENT_BUFFER);
						success = FALSE;
						break;
					}

					for (DWORD j = 0; j < dst.cPolicyQualifier; ++j) {
						dst.rgPolicyQualifier[j].pszPolicyQualifierId = (LPSTR)src.PolicyQualifiers[j].PolicyQualifierId;
						if (!EncodeIA5String(src.PolicyQualifiers[j].Qualifier, &dst.rgPolicyQualifier[j].Qualifier)) {
							success = FALSE;
							break;
						}
					}

					if (!success)break;
				}

			}

			if (!success)break;

			if (!EncodeExtension(
				&extension,
				&policies,
				X509_CERT_POLICIES,
				szOID_CERT_POLICIES))break;

			if (builder->u1.s1.ExtensionsMask & CERT_EXTENSION_CERT_POLICIES) {
				HeapFree(heap, 0, builder->Extension[CERT_EXTENSION_CERT_POLICIES_INDEX].Value.pbData);
			}

			extension.fCritical = Critical;
			
			RtlCopyMemory(
				&builder->Extension[CERT_EXTENSION_CERT_POLICIES_INDEX],
				&extension,
				sizeof(CERT_EXTENSION)
			);

			builder->u1.s1.ExtensionsMask |= CERT_EXTENSION_CERT_POLICIES;

			freePolicies();
			return TRUE;
		} while (false);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}

	freePolicies();
	HeapFree(heap, 0, extension.Value.pbData);
	return FALSE;
}

BOOL WINAPI X509CertBuilderSetSubjectAlternativeName(
	_In_ HANDLE X509CertBuilderHandle,
	_In_reads_bytes_(SANs->dwSAN * sizeof(CERT_SAN)) PCERT_SAN_LIST SANs,
	_In_ BOOL Critical) {

	CERT_EXTENSION extension{};
	CERT_ALT_NAME_INFO alt{};
	PX509_CERT_BUILDER builder = HandleToX509CertBuilder(X509CertBuilderHandle);
	HANDLE heap = GetProcessHeap();

	auto freeAN = [&alt, heap]() {

		for (DWORD i = 0; i < alt.cAltEntry; ++i) {
			switch (alt.rgAltEntry[i].dwAltNameChoice) {
			case X509_CERT_SAN_TYPE_DNS:
				HeapFree(heap, 0, alt.rgAltEntry[i].pwszDNSName);
				break;

			default:
				break;
			}
		}
		HeapFree(heap, 0, alt.rgAltEntry);

	};

	if (!builder)return FALSE;

	__try {
		alt.cAltEntry = SANs->dwSAN;
		alt.rgAltEntry = (PCERT_ALT_NAME_ENTRY)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(CERT_ALT_NAME_ENTRY) * alt.cAltEntry);

		do {
			if (!alt.rgAltEntry)break;

			BOOL success = TRUE;
			for (DWORD i = 0; i < alt.cAltEntry; ++i) {
				alt.rgAltEntry[i].dwAltNameChoice = SANs->SANs[i].type;

				switch (SANs->SANs[i].type) {
				case X509_CERT_SAN_TYPE_DNS:
					alt.rgAltEntry[i].pwszDNSName = toUnicode(SANs->SANs[i].SAN);
					break;

				default:
					success = FALSE;
					break;
				}

				if (!success)break;
			}

			if (!success)break;

			if (!EncodeExtension(
				&extension,
				&alt,
				X509_ALTERNATE_NAME,
				szOID_SUBJECT_ALT_NAME2))break;

			if (builder->u1.s1.ExtensionsMask & CERT_EXTENSION_SUBJECT_ALTERNATIVE_NAME) {
				HeapFree(heap, 0, builder->Extension[CERT_EXTENSION_SUBJECT_ALTERNATIVE_NAME_INDEX].Value.pbData);
			}

			extension.fCritical = Critical;

			RtlCopyMemory(
				&builder->Extension[CERT_EXTENSION_SUBJECT_ALTERNATIVE_NAME_INDEX],
				&extension,
				sizeof(CERT_EXTENSION)
			);

			builder->u1.s1.ExtensionsMask |= CERT_EXTENSION_SUBJECT_ALTERNATIVE_NAME;

			freeAN();
			return TRUE;
		} while (false);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}

	freeAN();
	HeapFree(heap, 0, extension.Value.pbData);
	return FALSE;
}

BOOL WINAPI X509CertBuilderSetEnhancedKeyUsage(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ PCERT_ENHANCED_KEY_USAGE_LIST EnhancedKeyUsageList,
	_In_ BOOL Critical) {

	CERT_EXTENSION extension{};
	CERT_ENHKEY_USAGE enhkey{};
	HANDLE heap = GetProcessHeap();
	PX509_CERT_BUILDER builder = HandleToX509CertBuilder(X509CertBuilderHandle);

	if (!builder)return FALSE;

	__try {
		enhkey.cUsageIdentifier = EnhancedKeyUsageList->dwEnhancedKeyUsage;
		enhkey.rgpszUsageIdentifier = (LPSTR*)&EnhancedKeyUsageList->EKUs[0];

		if (EncodeExtension(
			&extension,
			&enhkey,
			X509_ENHANCED_KEY_USAGE,
			szOID_ENHANCED_KEY_USAGE)) {

			if (builder->u1.s1.ExtensionsMask & CERT_EXTENSION_ENHANCED_KEY_USAGE) {
				HeapFree(heap, 0, builder->Extension[CERT_EXTENSION_ENHANCED_KEY_USAGE_INDEX].Value.pbData);
			}

			extension.fCritical = Critical;

			RtlCopyMemory(
				&builder->Extension[CERT_EXTENSION_ENHANCED_KEY_USAGE_INDEX],
				&extension,
				sizeof(CERT_EXTENSION)
			);

			builder->u1.s1.ExtensionsMask |= CERT_EXTENSION_ENHANCED_KEY_USAGE;
			return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}

	HeapFree(heap, 0, extension.Value.pbData);
	return FALSE;
}

BOOL WINAPI X509CertBuilderSetCRL(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ PCERT_CRL_DIST_POINT_LIST CRLs,
	_In_ BOOL Critical) {
	
	CERT_EXTENSION extension{};
	CRL_DIST_POINTS_INFO dpi{};
	HANDLE heap = GetProcessHeap();
	PX509_CERT_BUILDER builder = HandleToX509CertBuilder(X509CertBuilderHandle);

	auto freeCRL = [heap, &dpi]() {
		for (DWORD i = 0; i < dpi.cDistPoint; ++i) {
			for (DWORD j = 0; j < dpi.rgDistPoint[i].DistPointName.FullName.cAltEntry; ++j) {
				HeapFree(heap, 0, dpi.rgDistPoint[i].DistPointName.FullName.rgAltEntry[j].pwszURL);
			}
			HeapFree(heap, 0, dpi.rgDistPoint[i].DistPointName.FullName.rgAltEntry);

			for (DWORD j = 0; j < dpi.rgDistPoint[i].CRLIssuer.cAltEntry; ++j) {
				HeapFree(heap, 0, dpi.rgDistPoint[i].CRLIssuer.rgAltEntry[j].pwszURL);
			}
			HeapFree(heap, 0, dpi.rgDistPoint[i].CRLIssuer.rgAltEntry);
		}

		HeapFree(heap, 0, dpi.rgDistPoint);
	};

	if (!builder)return FALSE;

	__try {

		do {
			dpi.cDistPoint = CRLs->dwCRL;
			dpi.rgDistPoint = (PCRL_DIST_POINT)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(CRL_DIST_POINT) * dpi.cDistPoint);
			if (!dpi.rgDistPoint)break;

			BOOL success = TRUE;
			for (DWORD i = 0; i < CRLs->dwCRL; ++i) {
				if (CRLs->CRLs[i].DistPointNames) {
					auto& dst = dpi.rgDistPoint[i].DistPointName;
					auto& src = CRLs->CRLs[i].DistPointNames;

					dst.dwDistPointNameChoice = src->dwType;
					dst.FullName.cAltEntry = src->dwName;
					dst.FullName.rgAltEntry = (PCERT_ALT_NAME_ENTRY)HeapAlloc(
						heap,
						HEAP_ZERO_MEMORY,
						sizeof(CERT_ALT_NAME_ENTRY) * dst.FullName.cAltEntry
					);

					if (!dst.FullName.rgAltEntry) {
						success = FALSE;
						break;
					}

					for (DWORD j = 0; j < dst.FullName.cAltEntry; ++j) {
						dst.FullName.rgAltEntry[j].dwAltNameChoice = src->Names[j].dwType;

						switch (src->Names[j].dwType) {
						case X509_CERT_CRL_DIST_POINT_NAME_URL:
							dst.FullName.rgAltEntry[j].pwszURL = toUnicode(src->Names[j].Name);
							break;

						default:
							success = FALSE;
							break;
						}

						if (!success)break;
					}

					if (!success)break;
				}

				if (CRLs->CRLs[i].ReasonFlags.Flags) {
					dpi.rgDistPoint[i].ReasonFlags.pbData = (LPBYTE)&CRLs->CRLs[i].ReasonFlags.Flags;
					dpi.rgDistPoint[i].ReasonFlags.cbData = CRLs->CRLs[i].ReasonFlags.AA_Compromise ? 2 : 1;
				}

				if (CRLs->CRLs[i].CRLIssuer) {
					auto& dst = dpi.rgDistPoint[i].CRLIssuer;
					auto& src = CRLs->CRLs[i].CRLIssuer;

					dst.cAltEntry = src->dwName;
					dst.rgAltEntry = (PCERT_ALT_NAME_ENTRY)HeapAlloc(
						heap,
						HEAP_ZERO_MEMORY,
						sizeof(CERT_ALT_NAME_ENTRY) * dst.cAltEntry
					);

					if (!dst.rgAltEntry) {
						success = FALSE;
						break;
					}

					for (DWORD j = 0; j < dst.cAltEntry; ++j) {
						dst.rgAltEntry[j].dwAltNameChoice = src->Names[j].dwType;

						switch (src->Names[j].dwType) {
						case X509_CERT_CRL_DIST_POINT_NAME_URL:
							dst.rgAltEntry[j].pwszURL = toUnicode(src->Names[j].Name);
							break;

						default:
							success = FALSE;
							break;
						}

						if (!success)break;
					}

					if (!success)break;
				}
			}

			if (!success)break;

			if (!EncodeExtension(
				&extension,
				&dpi,
				X509_CRL_DIST_POINTS,
				szOID_CRL_DIST_POINTS))break;

			if (builder->u1.s1.ExtensionsMask & CERT_EXTENSION_CRL_DISTRIBUTION_POINT) {
				HeapFree(heap, 0, builder->Extension[CERT_EXTENSION_CRL_DISTRIBUTION_POINT_INDEX].Value.pbData);
			}

			extension.fCritical = Critical;

			RtlCopyMemory(
				&builder->Extension[CERT_EXTENSION_CRL_DISTRIBUTION_POINT_INDEX],
				&extension,
				sizeof(CERT_EXTENSION)
			);

			builder->u1.s1.ExtensionsMask |= CERT_EXTENSION_CRL_DISTRIBUTION_POINT;

			freeCRL();
			return TRUE;
		} while (false);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}

	freeCRL();
	HeapFree(heap, 0, extension.Value.pbData);
	return FALSE;
}

BOOL WINAPI X509CertBuilderSetAuthorityInfoAccess(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ PCERT_AUTHORITY_INFO_ACCESS_LIST AuthorityInfoAccessList,
	_In_ BOOL Critical) {
	
	CERT_EXTENSION extension{};
	CERT_AUTHORITY_INFO_ACCESS aia{};
	HANDLE heap = GetProcessHeap();
	PX509_CERT_BUILDER builder = HandleToX509CertBuilder(X509CertBuilderHandle);

	auto freeAIA = [heap, &aia]() {
		for (DWORD i = 0; i < aia.cAccDescr; ++i) {
			HeapFree(heap, 0, aia.rgAccDescr[i].AccessLocation.pwszURL);
		}
		HeapFree(heap, 0, aia.rgAccDescr);
	};

	if (!builder)return FALSE;

	__try {

		do {
			aia.cAccDescr = AuthorityInfoAccessList->dwAccDescr;
			aia.rgAccDescr = (PCERT_ACCESS_DESCRIPTION)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(CERT_ACCESS_DESCRIPTION) * aia.cAccDescr);
			if (!aia.rgAccDescr)break;

			BOOL success = TRUE;
			for (DWORD i = 0; i < aia.cAccDescr; ++i) {
				auto& src = AuthorityInfoAccessList->AccDescrs[i];
				auto& dst = aia.rgAccDescr[i];

				dst.pszAccessMethod = (LPSTR)src.AccessMethod;
				
				dst.AccessLocation.dwAltNameChoice = src.AccessLocation.dwType;
				switch (src.AccessLocation.dwType) {
				case X509_CERT_AUTHORITY_INFO_ACCESS_LOCATION_URL:
					dst.AccessLocation.pwszURL = toUnicode(src.AccessLocation.Name);
					break;

				default:
					success = FALSE;
					break;
				}

				if (!success)break;
			}

			if (!success)break;

			if (!EncodeExtension(
				&extension,
				&aia,
				X509_AUTHORITY_INFO_ACCESS,
				szOID_AUTHORITY_INFO_ACCESS))break;
			
			if (builder->u1.s1.ExtensionsMask & CERT_EXTENSION_AUTHORITY_INFO_ACCESS) {
				HeapFree(heap, 0, builder->Extension[CERT_EXTENSION_AUTHORITY_INFO_ACCESS_INDEX].Value.pbData);
			}

			extension.fCritical = Critical;

			RtlCopyMemory(
				&builder->Extension[CERT_EXTENSION_AUTHORITY_INFO_ACCESS_INDEX],
				&extension,
				sizeof(CERT_EXTENSION)
			);

			builder->u1.s1.ExtensionsMask |= CERT_EXTENSION_AUTHORITY_INFO_ACCESS;

			freeAIA();
			return TRUE;
		} while (false);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}

	freeAIA();
	HeapFree(heap, 0, extension.Value.pbData);
	return FALSE;
}

BOOL WINAPI X509CertBuilderSetAuthorityKeyIdentifier(
	_In_ HANDLE X509CertBuilderHandle,
	_In_opt_ PCERT_ALT_NAME_INFO Issuer,
	_In_opt_ PCRYPT_INTEGER_BLOB IssuerSerialNumber,
	_In_ HANDLE KeyHandle,
	_In_ BOOL Critical) {

	CERT_EXTENSION extension{};
	CERT_AUTHORITY_KEY_ID2_INFO aki{};
	HANDLE heap = GetProcessHeap();
	PX509_CERT_BUILDER builder = HandleToX509CertBuilder(X509CertBuilderHandle);
	PCERT_PUBLIC_KEY_INFO IssuerPublicKeyInfo = RSAKeyGetPublicKeyInfo(KeyHandle);

	if (!builder || !IssuerPublicKeyInfo)return FALSE;

	__try {
		if (Issuer)aki.AuthorityCertIssuer = *Issuer;

		if (IssuerSerialNumber)aki.AuthorityCertSerialNumber = *IssuerSerialNumber;

		do {
			if (!HashPublicKeyInfo(IssuerPublicKeyInfo, &aki.KeyId.pbData, &aki.KeyId.cbData))break;

			if (!EncodeExtension(&extension, &aki, X509_AUTHORITY_KEY_ID2, szOID_AUTHORITY_KEY_IDENTIFIER2))break;

			if (builder->u1.s1.ExtensionsMask & CERT_EXTENSION_AUTHORITY_KET_IDENTIFIER) {
				HeapFree(heap, 0, builder->Extension[CERT_EXTENSION_AUTHORITY_KET_IDENTIFIER_INDEX].Value.pbData);
			}

			extension.fCritical = Critical;

			RtlCopyMemory(
				&builder->Extension[CERT_EXTENSION_AUTHORITY_KET_IDENTIFIER_INDEX],
				&extension,
				sizeof(CERT_EXTENSION)
			);

			builder->u1.s1.ExtensionsMask |= CERT_EXTENSION_AUTHORITY_KET_IDENTIFIER;
			HeapFree(heap, 0, aki.KeyId.pbData);
			return TRUE;
		} while (false);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}

	HeapFree(heap, 0, aki.KeyId.pbData);
	HeapFree(heap, 0, extension.Value.pbData);
	return FALSE;
}

BOOL WINAPI X509CertBuilderSetSubjectKeyIdentifier(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ HANDLE KeyHandle,
	_In_ BOOL Critical) {

	CERT_EXTENSION extension{};
	CRYPT_INTEGER_BLOB subjectKeyId{};
	HANDLE heap = GetProcessHeap();
	PX509_CERT_BUILDER builder = HandleToX509CertBuilder(X509CertBuilderHandle);
	PCERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo = RSAKeyGetPublicKeyInfo(KeyHandle);

	if (!builder || !SubjectPublicKeyInfo)return FALSE;

	__try {
		
		do {
			if (!HashPublicKeyInfo(SubjectPublicKeyInfo, &subjectKeyId.pbData, &subjectKeyId.cbData))break;

			if (!EncodeExtension(&extension, &subjectKeyId, szOID_SUBJECT_KEY_IDENTIFIER, szOID_SUBJECT_KEY_IDENTIFIER))break;

		} while (false);

		if (builder->u1.s1.ExtensionsMask & CERT_EXTENSION_SUBJECT_KEY_IDENTIFIER) {
			HeapFree(heap, 0, builder->Extension[CERT_EXTENSION_SUBJECT_KEY_IDENTIFIER_INDEX].Value.pbData);
		}

		extension.fCritical = Critical;

		RtlCopyMemory(
			&builder->Extension[CERT_EXTENSION_SUBJECT_KEY_IDENTIFIER_INDEX],
			&extension,
			sizeof(CERT_EXTENSION)
		);

		builder->u1.s1.ExtensionsMask |= CERT_EXTENSION_SUBJECT_KEY_IDENTIFIER;

		HeapFree(heap, 0, subjectKeyId.pbData);
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}
	
	HeapFree(heap, 0, subjectKeyId.pbData);
	HeapFree(heap, 0, extension.Value.pbData);
	return FALSE;
}

BOOL WINAPI X509CertBuilderSetEffectiveTime(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ PSYSTEMTIME NotBefore,
	_In_ PSYSTEMTIME NotAfter) {

	PX509_CERT_BUILDER builder = HandleToX509CertBuilder(X509CertBuilderHandle);

	if (!builder)return FALSE;

	__try {
		if (!SystemTimeToFileTime(NotBefore, &builder->NotBeforeDate))return FALSE;
		if (!SystemTimeToFileTime(NotAfter, &builder->NotAfterDate))return FALSE;

		BOOL success;
		if (builder->NotBeforeDate.dwHighDateTime > builder->NotAfterDate.dwHighDateTime) {
			success = FALSE;
		}
		else if (builder->NotBeforeDate.dwHighDateTime == builder->NotAfterDate.dwHighDateTime) {
			success = builder->NotBeforeDate.dwLowDateTime < builder->NotAfterDate.dwLowDateTime;
		}
		else {
			success = TRUE;
		}

		if (!success)return FALSE;

		builder->u1.s1.TimeIsSet = TRUE;
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}

	return FALSE;
}

BOOL WINAPI X509CertBuilderSetSerialNumber(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ PCRYPT_INTEGER_BLOB SerialNumber) {

	CRYPT_INTEGER_BLOB sn{};
	HANDLE heap = GetProcessHeap();
	PX509_CERT_BUILDER builder = HandleToX509CertBuilder(X509CertBuilderHandle);

	if (!builder)return FALSE;

	__try {
		sn.cbData = SerialNumber->cbData;
		sn.pbData = (LPBYTE)HeapAlloc(heap, 0, sn.cbData);
		if (!sn.pbData)return FALSE;

		RtlCopyMemory(
			sn.pbData,
			SerialNumber->pbData,
			sn.cbData
		);

		if (builder->SerialNumber.pbData) {
			HeapFree(heap, 0, builder->SerialNumber.pbData);
		}

		RtlCopyMemory(
			&builder->SerialNumber,
			&sn,
			sizeof(CRYPT_INTEGER_BLOB)
		);

		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}

	HeapFree(heap, 0, sn.pbData);
	return FALSE;
}

BOOL WINAPI X509CertBuilderSetSubjectName(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ LPCSTR SubjectX500Name) {

	CERT_NAME_BLOB name{};
	HANDLE heap = GetProcessHeap();
	PX509_CERT_BUILDER builder = HandleToX509CertBuilder(X509CertBuilderHandle);

	if (!builder)return FALSE;

	__try {

		do {
			CertStrToNameA(
				X509_ASN_ENCODING,
				SubjectX500Name,
				CERT_NAME_STR_REVERSE_FLAG,
				nullptr,
				name.pbData,
				&name.cbData,
				nullptr
			);
			if (!name.cbData)break;

			name.pbData = (LPBYTE)HeapAlloc(heap, 0, name.cbData);
			if (!name.pbData)break;

			if (!CertStrToNameA(
				X509_ASN_ENCODING,
				SubjectX500Name,
				CERT_NAME_STR_REVERSE_FLAG,
				nullptr,
				name.pbData,
				&name.cbData,
				nullptr))break;

			if (builder->SubjectX500Name.pbData) {
				HeapFree(heap, 0, builder->SubjectX500Name.pbData);
			}

			RtlCopyMemory(
				&builder->SubjectX500Name,
				&name,
				sizeof(CERT_NAME_BLOB)
			);

			return TRUE;
		} while (false);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}

	HeapFree(heap, 0, name.pbData);
	return FALSE;
}

BOOL WINAPI X509CertBuilderSetIssuerName(
	_In_ HANDLE X509CertBuilderHandle,
	_In_opt_ PCERT_NAME_BLOB IssuerName) {

	CERT_NAME_BLOB name{};
	HANDLE heap = GetProcessHeap();
	PX509_CERT_BUILDER builder = HandleToX509CertBuilder(X509CertBuilderHandle);

	if (!builder)return FALSE;

	__try {

		if (!IssuerName) {
			IssuerName = &builder->SubjectX500Name;
			if (!IssuerName->cbData || !IssuerName->pbData)return FALSE;
		}

		do {
			name.cbData = IssuerName->cbData;
			name.pbData = (LPBYTE)HeapAlloc(heap, 0, name.cbData);

			if (!name.pbData)break;

			RtlCopyMemory(
				name.pbData,
				IssuerName->pbData,
				name.cbData
			);

			RtlCopyMemory(
				&builder->IssuerName,
				&name,
				sizeof(CERT_NAME_BLOB)
			);

			return TRUE;
		} while (false);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}

	HeapFree(heap, 0, name.pbData);
	return FALSE;
}

BOOL WINAPI X509CertBuilderSetSignatureAlgorithm(
	_In_ HANDLE X509CertBuilderHandle,
	_In_ SIGNATURE_ALGORITHM SignatureAlgorithm,
	_In_opt_ PCRYPT_OBJID_BLOB Parameters) {

	CRYPT_ALGORITHM_IDENTIFIER alg{};
	HANDLE heap = GetProcessHeap();
	PX509_CERT_BUILDER builder = HandleToX509CertBuilder(X509CertBuilderHandle);

	if (!builder)return FALSE;

	__try {
		do {
			if (Parameters) {
				alg.Parameters.cbData = Parameters->cbData;
				alg.Parameters.pbData = (LPBYTE)HeapAlloc(heap, 0, alg.Parameters.cbData);
				if (!alg.Parameters.pbData)return FALSE;

				RtlCopyMemory(
					alg.Parameters.pbData,
					Parameters->pbData,
					alg.Parameters.cbData
				);
			}

			switch (SignatureAlgorithm) {
			case SIGNATURE_ALGORITHM::md5RSA:
				alg.pszObjId = (LPSTR)szOID_RSA_MD5RSA;
				break;
			case SIGNATURE_ALGORITHM::sha1RSA:
				alg.pszObjId = (LPSTR)szOID_RSA_SHA1RSA;
				break;
			case SIGNATURE_ALGORITHM::sha256RSA:
				alg.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;
				break;
			case SIGNATURE_ALGORITHM::sha384RSA:
				alg.pszObjId = (LPSTR)szOID_RSA_SHA384RSA;
				break;
			case SIGNATURE_ALGORITHM::sha512RSA:
				alg.pszObjId = (LPSTR)szOID_RSA_SHA512RSA;
				break;
			default:
				break;
			}

			if (!alg.pszObjId)break;

			if (builder->SignatureAlgorithm.Parameters.pbData) {
				HeapFree(heap, 0, builder->SignatureAlgorithm.Parameters.pbData);
			}

			RtlCopyMemory(
				&builder->SignatureAlgorithm,
				&alg,
				sizeof(CRYPT_ALGORITHM_IDENTIFIER)
			);

			return TRUE;
		} while (false);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}

	HeapFree(heap, 0, alg.Parameters.pbData);
	return FALSE;
}

BOOL WINAPI X509CertBuilderSetSubjectPublicKeyInfo(
	_In_ HANDLE X509CertBuilderHandle, 
	_In_ HANDLE KeyHandle) {

	HANDLE heap = GetProcessHeap();
	PX509_CERT_BUILDER builder = HandleToX509CertBuilder(X509CertBuilderHandle);
	PCERT_PUBLIC_KEY_INFO pub = RSAKeyGetPublicKeyInfo(KeyHandle);
	CERT_PUBLIC_KEY_INFO PublicKeyInfo{};

	if (!builder || !pub)return FALSE;

	__try {
		do {
			PublicKeyInfo.Algorithm.pszObjId = pub->Algorithm.pszObjId;
			if (pub->Algorithm.Parameters.cbData) {
				PublicKeyInfo.Algorithm.Parameters.pbData = (LPBYTE)HeapAlloc(heap, 0, pub->Algorithm.Parameters.cbData);
				if (!PublicKeyInfo.Algorithm.Parameters.pbData)break;

				RtlCopyMemory(
					PublicKeyInfo.Algorithm.Parameters.pbData,
					pub->Algorithm.Parameters.pbData,
					PublicKeyInfo.Algorithm.Parameters.cbData
				);
			}

			PublicKeyInfo.PublicKey.cbData = pub->PublicKey.cbData;
			PublicKeyInfo.PublicKey.cUnusedBits = pub->PublicKey.cUnusedBits;
			PublicKeyInfo.PublicKey.pbData = (LPBYTE)HeapAlloc(heap, 0, PublicKeyInfo.PublicKey.cbData);
			if (!PublicKeyInfo.PublicKey.pbData)break;

			RtlCopyMemory(
				PublicKeyInfo.PublicKey.pbData,
				pub->PublicKey.pbData,
				PublicKeyInfo.PublicKey.cbData
			);

			RtlCopyMemory(
				&builder->PublicKeyInfo,
				&PublicKeyInfo,
				sizeof(CERT_PUBLIC_KEY_INFO)
			);

			return TRUE;
		} while (false);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}

	HeapFree(heap, 0, PublicKeyInfo.Algorithm.Parameters.pbData);
	HeapFree(heap, 0, PublicKeyInfo.PublicKey.pbData);
	return FALSE;
}

BOOL WINAPI X509CertBuilderDuplicateCertInfoDeepCopy(
	_Out_ PCERT_INFO* ResultCertInfo,
	_In_ PCERT_INFO SourceCertInfo) {

	__try {
		*ResultCertInfo = nullptr;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	HANDLE heap = GetProcessHeap();

	PCERT_INFO tmpInfo = (PCERT_INFO)HeapAlloc(heap, 0, sizeof(CERT_INFO));
	if (!tmpInfo)return FALSE;

	auto CopyDataBlob = [heap](PCRYPT_DATA_BLOB src, PCRYPT_DATA_BLOB dst) {
		if (dst->cbData) {
			dst->pbData = (LPBYTE)HeapAlloc(heap, 0, dst->cbData);
			if (!dst->pbData)return FALSE;

			RtlCopyMemory(
				dst->pbData,
				src->pbData,
				src->cbData
			);
		}

		return TRUE;
	};

	auto CopyBitBlob = [heap](PCRYPT_BIT_BLOB src, PCRYPT_BIT_BLOB dst) {
		if (dst->cbData) {
			dst->pbData = (LPBYTE)HeapAlloc(heap, 0, dst->cbData);
			if (!dst->pbData)return FALSE;

			RtlCopyMemory(
				dst->pbData,
				src->pbData,
				src->cbData
			);
		}

		return TRUE;
	};

	RtlCopyMemory(
		tmpInfo,
		SourceCertInfo,
		sizeof(CERT_INFO)
	);

	do {
		if (!CopyDataBlob(&SourceCertInfo->SerialNumber, &tmpInfo->SerialNumber))break;
		if (!CopyDataBlob(&SourceCertInfo->SignatureAlgorithm.Parameters, &tmpInfo->SignatureAlgorithm.Parameters))break;
		if (!CopyDataBlob(&SourceCertInfo->Issuer, &tmpInfo->Issuer))break;
		if (!CopyDataBlob(&SourceCertInfo->Subject, &tmpInfo->Subject))break;
		if (!CopyDataBlob(&SourceCertInfo->SubjectPublicKeyInfo.Algorithm.Parameters, &tmpInfo->SubjectPublicKeyInfo.Algorithm.Parameters))break;
		if (!CopyBitBlob(&SourceCertInfo->SubjectPublicKeyInfo.PublicKey, &tmpInfo->SubjectPublicKeyInfo.PublicKey))break;
		if (!CopyBitBlob(&SourceCertInfo->IssuerUniqueId, &tmpInfo->IssuerUniqueId))break;
		if (!CopyBitBlob(&SourceCertInfo->SubjectUniqueId, &tmpInfo->SubjectUniqueId))break;

		tmpInfo->rgExtension = (PCERT_EXTENSION)HeapAlloc(heap, 0, sizeof(CERT_EXTENSION) * tmpInfo->cExtension);
		if (!tmpInfo->rgExtension)break;

		RtlCopyMemory(
			tmpInfo->rgExtension,
			SourceCertInfo->rgExtension,
			sizeof(CERT_EXTENSION) * tmpInfo->cExtension
		);

		BOOL failed = FALSE;
		for (DWORD i = 0; i < tmpInfo->cExtension; ++i) {
			if (!CopyDataBlob(&SourceCertInfo->rgExtension[i].Value, &tmpInfo->rgExtension[i].Value)) {
				failed = TRUE;
				break;
			}
		}
		if (failed)break;

		__try {
			*ResultCertInfo = tmpInfo;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
		return TRUE;
	} while (false);

	X509CertBuilderFreeCertInfo(tmpInfo);
	return FALSE;
}


BOOL WINAPI X509CertBuilderCreateCertInfo(
	_Out_ PCERT_INFO* CertInfo,
	_In_ HANDLE X509CertBuilderHandle) {
	
	__try {
		*CertInfo = nullptr;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	BOOL success = FALSE;
	PCERT_INFO cert = nullptr;
	HANDLE heap = GetProcessHeap();
	PX509_CERT_BUILDER builder = HandleToX509CertBuilder(X509CertBuilderHandle);

	if (!builder)return FALSE;

	__try {
		if (!builder->IssuerName.pbData || !builder->SubjectX500Name.pbData ||
			!builder->PublicKeyInfo.Algorithm.pszObjId || !builder->PublicKeyInfo.PublicKey.pbData) {
			return FALSE;
		}

		RtlMoveMemory(
			builder->IssuerName.pbData,
			builder->IssuerName.pbData,
			builder->IssuerName.cbData
		);

		RtlMoveMemory(
			builder->SubjectX500Name.pbData,
			builder->SubjectX500Name.pbData,
			builder->SubjectX500Name.cbData
		);

		RtlMoveMemory(
			builder->PublicKeyInfo.PublicKey.pbData,
			builder->PublicKeyInfo.PublicKey.pbData,
			builder->PublicKeyInfo.PublicKey.cbData
		);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	do {
		cert = (PCERT_INFO)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(CERT_INFO));
		if (!cert)break;

		cert->dwVersion = CERT_V3;

		if (!builder->SerialNumber.pbData) {
			GUID id;
			if (UuidCreate(&id));

			CRYPT_INTEGER_BLOB sn;
			sn.cbData = sizeof(GUID);
			sn.pbData = (LPBYTE)&id;

			if (!X509CertBuilderSetSerialNumber(X509CertBuilderHandle, &sn))break;
		}

		RtlCopyMemory(
			&cert->SerialNumber,
			&builder->SerialNumber,
			sizeof(CRYPT_INTEGER_BLOB)
		);

		if (!builder->SignatureAlgorithm.pszObjId &&
			!X509CertBuilderSetSignatureAlgorithm(X509CertBuilderHandle, SIGNATURE_ALGORITHM::sha256RSA, nullptr))break;

		RtlCopyMemory(
			&cert->SignatureAlgorithm,
			&builder->SignatureAlgorithm,
			sizeof(CRYPT_ALGORITHM_IDENTIFIER)
		);

		RtlCopyMemory(
			&cert->Issuer,
			&builder->IssuerName,
			sizeof(CERT_NAME_BLOB)
		);

		if (!builder->u1.s1.TimeIsSet) {
			SYSTEMTIME begin;
			SYSTEMTIME end;

			GetSystemTime(&begin);
			
			RtlCopyMemory(&end, &begin, sizeof(SYSTEMTIME));

			end.wYear += 1;

			if (!X509CertBuilderSetEffectiveTime(X509CertBuilderHandle, &begin, &end))break;
		}

		RtlCopyMemory(
			&cert->NotBefore,
			&builder->NotBeforeDate,
			sizeof(FILETIME)
		);

		RtlCopyMemory(
			&cert->NotAfter,
			&builder->NotAfterDate,
			sizeof(FILETIME)
		);

		RtlCopyMemory(
			&cert->Subject,
			&builder->SubjectX500Name,
			sizeof(CERT_NAME_BLOB)
		);

		RtlCopyMemory(
			&cert->SubjectPublicKeyInfo,
			&builder->PublicKeyInfo,
			sizeof(CERT_PUBLIC_KEY_INFO)
		);

		cert->rgExtension = (PCERT_EXTENSION)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(CERT_EXTENSION) * CERT_EXTENSION_COUNT);
		if (!cert->rgExtension)break;

		for (DWORD i = 0; i < CERT_EXTENSION_COUNT; ++i) {
			if (builder->u1.s1.ExtensionsMask & (1 << i)) {
				RtlCopyMemory(
					&cert->rgExtension[cert->cExtension++],
					&builder->Extension[i],
					sizeof(CERT_EXTENSION)
				);
			}
		}

		if (!X509CertBuilderDuplicateCertInfoDeepCopy(CertInfo, cert))break;

		success = TRUE;
	} while (false);

	if (cert) {
		HeapFree(heap, 0, cert->rgExtension);
		HeapFree(heap, 0, cert);
	}
	return success;
}

BOOL WINAPI X509CertBuilderFreeCertInfo(_In_opt_ _Post_ptr_invalid_ PCERT_INFO CertInfo) {
	HANDLE heap = GetProcessHeap();

	if (!CertInfo)return FALSE;

	HeapFree(heap, 0, CertInfo->Issuer.pbData);
	HeapFree(heap, 0, CertInfo->SubjectPublicKeyInfo.Algorithm.Parameters.pbData);
	HeapFree(heap, 0, CertInfo->SubjectPublicKeyInfo.PublicKey.pbData);
	HeapFree(heap, 0, CertInfo->SerialNumber.pbData);
	HeapFree(heap, 0, CertInfo->SignatureAlgorithm.Parameters.pbData);
	HeapFree(heap, 0, CertInfo->Subject.pbData);

	for (DWORD i = 0; i < CertInfo->cExtension; ++i) {
		HeapFree(heap, 0, CertInfo->rgExtension[i].Value.pbData);
	}
	HeapFree(heap, 0, CertInfo);

	return TRUE;
}
