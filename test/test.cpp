#include "../Certificate/stdafx.h"
#include <cstdio>
#pragma warning(disable:4996)

LPCSTR ekus[] = {
szOID_PKIX_KP_SERVER_AUTH,
szOID_PKIX_KP_CLIENT_AUTH,
szOID_PKIX_KP_CODE_SIGNING,
szOID_PKIX_KP_EMAIL_PROTECTION,
szOID_PKIX_KP_IPSEC_END_SYSTEM,
szOID_PKIX_KP_IPSEC_TUNNEL,
szOID_PKIX_KP_IPSEC_USER,
szOID_PKIX_KP_TIMESTAMP_SIGNING,
szOID_PKIX_KP_OCSP_SIGNING,
szOID_PKIX_OCSP_NOCHECK,
szOID_PKIX_OCSP_NONCE,
szOID_IPSEC_KP_IKE_INTERMEDIATE,
szOID_PKINIT_KP_KDC,
szOID_KP_CTL_USAGE_SIGNING,
szOID_KP_TIME_STAMP_SIGNING,
szOID_SERVER_GATED_CRYPTO,
szOID_SGC_NETSCAPE,
szOID_KP_EFS,
szOID_EFS_RECOVERY,
szOID_WHQL_CRYPTO,
szOID_ATTEST_WHQL_CRYPTO,
szOID_NT5_CRYPTO,
szOID_OEM_WHQL_CRYPTO,
szOID_EMBEDDED_NT_CRYPTO,
szOID_ROOT_LIST_SIGNER,
szOID_KP_QUALIFIED_SUBORDINATION,
szOID_KP_KEY_RECOVERY,
szOID_KP_DOCUMENT_SIGNING,
szOID_KP_LIFETIME_SIGNING,
szOID_KP_MOBILE_DEVICE_SOFTWARE,
szOID_KP_SMART_DISPLAY,
szOID_KP_CSP_SIGNATURE,
szOID_KP_FLIGHT_SIGNING,
szOID_PLATFORM_MANIFEST_BINARY_ID,
szOID_DRM,
szOID_DRM_INDIVIDUALIZATION,
szOID_LICENSES,
szOID_LICENSE_SERVER,
szOID_KP_SMARTCARD_LOGON,
szOID_KP_KERNEL_MODE_CODE_SIGNING,
szOID_KP_KERNEL_MODE_TRUSTED_BOOT_SIGNING,
szOID_REVOKED_LIST_SIGNER,
szOID_WINDOWS_KITS_SIGNER,
szOID_WINDOWS_RT_SIGNER,
szOID_PROTECTED_PROCESS_LIGHT_SIGNER,
szOID_WINDOWS_TCB_SIGNER,
szOID_PROTECTED_PROCESS_SIGNER,
szOID_WINDOWS_THIRD_PARTY_COMPONENT_SIGNER,
szOID_WINDOWS_SOFTWARE_EXTENSION_SIGNER,
szOID_DISALLOWED_LIST,
szOID_IUM_SIGNING,
szOID_EV_WHQL_CRYPTO,
szOID_BIOMETRIC_SIGNING,
szOID_ENCLAVE_SIGNING,
szOID_SYNC_ROOT_CTL_EXT,
szOID_HPKP_DOMAIN_NAME_CTL,
szOID_HPKP_HEADER_VALUE_CTL,
szOID_KP_KERNEL_MODE_HAL_EXTENSION_SIGNING,
szOID_WINDOWS_STORE_SIGNER,
szOID_DYNAMIC_CODE_GEN_SIGNER,
szOID_MICROSOFT_PUBLISHER_SIGNER
};

//
// Root CA
//
PCERT_INFO CreateRootCA(
	_Out_ LPBYTE* cer,
	_Out_ LPDWORD len,
	_Out_ PHANDLE Key) {

	*cer = nullptr;
	*len = 0;
	*Key = nullptr;

	HANDLE hBuilder = nullptr;
	HANDLE hKey = nullptr;

	KEY_USAGE ku{};
	ku.Flags = 0x80ff;

	SYSTEMTIME NotBefore, NotAfter;
	NotBefore.wYear = 2021;
	NotBefore.wMonth = 1;
	NotBefore.wDayOfWeek = 5;
	NotBefore.wDay = 1;
	NotBefore.wHour = 0;
	NotBefore.wMinute = 0;
	NotBefore.wSecond = 0;
	NotBefore.wMilliseconds = 0;

	NotAfter.wYear = 2040;
	NotAfter.wMonth = 12;
	NotAfter.wDayOfWeek = 1;
	NotAfter.wDay = 31;
	NotAfter.wHour = 23;
	NotAfter.wMinute = 59;
	NotAfter.wSecond = 59;
	NotAfter.wMilliseconds = 999;
	

	PCERT_INFO cert = nullptr;
	LPBYTE signedCert = nullptr;
	DWORD signedCertLength = 0;
	BOOL success = FALSE;

	do {
		if (!CreateRSAKey(&hKey, 2048))break;

		if (!CreateX509CertBuilder(&hBuilder, nullptr))break;

		if (!X509CertBuilderSetSubjectName(hBuilder, "CN=TEST Root CA"))break;
		if (!X509CertBuilderSetEffectiveTime(hBuilder, &NotBefore, &NotAfter))break;
		if (!X509CertBuilderSetIssuerName(hBuilder, nullptr))break;
		if (!X509CertBuilderSetSignatureAlgorithm(hBuilder, SIGNATURE_ALGORITHM::sha256RSA, nullptr))break;
		if (!X509CertBuilderSetSubjectKeyIdentifier(hBuilder, hKey, FALSE))break;
		if (!X509CertBuilderSetKeyUsage(hBuilder, ku, TRUE))break;
		if (!X509CertBuilderSetBasicConstraint(hBuilder, 10, X509_CERT_SUBJECT_TYPE_CA, FALSE))break;
		if (!X509CertBuilderSetSubjectPublicKeyInfo(hBuilder, hKey))break;

		if (!X509CertBuilderCreateCertInfo(&cert, hBuilder))break;

		if (!IssuerSignCertificate(&signedCert, &signedCertLength, cert, hKey))break;

		success = TRUE;
	} while (false);

	CloseX509CertBuilder(hBuilder);

	if (!success) {
		X509CertBuilderFreeCertInfo(cert);
		CloseRSAKey(hKey);
		cert = nullptr;
	}
	else {
		*cer = signedCert;
		*len = signedCertLength;
		*Key = hKey;
	}

	return cert;
}

//
// SSL CA
//
PCERT_INFO CreateSSLSubjectCA(
	_In_ PCERT_INFO issuer,
	_In_ HANDLE issuerKey,
	_Out_ LPBYTE* cer,
	_Out_ LPDWORD len,
	_Out_ PHANDLE subjectKey) {

	*cer = nullptr;
	*len = 0;
	*subjectKey = nullptr;

	HANDLE hBuilder = nullptr;
	HANDLE hKey = nullptr;

	KEY_USAGE ku{};
	ku.DigitalSignature = TRUE;
	ku.KeyEncipherment = TRUE;
	ku.KeyCertSign = TRUE;

	LPBYTE buffer = new BYTE[sizeof(CERT_ENHANCED_KEY_USAGE_LIST) + sizeof(LPCSTR) * 2];
	PCERT_ENHANCED_KEY_USAGE_LIST el = (PCERT_ENHANCED_KEY_USAGE_LIST)buffer;
	el->dwEnhancedKeyUsage = 2;
	el->EKUs[0] = szOID_PKIX_KP_CLIENT_AUTH;
	el->EKUs[1] = szOID_PKIX_KP_SERVER_AUTH;

	CERT_POLICY_QUALIFIER qualifier{};
	CERT_POLICY policiesBuffer[2];
	BYTE policiesListBuffer[sizeof(CERT_POLICY_LIST) + sizeof(PCERT_POLICY) * 2];
	PCERT_POLICY_LIST policies = PCERT_POLICY_LIST(&policiesListBuffer[0]);
	policies->dwPolicyInfo = 2;
	policies->Policies = policiesBuffer;

	policies->Policies[0].dwPolicyQualifier = 0;
	policies->Policies[0].PolicyIdentifier = "2.23.140.1.1";
	policies->Policies[1].dwPolicyQualifier = 1;
	policies->Policies[1].PolicyIdentifier = "2.16.840.1.114412.2.1";
	policies->Policies[1].PolicyQualifiers = &qualifier;
	qualifier.PolicyQualifierId = X509_CERT_POLICY_QUALIFIER_CPS;
	qualifier.Qualifier = "http://127.0.0.1";

	PCERT_INFO cert = nullptr;
	LPBYTE signedCert = nullptr;
	DWORD signedCertLength = 0;
	BOOL success = FALSE;

	do {
		if (!CreateRSAKey(&hKey, 2048))break;

		if (!CreateX509CertBuilder(&hBuilder, nullptr))break;

		if (!X509CertBuilderSetSubjectName(hBuilder, "CN=TEST SSL RSA CA G1"))break;
		if (!X509CertBuilderSetIssuerName(hBuilder, &issuer->Subject))break;
		if (!X509CertBuilderSetSignatureAlgorithm(hBuilder, SIGNATURE_ALGORITHM::sha256RSA, nullptr))break;
		if (!X509CertBuilderSetSubjectKeyIdentifier(hBuilder, hKey, FALSE))break;
		if (!X509CertBuilderSetAuthorityKeyIdentifier(hBuilder, nullptr, nullptr, issuerKey, FALSE))break;
		if (!X509CertBuilderSetKeyUsage(hBuilder, ku, TRUE))break;
		if (!X509CertBuilderSetBasicConstraint(hBuilder, -1, X509_CERT_SUBJECT_TYPE_CA, FALSE))break;
		if (!X509CertBuilderSetEnhancedKeyUsage(hBuilder, el, FALSE))break;
		if (!X509CertBuilderSetSubjectPublicKeyInfo(hBuilder, hKey))break;
		if (!X509CertBuilderSetPolicies(hBuilder, policies, FALSE))break;

		if (!X509CertBuilderCreateCertInfo(&cert, hBuilder))break;

		if (!IssuerSignCertificate(&signedCert, &signedCertLength, cert, issuerKey))break;

		success = TRUE;
	} while (false);

	CloseX509CertBuilder(hBuilder);

	if (!success) {
		X509CertBuilderFreeCertInfo(cert);
		CloseRSAKey(hKey);
		cert = nullptr;
	}
	else {
		*cer = signedCert;
		*len = signedCertLength;
		*subjectKey = hKey;
	}

	return cert;
}

//
// Code Signing CA
//
PCERT_INFO CreateCodeSignSubjectCA(
	_In_ PCERT_INFO issuer,
	_In_ HANDLE issuerKey,
	_Out_ LPBYTE* cer,
	_Out_ LPDWORD len,
	_Out_ PHANDLE subjectKey) {

	*cer = nullptr;
	*len = 0;
	*subjectKey = nullptr;

	HANDLE hBuilder = nullptr;
	HANDLE hKey = nullptr;

	KEY_USAGE ku{};
	ku.DigitalSignature = TRUE;
	ku.DataEncipherment = TRUE;
	ku.KeyCertSign = TRUE;

	LPBYTE buffer = new BYTE[sizeof(CERT_ENHANCED_KEY_USAGE_LIST) + sizeof(ekus)];
	PCERT_ENHANCED_KEY_USAGE_LIST el = (PCERT_ENHANCED_KEY_USAGE_LIST)buffer;
	el->dwEnhancedKeyUsage = sizeof(ekus) / sizeof(LPCSTR);
	RtlCopyMemory(
		&el->EKUs[0],
		&ekus[0],
		sizeof(ekus)
	);

	PCERT_INFO cert = nullptr;
	LPBYTE signedCert = nullptr;
	DWORD signedCertLength = 0;
	BOOL success = FALSE;

	do {
		if (!CreateRSAKey(&hKey, 2048))break;

		if (!CreateX509CertBuilder(&hBuilder, nullptr))break;

		if (!X509CertBuilderSetSubjectName(hBuilder, "CN=TEST Code Signing RSA CA G1"))break;
		if (!X509CertBuilderSetIssuerName(hBuilder, &issuer->Subject))break;
		if (!X509CertBuilderSetSignatureAlgorithm(hBuilder, SIGNATURE_ALGORITHM::sha256RSA, nullptr))break;
		if (!X509CertBuilderSetSubjectKeyIdentifier(hBuilder, hKey, FALSE))break;
		if (!X509CertBuilderSetAuthorityKeyIdentifier(hBuilder, nullptr, nullptr, issuerKey, FALSE))break;
		if (!X509CertBuilderSetKeyUsage(hBuilder, ku, TRUE))break;
		if (!X509CertBuilderSetBasicConstraint(hBuilder, -1, X509_CERT_SUBJECT_TYPE_CA, FALSE))break;
		if (!X509CertBuilderSetEnhancedKeyUsage(hBuilder, el, FALSE))break;
		if (!X509CertBuilderSetSubjectPublicKeyInfo(hBuilder, hKey))break;

		if (!X509CertBuilderCreateCertInfo(&cert, hBuilder))break;

		if (!IssuerSignCertificate(&signedCert, &signedCertLength, cert, issuerKey))break;

		success = TRUE;
	} while (false);

	CloseX509CertBuilder(hBuilder);

	if (!success) {
		X509CertBuilderFreeCertInfo(cert);
		CloseRSAKey(hKey);
		cert = nullptr;
	}
	else {
		*cer = signedCert;
		*len = signedCertLength;
		*subjectKey = hKey;
	}

	return cert;
}

//
// SSL Server:  *.localhost.com
//
PCERT_INFO CreateSSLSubject(
	_In_ PCERT_INFO issuer,
	_In_ HANDLE issuerKey,
	_Out_ LPBYTE* cer,
	_Out_ LPDWORD len,
	_Out_ PHANDLE subjectKey) {

	*cer = nullptr;
	*len = 0;
	*subjectKey = nullptr;

	HANDLE hBuilder = nullptr;
	HANDLE hKey = nullptr;

	KEY_USAGE ku{};
	ku.DigitalSignature = TRUE;
	ku.KeyEncipherment = TRUE;

	BYTE buffer[sizeof(CERT_ENHANCED_KEY_USAGE_LIST) + sizeof(LPCSTR) * 2];
	PCERT_ENHANCED_KEY_USAGE_LIST el = (PCERT_ENHANCED_KEY_USAGE_LIST)&buffer[0];
	el->dwEnhancedKeyUsage = 2;
	el->EKUs[0] = szOID_PKIX_KP_CLIENT_AUTH;
	el->EKUs[1] = szOID_PKIX_KP_SERVER_AUTH;

	BYTE sanBuffer[sizeof(CERT_SAN) * 2];
	CERT_SAN_LIST san{};
	san.dwSAN = 2;
	san.SANs = PCERT_SAN(&sanBuffer[0]);
	san.SANs[0].type = X509_CERT_SAN_TYPE_DNS;
	san.SANs[0].SAN = "*.localhost.com";
	san.SANs[1].type = X509_CERT_SAN_TYPE_DNS;
	san.SANs[1].SAN = "test.localhost.com";

	CERT_POLICY_QUALIFIER qualifier{};
	CERT_POLICY policiesBuffer[2];
	BYTE policiesListBuffer[sizeof(CERT_POLICY_LIST) + sizeof(PCERT_POLICY) * 2];
	PCERT_POLICY_LIST policies=PCERT_POLICY_LIST(&policiesListBuffer[0]);
	policies->dwPolicyInfo = 2;
	policies->Policies = policiesBuffer;

	policies->Policies[0].dwPolicyQualifier = 0;
	policies->Policies[0].PolicyIdentifier = "2.23.140.1.1";
	policies->Policies[1].dwPolicyQualifier = 1;
	policies->Policies[1].PolicyIdentifier = "2.16.840.1.114412.2.1";
	policies->Policies[1].PolicyQualifiers = &qualifier;
	qualifier.PolicyQualifierId = X509_CERT_POLICY_QUALIFIER_CPS;
	qualifier.Qualifier = "http://127.0.0.1";

	BYTE aiaBuffer[sizeof(CERT_AUTHORITY_INFO_ACCESS_LIST) * 2];
	PCERT_AUTHORITY_INFO_ACCESS_LIST aia=(PCERT_AUTHORITY_INFO_ACCESS_LIST)&aiaBuffer[0];
	aia->dwAccDescr = 2;
	aia->AccDescrs[0].AccessMethod = X509_CERT_AYTHORITY_INFO_ACCESS_METHOD_OCSP;
	aia->AccDescrs[0].AccessLocation.dwType = X509_CERT_AUTHORITY_INFO_ACCESS_LOCATION_URL;
	aia->AccDescrs[0].AccessLocation.Name = "http://127.0.0.1";
	aia->AccDescrs[1].AccessMethod = X509_CERT_AYTHORITY_INFO_ACCESS_METHOD_CA_ISSUERS;
	aia->AccDescrs[1].AccessLocation.dwType = X509_CERT_AUTHORITY_INFO_ACCESS_LOCATION_URL;
	aia->AccDescrs[1].AccessLocation.Name = "http://127.0.0.1/certs/sslca.cer";

	CERT_CRL_DIST_POINT_NAME_LIST crl{};
	CERT_CRL_DIST_POINT_LIST crll{};
	crl.dwName = 1;
	crl.dwType = X509_CERT_CRL_DIST_POINT_NAME_TYPE_FULL_NAME;
	crl.Names[0].dwType = X509_CERT_CRL_DIST_POINT_NAME_URL;
	crl.Names[0].Name = "http://127.0.0.1";
	crll.dwCRL = 1;
	crll.CRLs->DistPointNames = &crl;


	PCERT_INFO cert = nullptr;
	LPBYTE signedCert = nullptr;
	DWORD signedCertLength = 0;
	BOOL success = FALSE;

	do {
		if (!CreateRSAKey(&hKey, 2048))break;

		if (!CreateX509CertBuilder(&hBuilder, nullptr))break;

		if (!X509CertBuilderSetSubjectName(hBuilder, "CN=test.localhost.com,S=ShanDong,C=CN,2.5.4.15=TEST,1.3.6.1.4.1.311.60.2.1.3=CN,2.5.4.5=123456"))break;
		if (!X509CertBuilderSetIssuerName(hBuilder, &issuer->Subject))break;
		if (!X509CertBuilderSetSignatureAlgorithm(hBuilder, SIGNATURE_ALGORITHM::sha256RSA, nullptr))break;
		if (!X509CertBuilderSetSubjectKeyIdentifier(hBuilder, hKey, FALSE))break;
		if (!X509CertBuilderSetAuthorityKeyIdentifier(hBuilder, nullptr, nullptr, issuerKey, FALSE))break;
		if (!X509CertBuilderSetKeyUsage(hBuilder, ku, TRUE))break;
		if (!X509CertBuilderSetBasicConstraint(hBuilder, -1, X509_CERT_SUBJECT_TYPE_END, TRUE))break;
		if (!X509CertBuilderSetEnhancedKeyUsage(hBuilder, el, FALSE))break;
		if (!X509CertBuilderSetSubjectAlternativeName(hBuilder, &san, FALSE))break;
		if (!X509CertBuilderSetPolicies(hBuilder, policies, FALSE))break;
		if (!X509CertBuilderSetSubjectPublicKeyInfo(hBuilder, hKey))break;
		if (!X509CertBuilderSetAuthorityInfoAccess(hBuilder, aia, FALSE))break;
		if (!X509CertBuilderSetCRL(hBuilder, &crll, FALSE))break;


		if (!X509CertBuilderCreateCertInfo(&cert, hBuilder))break;

		if (!IssuerSignCertificate(&signedCert, &signedCertLength, cert, issuerKey))break;

		success = TRUE;
	} while (false);

	CloseX509CertBuilder(hBuilder);

	if (!success) {
		X509CertBuilderFreeCertInfo(cert);
		CloseRSAKey(hKey);
		cert = nullptr;
	}
	else {
		*cer = signedCert;
		*len = signedCertLength;
		*subjectKey = hKey;
	}

	return cert;
}

//
// SSL Client:  TEST
//
PCERT_INFO CreateSSLClientSubject(
	_In_ PCERT_INFO issuer,
	_In_ HANDLE issuerKey,
	_Out_ LPBYTE* cer,
	_Out_ LPDWORD len,
	_Out_ PHANDLE subjectKey) {

	*cer = nullptr;
	*len = 0;
	*subjectKey = nullptr;

	HANDLE hBuilder = nullptr;
	HANDLE hKey = nullptr;

	KEY_USAGE ku{};
	ku.DigitalSignature = TRUE;
	ku.KeyEncipherment = TRUE;

	BYTE buffer[sizeof(CERT_ENHANCED_KEY_USAGE_LIST) + sizeof(LPCSTR) * 1];
	PCERT_ENHANCED_KEY_USAGE_LIST el = (PCERT_ENHANCED_KEY_USAGE_LIST)&buffer[0];
	el->dwEnhancedKeyUsage = 1;
	el->EKUs[0] = szOID_PKIX_KP_CLIENT_AUTH;

	BYTE sanBuffer[sizeof(CERT_SAN) * 1];
	CERT_SAN_LIST san{};
	san.dwSAN = 1;
	san.SANs = PCERT_SAN(&sanBuffer[0]);
	san.SANs[0].type = X509_CERT_SAN_TYPE_DNS;
	san.SANs[0].SAN = "WMS";

	BYTE aiaBuffer[sizeof(CERT_AUTHORITY_INFO_ACCESS_LIST) * 2];
	PCERT_AUTHORITY_INFO_ACCESS_LIST aia = (PCERT_AUTHORITY_INFO_ACCESS_LIST)&aiaBuffer[0];
	aia->dwAccDescr = 2;
	aia->AccDescrs[0].AccessMethod = X509_CERT_AYTHORITY_INFO_ACCESS_METHOD_OCSP;
	aia->AccDescrs[0].AccessLocation.dwType = X509_CERT_AUTHORITY_INFO_ACCESS_LOCATION_URL;
	aia->AccDescrs[0].AccessLocation.Name = "http://127.0.0.1";
	aia->AccDescrs[1].AccessMethod = X509_CERT_AYTHORITY_INFO_ACCESS_METHOD_CA_ISSUERS;
	aia->AccDescrs[1].AccessLocation.dwType = X509_CERT_AUTHORITY_INFO_ACCESS_LOCATION_URL;
	aia->AccDescrs[1].AccessLocation.Name = "http://127.0.0.1/certs/sslca.cer";

	PCERT_INFO cert = nullptr;
	LPBYTE signedCert = nullptr;
	DWORD signedCertLength = 0;
	BOOL success = FALSE;

	do {
		if (!CreateRSAKey(&hKey, 2048))break;

		if (!CreateX509CertBuilder(&hBuilder, nullptr))break;

		if (!X509CertBuilderSetSubjectName(hBuilder, "CN=TEST"))break;
		if (!X509CertBuilderSetIssuerName(hBuilder, &issuer->Subject))break;
		if (!X509CertBuilderSetSignatureAlgorithm(hBuilder, SIGNATURE_ALGORITHM::sha256RSA, nullptr))break;
		if (!X509CertBuilderSetSubjectKeyIdentifier(hBuilder, hKey, FALSE))break;
		if (!X509CertBuilderSetAuthorityKeyIdentifier(hBuilder, nullptr, nullptr, issuerKey, FALSE))break;
		if (!X509CertBuilderSetKeyUsage(hBuilder, ku, TRUE))break;
		if (!X509CertBuilderSetBasicConstraint(hBuilder, -1, X509_CERT_SUBJECT_TYPE_END, TRUE))break;
		if (!X509CertBuilderSetEnhancedKeyUsage(hBuilder, el, FALSE))break;
		if (!X509CertBuilderSetSubjectAlternativeName(hBuilder, &san, FALSE))break;
		if (!X509CertBuilderSetSubjectPublicKeyInfo(hBuilder, hKey))break;
		if (!X509CertBuilderSetAuthorityInfoAccess(hBuilder, aia, FALSE))break;


		if (!X509CertBuilderCreateCertInfo(&cert, hBuilder))break;

		if (!IssuerSignCertificate(&signedCert, &signedCertLength, cert, issuerKey))break;

		success = TRUE;
	} while (false);

	CloseX509CertBuilder(hBuilder);

	if (!success) {
		X509CertBuilderFreeCertInfo(cert);
		CloseRSAKey(hKey);
		cert = nullptr;
	}
	else {
		*cer = signedCert;
		*len = signedCertLength;
		*subjectKey = hKey;
	}

	return cert;
}

//
// Code Signing
//
PCERT_INFO CreateCodeSignSubject(
	_In_ PCERT_INFO issuer,
	_In_ HANDLE issuerKey,
	_Out_ LPBYTE* cer,
	_Out_ LPDWORD len,
	_Out_ PHANDLE subjectKey) {

	*cer = nullptr;
	*len = 0;
	*subjectKey = nullptr;

	HANDLE hBuilder = nullptr;
	HANDLE hKey = nullptr;

	KEY_USAGE ku{};
	ku.DigitalSignature = TRUE;
	ku.KeyEncipherment = TRUE;

	BYTE buffer[sizeof(CERT_ENHANCED_KEY_USAGE_LIST) + sizeof(LPCSTR) * 2];
	PCERT_ENHANCED_KEY_USAGE_LIST el = (PCERT_ENHANCED_KEY_USAGE_LIST)&buffer[0];
	el->dwEnhancedKeyUsage = 2;
	el->EKUs[0] = szOID_PKIX_KP_CODE_SIGNING;
	el->EKUs[1] = szOID_NT5_CRYPTO;

	CERT_POLICY policiesBuffer[3];
	BYTE policiesListBuffer[sizeof(CERT_POLICY_LIST) + sizeof(PCERT_POLICY) * 3];
	PCERT_POLICY_LIST policies = PCERT_POLICY_LIST(&policiesListBuffer[0]);
	policies->dwPolicyInfo = 3;
	policies->Policies = policiesBuffer;

	policies->Policies[0].dwPolicyQualifier = 0;
	policies->Policies[0].PolicyIdentifier = "2.23.140.1.3";
	policies->Policies[1].dwPolicyQualifier = 0;
	policies->Policies[1].PolicyIdentifier = "2.23.140.1.4.1";
	policies->Policies[2].dwPolicyQualifier = 0;
	policies->Policies[2].PolicyIdentifier = "2.16.840.1.114412.3.1";

	BYTE aiaBuffer[sizeof(CERT_AUTHORITY_INFO_ACCESS_LIST) * 2];
	PCERT_AUTHORITY_INFO_ACCESS_LIST aia = (PCERT_AUTHORITY_INFO_ACCESS_LIST)&aiaBuffer[0];
	aia->dwAccDescr = 2;
	aia->AccDescrs[0].AccessMethod = X509_CERT_AYTHORITY_INFO_ACCESS_METHOD_OCSP;
	aia->AccDescrs[0].AccessLocation.dwType = X509_CERT_AUTHORITY_INFO_ACCESS_LOCATION_URL;
	aia->AccDescrs[0].AccessLocation.Name = "http://127.0.0.1";
	aia->AccDescrs[1].AccessMethod = X509_CERT_AYTHORITY_INFO_ACCESS_METHOD_CA_ISSUERS;
	aia->AccDescrs[1].AccessLocation.dwType = X509_CERT_AUTHORITY_INFO_ACCESS_LOCATION_URL;
	aia->AccDescrs[1].AccessLocation.Name = "http://127.0.0.1/certs/codesignca.cer";

	CERT_CRL_DIST_POINT_NAME_LIST crl{};
	CERT_CRL_DIST_POINT_LIST crll{};
	crl.dwName = 1;
	crl.dwType = X509_CERT_CRL_DIST_POINT_NAME_TYPE_FULL_NAME;
	crl.Names[0].dwType = X509_CERT_CRL_DIST_POINT_NAME_URL;
	crl.Names[0].Name = "http://127.0.0.1";
	crll.dwCRL = 1;
	crll.CRLs->DistPointNames = &crl;


	PCERT_INFO cert = nullptr;
	LPBYTE signedCert = nullptr;
	DWORD signedCertLength = 0;
	BOOL success = FALSE;

	do {
		if (!CreateRSAKey(&hKey, 2048))break;

		if (!CreateX509CertBuilder(&hBuilder, nullptr))break;

		if (!X509CertBuilderSetSubjectName(hBuilder, "CN=TEST,S=ShanDong,C=CN,2.5.4.15=TEST,1.3.6.1.4.1.311.60.2.1.3=CN"))break;
		if (!X509CertBuilderSetIssuerName(hBuilder, &issuer->Subject))break;
		if (!X509CertBuilderSetSignatureAlgorithm(hBuilder, SIGNATURE_ALGORITHM::sha256RSA, nullptr))break;
		if (!X509CertBuilderSetSubjectKeyIdentifier(hBuilder, hKey, FALSE))break;
		if (!X509CertBuilderSetAuthorityKeyIdentifier(hBuilder, nullptr, nullptr, issuerKey, FALSE))break;
		if (!X509CertBuilderSetKeyUsage(hBuilder, ku, TRUE))break;
		if (!X509CertBuilderSetBasicConstraint(hBuilder, -1, X509_CERT_SUBJECT_TYPE_END, TRUE))break;
		if (!X509CertBuilderSetEnhancedKeyUsage(hBuilder, el, FALSE))break;
		if (!X509CertBuilderSetPolicies(hBuilder, policies, FALSE))break;
		if (!X509CertBuilderSetSubjectPublicKeyInfo(hBuilder, hKey))break;
		if (!X509CertBuilderSetAuthorityInfoAccess(hBuilder, aia, FALSE))break;
		if (!X509CertBuilderSetCRL(hBuilder, &crll, FALSE))break;


		if (!X509CertBuilderCreateCertInfo(&cert, hBuilder))break;

		if (!IssuerSignCertificate(&signedCert, &signedCertLength, cert, issuerKey))break;

		success = TRUE;
	} while (false);

	CloseX509CertBuilder(hBuilder);

	if (!success) {
		X509CertBuilderFreeCertInfo(cert);
		CloseRSAKey(hKey);
		cert = nullptr;
	}
	else {
		*cer = signedCert;
		*len = signedCertLength;
		*subjectKey = hKey;
	}

	return cert;
}

VOID SaveFile(LPCSTR FileName, LPVOID Buffer, DWORD Length) {
	auto file = fopen(FileName, "wb");
	if (file) {
		fwrite(Buffer, Length, 1, file);
		fclose(file);
	}
}

BOOL WINAPI Write(LPCVOID param, LPVOID data, DWORD len) {
	SaveFile(LPCSTR(param), data, len);
	return TRUE;
}

VOID IssueSubject() {
	PCERT_INFO cert;
	HANDLE hKey;
	LPBYTE buffer;
	DWORD len;

	OpenX509CertificateFromFile(&cert, "SSLCA.cer");
	OpenRSAKeyFromFile(&hKey, "SSLCA.pvk");
	if (cert) {
		HANDLE SSL_Key;
		PCERT_INFO SSL_Cert = CreateSSLSubject(cert, hKey, &buffer, &len, &SSL_Key);
		if (SSL_Cert) {
			SaveFile("SSL.cer", buffer, len);
			RSAKeySave(SSL_Key, Write, "SSL.pvk");
			HeapFree(GetProcessHeap(), 0, buffer);

			X509CertBuilderFreeCertInfo(SSL_Cert);
			CloseRSAKey(SSL_Key);
		}

		CloseX509Certificate(cert);
		CloseRSAKey(hKey);
	}

	OpenX509CertificateFromFile(&cert, "CodeSigningCA.cer");
	OpenRSAKeyFromFile(&hKey, "CodeSigningCA.pvk");
	if (cert) {
		HANDLE CodeSigning_Key;
		PCERT_INFO CodeSigning_Cert = CreateCodeSignSubject(cert, hKey, &buffer, &len, &CodeSigning_Key);
		if (CodeSigning_Cert) {
			SaveFile("CodeSigning.cer", buffer, len);
			RSAKeySave(CodeSigning_Key, Write, "CodeSigning.pvk");
			HeapFree(GetProcessHeap(), 0, buffer);

			X509CertBuilderFreeCertInfo(CodeSigning_Cert);
			CloseRSAKey(CodeSigning_Key);
		}

		CloseX509Certificate(cert);
		CloseRSAKey(hKey);
	}

}

VOID IssueSSLClient() {
	PCERT_INFO cert;
	HANDLE hKey;
	LPBYTE buffer;
	DWORD len;

	OpenX509CertificateFromFile(&cert, "SSLCA.cer");
	OpenRSAKeyFromFile(&hKey, "SSLCA.pvk");
	if (cert) {
		HANDLE SSL_Key;
		PCERT_INFO SSL_Cert = CreateSSLClientSubject(cert, hKey, &buffer, &len, &SSL_Key);
		if (SSL_Cert) {
			SaveFile("SSLClient.cer", buffer, len);
			RSAKeySave(SSL_Key, Write, "SSLClient.pvk");
			HeapFree(GetProcessHeap(), 0, buffer);

			X509CertBuilderFreeCertInfo(SSL_Cert);
			CloseRSAKey(SSL_Key);
		}

		CloseX509Certificate(cert);
		CloseRSAKey(hKey);
	}
}

VOID BuildCertificateChain() {
	LPBYTE buffer;
	DWORD len;

	HANDLE RootCertKey;
	PCERT_INFO RootCert = CreateRootCA(&buffer, &len, &RootCertKey);
	if (RootCert) {
		SaveFile("RootCA.cer", buffer, len);
		RSAKeySave(RootCertKey, Write, "RootCA.pvk");
		HeapFree(GetProcessHeap(), 0, buffer);

		HANDLE SSLCA_Key;
		PCERT_INFO SSLCA_Cert = CreateSSLSubjectCA(RootCert, RootCertKey, &buffer, &len, &SSLCA_Key);
		if (SSLCA_Cert) {
			SaveFile("SSLCA.cer", buffer, len);
			RSAKeySave(SSLCA_Key, Write, "SSLCA.pvk");
			HeapFree(GetProcessHeap(), 0, buffer);

			HANDLE SSL_Key;
			PCERT_INFO SSL_Cert = CreateSSLSubject(SSLCA_Cert, SSLCA_Key, &buffer, &len, &SSL_Key);
			if (SSL_Cert) {
				SaveFile("SSL.cer", buffer, len);
				RSAKeySave(SSL_Key, Write, "SSL.pvk");
				HeapFree(GetProcessHeap(), 0, buffer);

				X509CertBuilderFreeCertInfo(SSL_Cert);
				CloseRSAKey(SSL_Key);
			}

			SSL_Cert = CreateSSLClientSubject(SSLCA_Cert, SSLCA_Key, &buffer, &len, &SSL_Key);
			if (SSL_Cert) {
				SaveFile("SSLClient.cer", buffer, len);
				RSAKeySave(SSL_Key, Write, "SSLClient.pvk");
				HeapFree(GetProcessHeap(), 0, buffer);

				X509CertBuilderFreeCertInfo(SSL_Cert);
				CloseRSAKey(SSL_Key);
			}

			X509CertBuilderFreeCertInfo(SSLCA_Cert);
			CloseRSAKey(SSLCA_Key);
		}

		HANDLE CodeSigningCA_Key;
		PCERT_INFO CodeSigningCA_Cert = CreateCodeSignSubjectCA(RootCert, RootCertKey, &buffer, &len, &CodeSigningCA_Key);
		if (CodeSigningCA_Cert) {
			SaveFile("CodeSigningCA.cer", buffer, len);
			RSAKeySave(CodeSigningCA_Key, Write, "CodeSigningCA.pvk");
			HeapFree(GetProcessHeap(), 0, buffer);

			HANDLE CodeSigning_Key;
			PCERT_INFO CodeSigning_Cert = CreateCodeSignSubject(CodeSigningCA_Cert, CodeSigningCA_Key, &buffer, &len, &CodeSigning_Key);
			if (CodeSigning_Cert) {
				SaveFile("CodeSigning.cer", buffer, len);
				RSAKeySave(CodeSigning_Key, Write, "CodeSigning.pvk");
				HeapFree(GetProcessHeap(), 0, buffer);

				X509CertBuilderFreeCertInfo(CodeSigning_Cert);
				CloseRSAKey(CodeSigning_Key);
			}

			X509CertBuilderFreeCertInfo(CodeSigningCA_Cert);
			CloseRSAKey(CodeSigningCA_Key);
		}

		X509CertBuilderFreeCertInfo(RootCert);
		CloseRSAKey(RootCertKey);
	}

}

int main() {
	//TestCodeSignCreate();
	//TestCodeSignIssue();
	BuildCertificateChain();
	return 0;
}
