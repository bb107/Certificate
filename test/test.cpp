#include "../Certificate/cert.h"
#include <cstdio>
#pragma warning(disable:4996)

PX509CERTIFICATE CreateSelfSignedCert(LPBYTE* cer, LPDWORD len) {
	KEY_INFO ki{};
	ki.RSAKeyLength = 2048;
	ki.SignatureAlgorithm = SIGNATURE_ALGORITHM::sha256RSA;

	BASIC_CONSTRAINT bc{};
	bc.Authority = TRUE;
	bc.MaxPathHeight = -1;

	KEY_USAGE kur{};
	kur.DigitalSignature = TRUE;
	kur.KeyAgreement = TRUE;
	kur.KeyCertSign = TRUE;

	BYTE buffer[sizeof(EKU_LIST) + sizeof(LPCSTR) * 2];
	PEKU_LIST el = (PEKU_LIST)&buffer[0];
	el->EkuCount = 2;
	el->Ekus[0] = szOID_PKIX_KP_CODE_SIGNING;
	el->Ekus[1] = szOID_PKIX_KP_SERVER_AUTH;


	PX509CERTIFICATE cert = nullptr;

	CreateX509Certificate(
		&cert,
		cer,
		len,
		nullptr,
		"CN=root test",
		&ki,
		nullptr,
		nullptr,
		nullptr,
		&bc,
		&kur,
		L"https://127.0.0.1",
		nullptr,
		el,
		nullptr
	);

	return cert;
}

PX509CERTIFICATE CreateSubjectCert(PX509CERTIFICATE issuer, LPBYTE* cer, LPDWORD len) {
	KEY_INFO ki{};
	ki.RSAKeyLength = 2048;
	ki.SignatureAlgorithm = SIGNATURE_ALGORITHM::sha256RSA;

	BASIC_CONSTRAINT bc{};
	bc.End = TRUE;
	bc.MaxPathHeight = -1;

	KEY_USAGE kur{};
	kur.DigitalSignature = TRUE;

	BYTE buffer[sizeof(EKU_LIST) + sizeof(LPCSTR) * 2];
	PEKU_LIST el = (PEKU_LIST)&buffer[0];
	el->EkuCount = 1;
	el->Ekus[0] = szOID_PKIX_KP_SERVER_AUTH;

	BYTE nameBuffer[sizeof(DNS_NAME_LIST) + sizeof(LPCWSTR) * 2];
	PDNS_NAME_LIST names = PDNS_NAME_LIST(&nameBuffer[0]);
	names->dwNames = 2;
	names->Names[0] = L"*.localhost.com";
	names->Names[1] = L"test.localhost.com";

	PX509CERTIFICATE cert = nullptr;

	CreateX509Certificate(
		&cert,
		cer,
		len,
		issuer,
		"CN=test.localhost.com",
		&ki,
		nullptr,
		nullptr,
		nullptr,
		&bc,
		&kur,
		nullptr,
		names,
		el,
		nullptr
	);

	return cert;
}

VOID SaveFile(LPCSTR FileName, LPVOID Buffer, DWORD Length) {
	auto file = fopen(FileName, "wb");
	if (file) {
		fwrite(Buffer, Length, 1, file);
		fclose(file);
	}
}

VOID TestCreate() {
	LPBYTE cer = nullptr;
	DWORD len = 0;
	auto cert = CreateSelfSignedCert(&cer, &len);

	if (cert) {
		SaveFile("auth.cer", cer, len);
		SaveFile("auth.pvk", cert->PrivateKey, cert->KeyLength);

		CloseX509Certificate(cert);
	}
}

VOID TestOpen() {
	PX509CERTIFICATE cert;
	OpenX509CertificateFromFile(&cert, "auth.cer", "auth.pvk");

	if (cert) {
		CloseX509Certificate(cert);
	}
}

VOID TestIssue() {
	PX509CERTIFICATE issuer;
	OpenX509CertificateFromFile(&issuer, "auth.cer", "auth.pvk");

	if (issuer) {
		LPBYTE cer = nullptr;
		DWORD len = 0;
		PX509CERTIFICATE cert = CreateSubjectCert(issuer, &cer, &len);

		if (cert) {
			SaveFile("sub.cer", cer, len);
			SaveFile("sub.pvk", cert->PrivateKey, cert->KeyLength);

			CloseX509Certificate(cert);
		}

		CloseX509Certificate(issuer);
	}
}

VOID TestStoreOpen() {
	PX509CERTIFICATE cert;

	OpenX509CertificateFromStore(&cert, "my", "Boringsoft Company Limited");
	if (cert) {
		CloseX509Certificate(cert);
	}
}

int main() {
	TestStoreOpen();
	return 0;
}
