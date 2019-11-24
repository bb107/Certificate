#include "../Certificate/Certificate.h"
#include <cstdio>
#pragma comment(lib,"crypt32.lib")

bool TestSelfSignCert(Certificate &CA) {
	return NT_SUCCESS(CA(
		L"CN=TestSelfSign CA",		//Subject Common Name
		nullptr,					//Issuer's Certificate (nullptr is self-sign)
		SignSha1RSA,				//Signature Algorithm
		2048,						//RSA Bits
		AT_SIGNATURE,				//Key Type
		ALL_KEY_USAGE,				//Key Usage
		TRUE,						//Is CA
		0,							//Path Constraint (0 is no Constraint)
		nullptr,					//Expire Time (nullptr add 50 years)
		ALL_KEY_ENHANCED_USAGE,		//Common Key Enhanced Usage
		nullptr,					//Other Enhanced Key Usage
		nullptr));					//Other Certificate Extensions
}

bool TestIssuingCertificate(Certificate* Issuer, Certificate& Subject) {
	return NT_SUCCESS(Subject(L"CN=Test Subject", Issuer));
}

bool TestSaveCertificateToFile(Certificate& Cert) {
	Certificate tmp;
	bool success = NT_SUCCESS(Cert.ToFileW(L"Cert.cer", L"Cert.pvk", L"abcdef"));
	success &= !NT_SUCCESS(tmp.FromFileW(L"Cert.cer", L"Cert.pvk", L"00000000000"));
	success &= NT_SUCCESS(tmp.FromFileW(L"Cert.cer", L"Cert.pvk", L"abcdef"));
	DeleteFileA("Cert.cer");
	DeleteFileA("Cert.pvk");
	success &= NT_SUCCESS(tmp.ToFileW(L"Cert.cer"));
	DeleteFileA("Cert.cer");
	tmp.RemoveFromStore();
	return success;
}

bool TestSavePfx(Certificate& Cert) {
	Certificate tmp;
	bool success = NT_SUCCESS(Cert.ToPfxW(L"Cert.pfx", L"123456"));
	success &= !NT_SUCCESS(tmp.FromPfxW(L"Cert.pfx", L"666666"));
	success &= NT_SUCCESS(tmp.FromPfxW(L"Cert.pfx", L"123456"));
	DeleteFileA("Cert.pfx");
	tmp.RemoveFromStore();
	if (NT_SUCCESS(tmp.FromStoreW(L"Microsoft Root Authority", L"ca"))) {
		success &= !NT_SUCCESS(tmp.ToPfxW(L"Cert.pfx", L"666666"));
		tmp.ReleaseContexts();
	}
	return success;
}

int main() {
	Certificate CA, Subject;
	printf("Test Self-sign Cert:..............[%s]\n",
		TestSelfSignCert(CA) ? "OK" : "FAIL");
	printf("Test Issuing Certificate:.........[%s]\n",
		TestIssuingCertificate(&CA, Subject) ? "OK" : "FAIL");
	printf("Test Save Certificate To File:....[%s]\n",
		TestSaveCertificateToFile(CA) ? "OK" : "FAIL");
	printf("Test Save Pfx:....................[%s]\n",
		TestSavePfx(Subject) ? "OK" : "FAIL");
	CA.DestroyKeyAndDeleteKeySet();
	Subject.DestroyKeyAndDeleteKeySet();
	try {
		Certificate CA(L"abc", L"def");
	}
	catch (CertificateException* status) {
		(*status) >> std::cout << "Error Exit" << std::endl;
		return status->status();
	}
	system("pause");
	return 0;
}
