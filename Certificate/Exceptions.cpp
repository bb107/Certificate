#include "Exceptions.h"

CertificateException::CertificateException() {
	this->m_status = STATUS_SUCCESS;
}

CertificateException::CertificateException(CertificateException& _exceprtion) {
	this->m_status = _exceprtion.m_status;
}

CertificateException::CertificateException(NTSTATUS status) {
	this->m_status = status;
}

NTSTATUS CertificateException::status() {
	return this->m_status;
}

CertificateException& CertificateException::operator=(NTSTATUS status) {
	this->m_status = status;
	return *this;
}

std::ostream& CertificateException::operator>>(std::ostream& cout) {
	cout << this->what() << std::endl;
	return cout;
}

LPCSTR CertificateException::what() const throw() {
	switch (this->m_status) {
	case STATUS_SUCCESS:return "Success.";
	case STATUS_NO_KEY:return "This cert can not found private key.";
	case STATUS_INVALID_CERTIFICATE_CONTEXT:return "this->m_pCertContext is nullptr or CertDuplicateCertificateContext return is nullptr.";
	case STATUS_OPEN_STORE:return "Call CertOpenStore failed.";
	case STATUS_CN_NOT_FOUND:return "Search cert in store with CommonName is finished, but no cert found.";
	case STATUS_NEW_SEARCH:return "No search context, call FromStoreA or FromStoreW first.";
	case STATUS_SEARCH_END:return "Search completed, not found after last time.";
	case STATUS_CRYPT_PROVIDER:return "Acquire Crypt provider failed.";
	case STATUS_GEN_RANDOM:return "Call CryptGenRandom failed.";
	case STATUS_RPC_CALL:return "Call UuidToString failed.";
	case STATUS_GEN_KEY:return "Call CryptGenKey failed.";
	case STATUS_X500_CONVERT:return "Call CertStrToName or CertNameToStr failed.";
	case STATUS_BAD_SIGN_ALG:return "Invalid SignatureAlogrithm.";
	case STATUS_EXPORT_PUB_KEY:return "Call CryptExportPublicKeyInfo failed.";
	case STATUS_CREATE_HASH:return "Call CryptCreateHash failed.";
	case STATUS_HASH_DATA:return "Call CryptHashData failed.";
	case STATUS_GET_HASH_VAL:return "Call CryptGetHashParam failed.";
	case STATUS_ENCODE_KEY_ID:return "Call CryptEncodeObject CertKeyIdentifier failed.";
	case STATUS_ENCODE_KEY_USAGE:return "CryptEncodeObject KeyUsage failed.";
	case STATUS_ENCODE_KEY_ENH_USAGE:return "Call CryptEncodeObject KeyEnhUsage failed.";
	case STATUS_DECODE_KEY_ID:return "Call CryptDecodeObject CertKeyIdentifier failed.";
	case STATUS_ENCODE_AUTH_KEY_ID:return "Call CryptEncodeObject CertAuthKeyId failed.";
	case STATUS_ISSUER_CERTIFICATE:return "Issuer Certificate is invalid.";
	case STATUS_SIGN_CERTIFICATE:return "Issuer CryptSignAndEncodeCertificate is failed.";
	case STATUS_ADD_TO_STORE:return "Call CertAddEncodedCertificateToStore failed.";
	case STATUS_SET_CERT_PROP_KEY_ID:return "Call CertSetCertificateContextProperty CERT_KEY_PROV_INFO_PROP_ID failed.";
	case STATUS_CREATE_FILE:return "Call CreateFile failed.";
	case STATUS_WRITE_FILE:return "Call WriteFile failed.";
	case STATUS_DERIVE_KEY:return "Call CryptDeriveKey failed.";
	case STATUS_EXPORT_PRIV_KEY:return "Call CryptExportKey failed.";
	case STATUS_INVALID_CRYPT_HANDLE:return "hCryptProv or hCryptKey is nullptr";
	case STATUS_BAD_EXCHANGE_KEY:return "Private key Exchange password incorrect.";
	case STATUS_OPEN_FILE:return "CreateFile Open file failed.";
	case STATUS_READ_FILE:return "Call ReadFile failed.";
	case STATUS_GET_KEY_PARAM:return "Call CryptGetKeyParam failed.";
	case STATUS_GET_CERT_PROP_KEY_ID:return "Call CertGetCertificateContextProperty CERT_KEY_PROV_INFO_PROP_ID failed.";
	case STATUS_EXPORT_PFX:return "Call PFXExportCertStoreEx failed.";
	case STATUS_FILE_TYPE:return "Invalid file type.";
	case STATUS_IMPORT_PFX:return "Call PFXImportCertStore failed.";
	case STATUS_ENUM_STORE:return "Call CertEnumCertificatesInStore failed.";
	default:return "Bad exception";
	}
}

std::ostream& operator<<(std::ostream& cout, CertificateException& _exception) {
	std::cout << _exception.what();
	return cout;
}
