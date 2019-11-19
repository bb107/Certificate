#pragma once
#include <Windows.h>
#ifndef NT_SUCCESS
#define NT_SUCCESS(x) ((x)>=0)
#endif

//Exception codes
#define STATUS_SUCCESS						(NTSTATUS)0x00000000	//completed successfully.
#define STATUS_NO_KEY						(NTSTATUS)0x00000001	//this cert can not found private key.

#define STATUS_INVALID_CERTIFICATE_CONTEXT	(NTSTATUS)0x80000000	//invalid cert_context.
#define STATUS_OPEN_STORE					(NTSTATUS)0x80000001	//CertOpenStore failed.
#define STATUS_CN_NOT_FOUND					(NTSTATUS)0x80000002	//search cert in store with CommonName is finished, but no cert found.
#define STATUS_NEW_SEARCH					(NTSTATUS)0x80000003	//no search context, call FromStoreA or FromStoreW first.
#define STATUS_SEARCH_END					(NTSTATUS)0x80000004	//search completed, not found after last time.
#define STATUS_CRYPT_PROVIDER				(NTSTATUS)0x80000005	//Acquire Crypt provider failed.
#define STATUS_GEN_RANDOM					(NTSTATUS)0x80000006	//CryptGenRandom failed.
#define STATUS_RPC_CALL						(NTSTATUS)0x80000007	//UuidToString failed.
#define STATUS_GEN_KEY						(NTSTATUS)0x80000008	//CryptGenKey failed.
#define STATUS_X500_CONVERT					(NTSTATUS)0x80000009	//CertStrToName or CertNameToStr failed.
#define STATUS_BAD_SIGN_ALG					(NTSTATUS)0x8000000A	//Invalid SignatureAlogrithm.
#define STATUS_EXPORT_PUB_KEY				(NTSTATUS)0x8000000B	//CryptExportPublicKeyInfo failed.
#define STATUS_CREATE_HASH					(NTSTATUS)0x8000000C	//CryptCreateHash failed.
#define STATUS_HASH_DATA					(NTSTATUS)0x8000000D	//CryptHashData failed.
#define STATUS_GET_HASH_VAL					(NTSTATUS)0x8000000E	//CryptGetHashParam failed.
#define STATUS_ENCODE_KEY_ID				(NTSTATUS)0x8000000F	//CryptEncodeObject CertKeyIdentifier failed.
#define STATUS_ENCODE_KEY_USAGE				(NTSTATUS)0x80000010	//CryptEncodeObject KeyUsage failed.
#define STATUS_ENCODE_KEY_ENH_USAGE			(NTSTATUS)0x80000011	//CryptEncodeObject KeyEnhUsage failed.
#define STATUS_DECODE_KEY_ID				(NTSTATUS)0x80000012	//CryptDecodeObject CertKeyIdentifier failed.
#define STATUS_ENCODE_AUTH_KEY_ID			(NTSTATUS)0x80000013	//CryptEncodeObject CertAuthKeyId failed.
#define STATUS_ISSUER_CERTIFICATE			(NTSTATUS)0x80000014	//Issuer Certificate is invalid.
#define STATUS_SIGN_CERTIFICATE				(NTSTATUS)0x80000015	//Issuer CryptSignAndEncodeCertificate is invalid.
#define STATUS_ADD_TO_STORE					(NTSTATUS)0x80000016	//CertAddEncodedCertificateToStore failed.
#define STATUS_SET_CERT_PROP_KEY_ID			(NTSTATUS)0x80000017	//CertSetCertificateContextProperty CERT_KEY_PROV_INFO_PROP_ID failed.
#define STATUS_CREATE_FILE					(NTSTATUS)0x80000018	//CreateFile failed.
#define STATUS_WRITE_FILE					(NTSTATUS)0x80000019	//WriteFile failed.
#define STATUS_DERIVE_KEY					(NTSTATUS)0x8000001A	//CryptDeriveKey failed.
#define STATUS_EXPORT_PRIV_KEY				(NTSTATUS)0x8000001B	//CryptExportKey failed.
#define STATUS_INVALID_CRYPT_HANDLE			(NTSTATUS)0x8000001E	//hCryptProv or hCryptKey is nullptr
#define STATUS_BAD_EXCHANGE_KEY				(NTSTATUS)0x8000001F	//Private key Exchange password incorrect.
#define STATUS_OPEN_FILE					(NTSTATUS)0x80000020	//CreateFile Open file failed.
#define STATUS_READ_FILE					(NTSTATUS)0x80000021	//ReadFile failed.
#define STATUS_GET_KEY_PARAM				(NTSTATUS)0x80000022	//CryptGetKeyParam failed.
#define STATUS_GET_CERT_PROP_KEY_ID			(NTSTATUS)0x80000023	//CertGetCertificateContextProperty CERT_KEY_PROV_INFO_PROP_ID failed.
#define STATUS_EXPORT_PFX					(NTSTATUS)0x80000024	//PFXExportCertStoreEx failed.
#define STATUS_FILE_TYPE					(NTSTATUS)0x80000025	//Invalid file type.
#define STATUS_IMPORT_PFX					(NTSTATUS)0x80000026	//PFXImportCertStore failed.
#define STATUS_ENUM_STORE					(NTSTATUS)0x80000027	//CertEnumCertificatesInStore failed.
