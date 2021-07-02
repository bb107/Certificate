#pragma once

BOOL WINAPI OpenRSAKeyFromFile(
	_Out_ PHANDLE KeyHandle,
	_In_ LPCSTR KeyFileName
);

BOOL WINAPI CreateRSAKey(
	_Out_ PHANDLE KeyHandle,
	_In_ DWORD KeyLength
);

BOOL WINAPI CloseRSAKey(_In_opt_ _Post_ptr_invalid_ HANDLE KeyHandle);

PCERT_PUBLIC_KEY_INFO WINAPI RSAKeyGetPublicKeyInfo(_In_ HANDLE KeyHandle);

BOOL WINAPI RSAKeyGetCryptProvHandle(
	_Out_ HCRYPTPROV* CryptProv,
	_Out_ HCRYPTKEY* CryptKey,
	_In_ HANDLE KeyHandle
);

VOID WINAPI RSAKeyReleaseCryptProvider(
	_In_opt_ HCRYPTPROV CryptProv,
	_In_opt_ HCRYPTKEY CryptKey
);

typedef BOOL(WINAPI* COMMON_WRITE_ROUTINE)(LPCVOID parameter, LPVOID dataToWrites, DWORD dataLength);

BOOL WINAPI RSAKeySave(
	_In_ HANDLE KeyHandle,
	_In_ COMMON_WRITE_ROUTINE WriteRoutine,
	_In_ LPCVOID Parameter
);
