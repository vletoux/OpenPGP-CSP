/*	OpenPGP CSP
Copyright (C) 2017 Vincent Le Toux

This library is Free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License version 2.1 as published by the Free Software Foundation.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifdef __cplusplus
extern "C" {
#endif

//
// Interfaces
//

#define NCRYPT_HASH_INTERFACE                   BCRYPT_HASH_INTERFACE
#define NCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE  BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE

#define NCRYPT_SECRET_AGREEMENT_INTERFACE       BCRYPT_SECRET_AGREEMENT_INTERFACE

#define NCRYPT_SIGNATURE_INTERFACE              BCRYPT_SIGNATURE_INTERFACE

#define NCRYPT_KEY_STORAGE_INTERFACE            0x00010001
#define NCRYPT_SCHANNEL_INTERFACE               0x00010002
#define NCRYPT_SCHANNEL_SIGNATURE_INTERFACE     0x00010003

//
// algorithm groups.
//

#define NCRYPT_RSA_ALGORITHM_GROUP      NCRYPT_RSA_ALGORITHM
#define NCRYPT_DH_ALGORITHM_GROUP       NCRYPT_DH_ALGORITHM
#define NCRYPT_DSA_ALGORITHM_GROUP      NCRYPT_DSA_ALGORITHM
#define NCRYPT_ECDSA_ALGORITHM_GROUP    L"ECDSA"
#define NCRYPT_ECDH_ALGORITHM_GROUP     L"ECDH"

//
// NCrypt generic memory descriptors
//

#define NCRYPTBUFFER_VERSION                0

#define NCRYPTBUFFER_EMPTY                  0
#define NCRYPTBUFFER_DATA                   1
#define NCRYPTBUFFER_SSL_CLIENT_RANDOM      20
#define NCRYPTBUFFER_SSL_SERVER_RANDOM      21
#define NCRYPTBUFFER_SSL_HIGHEST_VERSION    22
#define NCRYPTBUFFER_SSL_CLEAR_KEY          23
#define NCRYPTBUFFER_SSL_KEY_ARG_DATA       24

#define NCRYPTBUFFER_PKCS_OID               40
#define NCRYPTBUFFER_PKCS_ALG_OID           41
#define NCRYPTBUFFER_PKCS_ALG_PARAM         42
#define NCRYPTBUFFER_PKCS_ALG_ID            43
#define NCRYPTBUFFER_PKCS_ATTRS             44
#define NCRYPTBUFFER_PKCS_KEY_NAME          45
#define NCRYPTBUFFER_PKCS_SECRET            46

#define NCRYPTBUFFER_CERT_BLOB              47

// NCRYPT shares the same BCRYPT definitions
typedef BCryptBuffer     NCryptBuffer;
typedef BCryptBuffer*    PNCryptBuffer;
typedef BCryptBufferDesc NCryptBufferDesc;
typedef BCryptBufferDesc* PNCryptBufferDesc;

//
// NCrypt handles
//

typedef ULONG_PTR NCRYPT_HANDLE;
typedef ULONG_PTR NCRYPT_PROV_HANDLE;
typedef ULONG_PTR NCRYPT_KEY_HANDLE;
typedef ULONG_PTR NCRYPT_HASH_HANDLE;
typedef ULONG_PTR NCRYPT_SECRET_HANDLE;



//
// Functions used to manage persisted keys.
//
__checkReturn
SECURITY_STATUS
WINAPI
NCryptOpenStorageProvider(
    __out   NCRYPT_PROV_HANDLE *phProvider,
    __in_opt LPCWSTR pszProviderName,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptOpenStorageProviderFn)(
    __out   NCRYPT_PROV_HANDLE *phProvider,
    __in_opt LPCWSTR pszProviderName,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT


// AlgOperations flags for use with NCryptEnumAlgorithms()
#define NCRYPT_CIPHER_OPERATION                 BCRYPT_CIPHER_OPERATION
#define NCRYPT_HASH_OPERATION                   BCRYPT_HASH_OPERATION
#define NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION  BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION
#define NCRYPT_SECRET_AGREEMENT_OPERATION       BCRYPT_SECRET_AGREEMENT_OPERATION
#define NCRYPT_SIGNATURE_OPERATION              BCRYPT_SIGNATURE_OPERATION
#define NCRYPT_RNG_OPERATION                    BCRYPT_RNG_OPERATION


__checkReturn
SECURITY_STATUS
WINAPI
NCryptEnumAlgorithms(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    DWORD   dwAlgOperations,
    __out   DWORD * pdwAlgCount,
    __deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptEnumAlgorithmsFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    DWORD   dwAlgClass,
    __out   DWORD * pdwAlgCount,
    __deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT


__checkReturn
SECURITY_STATUS
WINAPI
NCryptIsAlgSupported(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszAlgId,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptIsAlgSupportedFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszAlgId,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT



// NCryptEnumKeys flags
#define NCRYPT_MACHINE_KEY_FLAG         0x00000020


__checkReturn
SECURITY_STATUS
WINAPI
NCryptEnumKeys(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt LPCWSTR pszScope,
    __deref_out NCryptKeyName **ppKeyName,
    __inout PVOID * ppEnumState,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptEnumKeysFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt LPCWSTR pszScope,
    __deref_out NCryptKeyName **ppKeyName,
    __inout PVOID * ppEnumState,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT


__checkReturn
SECURITY_STATUS
WINAPI
NCryptEnumStorageProviders(
    __out   DWORD * pdwProviderCount,
    __deref_out_ecount(*pdwProviderCount) NCryptProviderName **ppProviderList,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptEnumStorageProvidersFn)(
    __out   DWORD * pdwProviderCount,
    __deref_out_ecount(*pdwProviderCount) NCryptProviderName **ppProviderList,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT


SECURITY_STATUS
WINAPI
NCryptFreeBuffer(
    __deref PVOID   pvInput);


// @@BEGIN_DDKSPLIT

typedef SECURITY_STATUS
(WINAPI * NCryptFreeBufferFn)(
    __deref PVOID   pvInput);

// @@END_DDKSPLIT


// NCryptOpenKey flags
#define NCRYPT_MACHINE_KEY_FLAG         0x00000020
#define NCRYPT_SILENT_FLAG              0x00000040

__checkReturn
SECURITY_STATUS
WINAPI
NCryptOpenKey(
    __inout NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszKeyName,
    __in_opt DWORD  dwLegacyKeySpec,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptOpenKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszKeyName,
    __in_opt DWORD  dwLegacyKeySpec,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT



// NCryptCreatePersistedKey flags
#define NCRYPT_MACHINE_KEY_FLAG         0x00000020
#define NCRYPT_OVERWRITE_KEY_FLAG       0x00000080

__checkReturn
SECURITY_STATUS
WINAPI
NCryptCreatePersistedKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszAlgId,
    __in_opt LPCWSTR pszKeyName,
    __in    DWORD   dwLegacyKeySpec,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptCreatePersistedKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszAlgId,
    __in_opt LPCWSTR pszKeyName,
    __in    DWORD   dwLegacyKeySpec,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT



// Standard property names.
#define NCRYPT_NAME_PROPERTY                    L"Name"
#define NCRYPT_UNIQUE_NAME_PROPERTY             L"Unique Name"
#define NCRYPT_ALGORITHM_PROPERTY               L"Algorithm Name"
#define NCRYPT_LENGTH_PROPERTY                  L"Length"
#define NCRYPT_LENGTHS_PROPERTY                 L"Lengths"
#define NCRYPT_BLOCK_LENGTH_PROPERTY            L"Block Length"
#define NCRYPT_UI_POLICY_PROPERTY               L"UI Policy"
#define NCRYPT_EXPORT_POLICY_PROPERTY           L"Export Policy"
#define NCRYPT_WINDOW_HANDLE_PROPERTY           L"HWND Handle"
#define NCRYPT_USE_CONTEXT_PROPERTY             L"Use Context"
#define NCRYPT_IMPL_TYPE_PROPERTY               L"Impl Type"
#define NCRYPT_KEY_USAGE_PROPERTY               L"Key Usage"
#define NCRYPT_KEY_TYPE_PROPERTY                L"Key Type"
#define NCRYPT_VERSION_PROPERTY                 L"Version"
#define NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY  L"Security Descr Support"
#define NCRYPT_SECURITY_DESCR_PROPERTY          L"Security Descr"
#define NCRYPT_USE_COUNT_ENABLED_PROPERTY       L"Enabled Use Count"
#define NCRYPT_USE_COUNT_PROPERTY               L"Use Count"
#define NCRYPT_LAST_MODIFIED_PROPERTY           L"Modified"
#define NCRYPT_MAX_NAME_LENGTH_PROPERTY         L"Max Name Length"
#define NCRYPT_ALGORITHM_GROUP_PROPERTY         L"Algorithm Group"
#define NCRYPT_DH_PARAMETERS_PROPERTY           BCRYPT_DH_PARAMETERS
#define NCRYPT_PROVIDER_HANDLE_PROPERTY         L"Provider Handle"
#define NCRYPT_PIN_PROPERTY                     L"SmartCardPin"
#define NCRYPT_READER_PROPERTY                  L"SmartCardReader"
#define NCRYPT_SMARTCARD_GUID_PROPERTY          L"SmartCardGuid"
#define NCRYPT_CERTIFICATE_PROPERTY             L"SmartCardKeyCertificate"
#define NCRYPT_PIN_PROMPT_PROPERTY              L"SmartCardPinPrompt"
#define NCRYPT_USER_CERTSTORE_PROPERTY          L"SmartCardUserCertStore"
#define NCRYPT_ROOT_CERTSTORE_PROPERTY          L"SmartcardRootCertStore"
#define NCRYPT_SECURE_PIN_PROPERTY              L"SmartCardSecurePin"
#define NCRYPT_ASSOCIATED_ECDH_KEY              L"SmartCardAssociatedECDHKey"
#define NCRYPT_SCARD_PIN_ID                     L"SmartCardPinId"
#define NCRYPT_SCARD_PIN_INFO                   L"SmartCardPinInfo"

// Maximum length of property name (in characters)
#define NCRYPT_MAX_PROPERTY_NAME        64

// Maximum length of property data (in bytes)
#define NCRYPT_MAX_PROPERTY_DATA        0x100000

// NCRYPT_EXPORT_POLICY_PROPERTY property flags.
#define NCRYPT_ALLOW_EXPORT_FLAG                0x00000001
#define NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG      0x00000002
#define NCRYPT_ALLOW_ARCHIVING_FLAG             0x00000004
#define NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG   0x00000008

// NCRYPT_IMPL_TYPE_PROPERTY property flags.
#define NCRYPT_IMPL_HARDWARE_FLAG               0x00000001
#define NCRYPT_IMPL_SOFTWARE_FLAG               0x00000002
#define NCRYPT_IMPL_REMOVABLE_FLAG              0x00000008
#define NCRYPT_IMPL_HARDWARE_RNG_FLAG           0x00000010

// NCRYPT_KEY_USAGE_PROPERTY property flags.
#define NCRYPT_ALLOW_DECRYPT_FLAG               0x00000001
#define NCRYPT_ALLOW_SIGNING_FLAG               0x00000002
#define NCRYPT_ALLOW_KEY_AGREEMENT_FLAG         0x00000004
#define NCRYPT_ALLOW_ALL_USAGES                 0x00ffffff

// NCRYPT_UI_POLICY_PROPERTY property flags and structure
#define NCRYPT_UI_PROTECT_KEY_FLAG              0x00000001
#define NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG    0x00000002

typedef struct __NCRYPT_UI_POLICY_BLOB
{
    DWORD   dwVersion;
    DWORD   dwFlags;
    DWORD   cbCreationTitle;
    DWORD   cbFriendlyName;
    DWORD   cbDescription;
    // creation title string
    // friendly name string
    // description string
} NCRYPT_UI_POLICY_BLOB;


// NCryptGetProperty flags
#define NCRYPT_PERSIST_ONLY_FLAG        0x40000000

__checkReturn
SECURITY_STATUS
WINAPI
NCryptGetProperty(
    __in    NCRYPT_HANDLE hObject,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptGetProviderPropertyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptGetKeyPropertyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT


// NCryptSetProperty flags
#define NCRYPT_PERSIST_FLAG             0x80000000
#define NCRYPT_PERSIST_ONLY_FLAG        0x40000000

__checkReturn
SECURITY_STATUS
WINAPI
NCryptSetProperty(
    __in    NCRYPT_HANDLE hObject,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptSetProviderPropertyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags);

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptSetKeyPropertyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT

#define     NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG   0x00000200

__checkReturn
SECURITY_STATUS
WINAPI
NCryptFinalizeKey(
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptFinalizeKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT


__checkReturn
SECURITY_STATUS
WINAPI
NCryptEncrypt(
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount_opt(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in_opt    VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptEncryptFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount_opt(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in_opt    VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT


__checkReturn
SECURITY_STATUS
WINAPI
NCryptDecrypt(
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount_opt(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in_opt    VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptDecryptFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount_opt(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in_opt    VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT



#define NCRYPT_PKCS7_ENVELOPE_BLOB      L"PKCS7_ENVELOPE"
#define NCRYPT_PKCS8_PRIVATE_KEY_BLOB   L"PKCS8_PRIVATEKEY"
#define NCRYPT_OPAQUETRANSPORT_BLOB     L"OpaqueTransport"

#define NCRYPT_MACHINE_KEY_FLAG         0x00000020
#define NCRYPT_DO_NOT_FINALIZE_FLAG     0x00000400
#define NCRYPT_EXPORT_LEGACY_FLAG       0x00000800

__checkReturn
SECURITY_STATUS
WINAPI
NCryptImportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hImportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in_bcount(cbData) PBYTE pbData,
    __in    DWORD   cbData,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptImportKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hImportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in_bcount(cbData) PBYTE pbData,
    __in    DWORD   cbData,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT


__checkReturn
SECURITY_STATUS
WINAPI
NCryptExportKey(
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt NCRYPT_KEY_HANDLE hExportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptExportKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt NCRYPT_KEY_HANDLE hExportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT


__checkReturn
SECURITY_STATUS
WINAPI
NCryptSignHash(
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __out_bcount_part_opt(cbSignature, *pcbResult) PBYTE pbSignature,
    __in    DWORD   cbSignature,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptSignHashFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __out_bcount_part_opt(cbSignature, *pcbResult) PBYTE pbSignature,
    __in    DWORD   cbSignature,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT


__checkReturn
SECURITY_STATUS
WINAPI
NCryptVerifySignature(
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __in_bcount(cbSignature) PBYTE pbSignature,
    __in    DWORD   cbSignature,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptVerifySignatureFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __in_bcount(cbSignature) PBYTE pbSignature,
    __in    DWORD   cbSignature,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT



SECURITY_STATUS
WINAPI
NCryptDeleteKey(
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT

typedef SECURITY_STATUS
(WINAPI * NCryptDeleteKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT



SECURITY_STATUS
WINAPI
NCryptFreeObject(
    __in    NCRYPT_HANDLE hObject);


// @@BEGIN_DDKSPLIT

typedef SECURITY_STATUS
(WINAPI * NCryptFreeProviderFn)(
    __in    NCRYPT_PROV_HANDLE hProvider);

typedef SECURITY_STATUS
(WINAPI * NCryptFreeKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey);

typedef SECURITY_STATUS
(WINAPI * NCryptFreeSecretFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_SECRET_HANDLE hSharedSecret);

// @@END_DDKSPLIT

BOOL
WINAPI
NCryptIsKeyHandle(
    __in    NCRYPT_KEY_HANDLE hKey);

__checkReturn
SECURITY_STATUS
WINAPI
NCryptTranslateHandle(
    __out_opt NCRYPT_PROV_HANDLE *phProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    HCRYPTPROV hLegacyProv,
    __in_opt HCRYPTKEY hLegacyKey,
    __in_opt DWORD  dwLegacyKeySpec,
    __in    DWORD   dwFlags);



// @@BEGIN_DDKSPLIT

typedef SECURITY_STATUS
(WINAPI * NCryptPromptUserFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszOperation,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT



// NCryptNotifyChangeKey flags
#define NCRYPT_REGISTER_NOTIFY_FLAG     0x00000001
#define NCRYPT_UNREGISTER_NOTIFY_FLAG   0x00000002
#define NCRYPT_MACHINE_KEY_FLAG         0x00000020

__checkReturn
SECURITY_STATUS
WINAPI
NCryptNotifyChangeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout HANDLE *phEvent,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptNotifyChangeKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout HANDLE *phEvent,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT

__checkReturn
SECURITY_STATUS
WINAPI
NCryptSecretAgreement(
    __in    NCRYPT_KEY_HANDLE hPrivKey,
    __in    NCRYPT_KEY_HANDLE hPubKey,
    __out   NCRYPT_SECRET_HANDLE *phAgreedSecret,
    __in    DWORD   dwFlags);


// @@BEGIN_DDKSPLIT
__checkReturn
typedef SECURITY_STATUS
(WINAPI * NCryptSecretAgreementFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hPrivKey,
    __in    NCRYPT_KEY_HANDLE hPubKey,
    __out   NCRYPT_SECRET_HANDLE *phAgreedSecret,
    __in    DWORD   dwFlags);

// @@END_DDKSPLIT

__checkReturn
SECURITY_STATUS
WINAPI
NCryptDeriveKey(
    __in        NCRYPT_SECRET_HANDLE hSharedSecret,
    __in        LPCWSTR              pwszKDF,
    __in_opt    NCryptBufferDesc     *pParameterList,
    __out_bcount_part_opt(cbDerivedKey, *pcbResult) PBYTE pbDerivedKey,
    __in        DWORD                cbDerivedKey,
    __out       DWORD                *pcbResult,
    __in        ULONG                dwFlags);


// @@BEGIN_DDKSPLIT

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptDeriveKeyFn)(
    __in        NCRYPT_PROV_HANDLE   hProvider,
    __in        NCRYPT_SECRET_HANDLE hSharedSecret,
    __in        LPCWSTR              pwszKDF,
    __in_opt    NCryptBufferDesc     *pParameterList,
    __out_bcount_part_opt(cbDerivedKey, *pcbResult) PBYTE pbDerivedKey,
    __in        DWORD                cbDerivedKey,
    __out       DWORD                *pcbResult,
    __in        ULONG                dwFlags);

// @@END_DDKSPLIT


#define NCRYPT_KEY_STORAGE_INTERFACE_VERSION BCRYPT_MAKE_INTERFACE_VERSION(1,0)


// @@BEGIN_DDKSPLIT

typedef struct _NCRYPT_KEY_STORAGE_FUNCTION_TABLE
{
    BCRYPT_INTERFACE_VERSION        Version;
    NCryptOpenStorageProviderFn     OpenProvider;
    NCryptOpenKeyFn                 OpenKey;
    NCryptCreatePersistedKeyFn      CreatePersistedKey;
    NCryptGetProviderPropertyFn     GetProviderProperty;
    NCryptGetKeyPropertyFn          GetKeyProperty;
    NCryptSetProviderPropertyFn     SetProviderProperty;
    NCryptSetKeyPropertyFn          SetKeyProperty;
    NCryptFinalizeKeyFn             FinalizeKey;
    NCryptDeleteKeyFn               DeleteKey;
    NCryptFreeProviderFn            FreeProvider;
    NCryptFreeKeyFn                 FreeKey;
    NCryptFreeBufferFn              FreeBuffer;
    NCryptEncryptFn                 Encrypt;
    NCryptDecryptFn                 Decrypt;
    NCryptIsAlgSupportedFn          IsAlgSupported;
    NCryptEnumAlgorithmsFn          EnumAlgorithms;
    NCryptEnumKeysFn                EnumKeys;
    NCryptImportKeyFn               ImportKey;
    NCryptExportKeyFn               ExportKey;
    NCryptSignHashFn                SignHash;
    NCryptVerifySignatureFn         VerifySignature;
    NCryptPromptUserFn              PromptUser;
    NCryptNotifyChangeKeyFn         NotifyChangeKey;
    NCryptSecretAgreementFn         SecretAgreement;
    NCryptDeriveKeyFn               DeriveKey;
    NCryptFreeSecretFn              FreeSecret;
} NCRYPT_KEY_STORAGE_FUNCTION_TABLE;

__checkReturn
NTSTATUS
WINAPI
GetKeyStorageInterface(
    __in   LPCWSTR  pszProviderName,
    __out  NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
    __in   DWORD    dwFlags);

typedef __checkReturn NTSTATUS
(WINAPI * GetKeyStorageInterfaceFn)(
    __in    LPCWSTR pszProviderName,
    __out   NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
    __in    ULONG dwFlags);

// @@END_DDKSPLIT

// @@BEGIN_DDKSPLIT
//
// Provider Registration Functions
//

__checkReturn
NTSTATUS
WINAPI
BCryptRegisterProvider(
    __in LPCWSTR pszProvider,
    __in ULONG dwFlags,
    __in PCRYPT_PROVIDER_REG pReg);

__checkReturn
NTSTATUS
WINAPI
BCryptUnregisterProvider(
    __in LPCWSTR pszProvider);

// @@END_DDKSPLIT

// @@BEGIN_DDKSPLIT
__checkReturn
NTSTATUS
WINAPI
BCryptAddContextFunctionProvider(
    __in ULONG dwTable,
    __in LPCWSTR pszContext,
    __in ULONG dwInterface,
    __in LPCWSTR pszFunction,
    __in LPCWSTR pszProvider,
    __in ULONG dwPosition);

__checkReturn
NTSTATUS
WINAPI
BCryptRemoveContextFunctionProvider(
    __in ULONG dwTable,
    __in LPCWSTR pszContext,
    __in ULONG dwInterface,
    __in LPCWSTR pszFunction,
    __in LPCWSTR pszProvider);

// @@END_DDKSPLIT


#ifdef __cplusplus
}       // Balance extern "C" above
#endif
