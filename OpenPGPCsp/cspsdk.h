/*++

Copyright (C) Microsoft Corporation, 2000

Module Name:

       cspdk

Abstract:

       This header file contains the definitions and references that every CSP
       needs to know.

Author:

       Doug Barlow (dbarlow) 1/27/2000

--*/

#ifndef _CSPDK_H_
#define _CSPDK_H_
#ifdef __cplusplus
extern   "C"  {
#endif

#define CRYPT_PROVSTRUC_VERSION_V3                     3
#define CRYPT_MAX_PROVIDER_ID                           999
#define CRYPT_SIG_RESOURCE_VERSION   0x00000100
#define CRYPT_EXTERNAL_SIGNATURE_LENGTH       136
#define CRYPT_SIG_RESOURCE_NUMBER               0x29A
#define CRYPT_SIG_RESOURCE               TEXT("#666")
#define CRYPT_MAC_RESOURCE_NUMBER               0x29B
#define CRYPT_MAC_RESOURCE               TEXT("#667")

// Exponentiation Offload Reg Location
#define EXPO_OFFLOAD_REG_VALUE "ExpoOffload"
#define EXPO_OFFLOAD_FUNC_NAME "OffloadModExpo"

typedef   struct  _OFFLOAD_PRIVATE_KEY
{
       DWORD  dwVersion;                       
       DWORD  cbPrime1;                         
       DWORD  cbPrime2;                         
       PBYTE  pbPrime1;                          // "p"
       PBYTE  pbPrime2;                          // "q"
}  OFFLOAD_PRIVATE_KEY, *POFFLOAD_PRIVATE_KEY;

#define CUR_OFFLOAD_VERSION                         1

//
// Callback prototypes
//

typedef   BOOL  (WINAPI  *CRYPT_VERIFY_IMAGE)(LPCWSTR szImage,  CONST  BYTE *pbSigData);
typedef   void  (WINAPI *CRYPT_RETURN_HWND)(HWND *phWnd);


//
// Structures for CSPs
//

typedef   struct  _VTableProvStruc  {
       DWORD                                Version;
       CRYPT_VERIFY_IMAGE   FuncVerifyImage;
       CRYPT_RETURN_HWND         FuncReturnhWnd;
       DWORD                                dwProvType;
       BYTE                               *pbContextInfo;
       DWORD                                cbContextInfo;
       LPSTR                                pszProvName;
}  VTableProvStruc,           *PVTableProvStruc;


typedef   struct  {
       DWORD dwVersion;
       DWORD dwCrcOffset;
       BYTE rgbSignature[88];    // 1024-bit key, plus 2 DWORDs of padding.
}  InFileSignatureResource;


//
// ===========================================================================
// CSP Entry points.
// ===========================================================================
//




/*
 -   CPDuplicateHash
 -
 *   Purpose:
 *                               Duplicates the state of a hash and returns a handle to it.
 *                               This is an optional entry.   Typically it only occurs in
 *                               SChannel related CSPs.
 *
 *   Parameters:
 *                             IN           hUID                     -   Handle to a CSP
 *                             IN           hHash                   -   Handle to a hash
 *                             IN           pdwReserved       -   Reserved
 *                             IN           dwFlags               -   Flags
 *                             IN           phHash                 -   Handle to the new hash
 *
 *   Returns:
 */

EXTERN_C   BOOL   WINAPI
CPDuplicateHash(
        IN     HCRYPTPROV  hProv,
        IN     HCRYPTHASH  hHash,
        IN    LPDWORD pdwReserved,
        IN    DWORD  dwFlags,
        OUT   HCRYPTHASH  *phHash);


/*
 -   CPDuplicateKey
 -
 *   Purpose:
 *                               Duplicates the state of a key and returns a handle to it.
 *                               This is an optional entry.   Typically it only occurs in
 *                               SChannel related CSPs.
 *
 *   Parameters:
 *                             IN           hUID                     -   Handle to a CSP
 *                             IN           hKey                     -   Handle to a key
 *                             IN           pdwReserved       -   Reserved
 *                             IN           dwFlags               -   Flags
 *                             IN           phKey                   -   Handle to the new key
 *
 *   Returns:
 */

EXTERN_C   BOOL   WINAPI
CPDuplicateKey(
        IN     HCRYPTPROV  hProv,
        IN     HCRYPTKEY   hKey,
        IN    LPDWORD pdwReserved,
        IN    DWORD  dwFlags,
        OUT   HCRYPTKEY  *phKey);

#define PP_USER_CERTSTORE       42
#define PP_SMARTCARD_READER     43
#define PP_SMARTCARD_GUID       45
#define PP_ROOT_CERTSTORE       46

#define PP_PIN_PROMPT_STRING      44
#define PP_SECURE_KEYEXCHANGE_PIN 47
#define PP_SECURE_SIGNATURE_PIN   48

#ifdef __cplusplus
}
#endif
#endif // _CSPDK_H_
