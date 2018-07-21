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

#pragma once

class Card;

#define OPENPGP_KEY_SIGNATURE 0
#define OPENPGP_KEY_CONFIDENTIALITY 1
#define OPENPGP_KEY_AUTHENTICATION 2
#define OPENPGPKEYMAX 3


#define OPENPGP_USER_SIGNATURE_PIN 1
#define OPENPGP_USER_PIN 2
#define OPENPGP_ADMIN_PIN 3

#define OPENPGP_USER_PIN_SIGNATURE_ID 0x81
#define OPENPGP_USER_PIN_ID 0x82
#define OPENPGP_ADMIN_PIN_ID 0x83

typedef struct _OPENPGP_AID
{
	BYTE					AidRid[5];
	BYTE					AidApplication[1];
	BYTE					AidVersion[2];
	BYTE					AidManufacturer[2];
	BYTE					AidSerialNumber[4];
	BYTE					AidRFU[2];
} OPENPGP_AID;


typedef enum _OPENPGP_FILE_ID 
{
	OpenPGPFingerprint,
	OpenPGPStatus,
	OpenPGPDir,
	OpenPGPStatusPW1,
	OpenPGPApplicationIdentifier,
	OpenPGPLogin,
	OpenPGPName,
	OpenPGPLanguage,
	OpenPGPSex,
	OpenPGPUrl,
	OpenPGPHistoricalBytes,
	OpenPGPCertificate,
	OpenPGPExtendedCap,
	OpenPGPAlgoAttributesSignature,
	OpenPGPAlgoAttributesDecryption,
	OpenPGPAlgoAttributesAuthentication,
	OpenPGPPUK,
	OpenPGPSecureMessaging,
	OpenPGPSecureMessagingCryptographicCheksum,
	OpenPGPSecureMessagingCryptogram,
	OpenPGPIdentifier,
} OPENPGP_FILE_ID ;

#pragma pack(push,1)
typedef struct _OPENPGP_ALGORITHM_ATTRIBUTE
{
	BYTE bAlgoId;
	unsigned short wModulusLengthInBit;
	unsigned short wExponentLengthInBit;
	BYTE bFormat;
} OPENPGP_ALGORITHM_ATTRIBUTE, *POPENPGP_ALGORITHM_ATTRIBUTE;
#pragma pack(pop)

typedef struct _OPENPGP_KEY_INFO
{
	BYTE    bKeyTag;
	BYTE    bDateTimeTag;
	BYTE    bSignatureTag;
	ALG_ID  aiKeyAlg;
} OPENPGP_KEY_INFO, *POPENPGP_KEY_INFO;

OPENPGP_KEY_INFO OpenPGPKeys[];

class OpenPGPCardv2: public Card
{
public:
	
	static Card* CreateContext(SCARDCONTEXT hContext, SCARDHANDLE hScard, BOOL fAllowUI, OPENPGP_AID Aid);
	virtual BOOL LocateContainer(__in_opt PCSTR szContainer, __out PDWORD pdwId);
	virtual BOOL GetContainerName(__in DWORD dwKeyId, __out_ecount(MAX_CONTAINER_NAME) PSTR szContainer);
	virtual BOOL GetPublicKey(__in DWORD dwKeyId, _Out_writes_bytes_to_opt_(*pdwSize, *pdwSize) PBYTE* ppbPubKey, __out PDWORD pdwSize);
	virtual BOOL GetKeySpec(__in DWORD dwKeyId, __out PDWORD pdwKeySpec);
	virtual DWORD GetMaxContainer() {return OPENPGPKEYMAX;}
	virtual BOOL GetCertificate(__in DWORD dwKeyId, _Out_writes_bytes_to_opt_(*pdwSize, *pdwSize) PBYTE pbData, __out PDWORD pdwSize);
	virtual BOOL SignData(__in DWORD dwKeyId,__in PCWSTR szAlgorithm, __in PBYTE pbHashValue, __in DWORD cbHashValue,
					_Out_writes_bytes_to_(*pdwSigLen, *pdwSigLen) BYTE *pbSignature,
					_Inout_  DWORD *pdwSigLen);
	virtual BOOL Decrypt(__in DWORD dwKeyId,
					 __in PBYTE pbEncryptedData, __in DWORD cbEncryptedData,
					_Out_writes_bytes_to_(*pcbDecryptedData, *pcbDecryptedData) BYTE *pbDecryptedData,
					_Inout_  DWORD *pcbDecryptedData);
	virtual BOOL GetPIN(__in DWORD dwKeyId, __in DWORD dwOperationId, __out PDWORD dwPinId);
	virtual BOOL AuthenticatePIN(__in DWORD dwPinId,__in PSTR szPin, __out PDWORD pdwRemainingAttempt);
	virtual BOOL Deauthenticate(__in DWORD dwPinId);
	virtual DWORD Reinit();
	virtual BOOL GenerateKey(__in ALG_ID Algid, __in DWORD dwKeyId, __in DWORD dwBitLen);
	virtual BOOL GetKeyIdForNewKey(__in ALG_ID Algid, __in_opt HWND hWndParent, __out PDWORD dwKeyId);
	virtual BOOL AskForPin(__in HWND hWndParent, __in PWSTR szPinPROMPT, __in DWORD dwPinId, __out_ecount(MAX_PIN_SIZE) PSTR szPin);
	virtual BOOL SaveCertificate(__in DWORD dwKey, __in_bcount(dwSize) PBYTE pbData, __in DWORD dwSize, __in DWORD dwKeySpec);
	virtual BOOL RemoveKey(__in DWORD dwKey);
	virtual BOOL SaveKey(__in DWORD dwKey, __in ALG_ID Algid, __in_bcount(dwKeySize) PBYTE pBlob, __in DWORD dwKeySize);
	virtual BOOL SetContainerName(PSTR szContainer, DWORD dwKeyId);
	virtual BOOL GetKeyLength(__out PDWORD pdwDefaultLen, __out PDWORD pdwMinLen, __out PDWORD pdwMaxLen);
protected:
	BOOL CheckForAlias(PCSTR szContainer, __out PDWORD dwKeyId);
	BOOL RemoveAlias(DWORD dwKeyId);
	BOOL SignHashWithAuthenticationKey(__in DWORD dwAlgIndex, __in PBYTE pbHashData, __in DWORD cbHashData, 
					_Out_writes_bytes_to_(*pdwSigLen, *pdwSigLen) BYTE *pbSignature,
					_Inout_  DWORD       *pdwSigLen, __in BOOL fNoHashOid);
	BOOL SignHashWithSignatureKey(__in DWORD dwAlgIndex, __in PBYTE pbHashData, __in DWORD cbHashData, 
					_Out_writes_bytes_to_(*pdwSigLen, *pdwSigLen) BYTE *pbSignature,
					_Inout_  DWORD       *pdwSigLen);
	BOOL DecryptOperation(__in PBYTE pbEncryptedData, __in DWORD cbEncryptedData,
					_Out_writes_bytes_to_(*pcbDecryptedData, *pcbDecryptedData) BYTE *pbDecryptedData,
					_Inout_  DWORD *pcbDecryptedData);
	DWORD CreateKey(DWORD dwKeyId, DWORD dwBitLen);
	DWORD SetKeyAlgorithmAttributes(__in DWORD dwKey,
								__out POPENPGP_ALGORITHM_ATTRIBUTE pAttributes);
	DWORD CreateGenerationDateTime(__out PDWORD pdwSecondsSince1970);
	DWORD UpdateGenerationDateTime(__in DWORD dwKey,
							   __in DWORD dwSecondsSince1970);
	DWORD CreateFingerPrint(__in DWORD dwKey, 
						__in DWORD dwSecondsSince1970,
						__inout BYTE pbFingerPrint[20],
						__in PBYTE pbModulusInLittleEndian, __in DWORD dwModulusSizeInBytes,
						__in DWORD dwExponent);
	DWORD UpdateFingerPrint(__in DWORD dwKey, 
						__inout BYTE pbFingerPrint[20]);
	DWORD ImportKey(DWORD dwKey, PBYTE pBlob, DWORD dwKeySize);
	OpenPGPCardv2():Card() {}
	DWORD ReadDO(__in OPENPGP_FILE_ID File,
					__out_bcount(*pdwResponseSize) PBYTE* ppbResponse, __out PDWORD pdwResponseSize);
	DWORD WriteDO(__in OPENPGP_FILE_ID File,
					__in PBYTE pbData, __in DWORD dwSize);
	virtual DWORD CheckCapabilities(__in_bcount(dwCardCapabilitiesSize) PBYTE pbCardCapabilities, DWORD dwCardCapabilitiesSize,
							__in_bcount(dwExtendedCapabilitiesSize) PBYTE pbExtendedCapabilities, DWORD dwExtendedCapabilitiesSize);
	virtual BOOL IsKeyCompatibleWithAlgId(__in DWORD dwKeyId, __in ALG_ID algId);
	virtual ALG_ID GetAlgIdFromKeyId(__in DWORD dwKeyId);
	DWORD Create();
	OPENPGP_AID				Aid;
	BOOL m_fExtentedLeLcFields;
	BOOL m_fSupportCommandChaining;
	ALG_ID m_aiSecureMessagingAlg;
	DWORD m_dwMaxChallengeLength;
	DWORD m_dwMaxCertificateLength;
	DWORD m_dwMaxResponseLength;
	BOOL m_fSupportAlgorithmAttributes;
	BYTE m_bFingerPrint[60];
	BOOL m_fHasKey[OPENPGPKEYMAX];
	BOOL m_AllowUI;
private:
	static OpenPGPCardv2* AllocateCard() { return new OpenPGPCardv2();}
};