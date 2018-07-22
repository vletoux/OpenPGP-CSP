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

#include "stdafx.h"

#pragma once


OPENPGP_KEY_INFO OpenPGPKeys[] = 
{
	{0xB6, 0xCE, 0xC7, CALG_RSA_SIGN}, // signature
	{0xB8, 0xCF, 0xC8, CALG_RSA_KEYX}, // confidentiality
	{0xA4, 0xD0, 0xC9, CALG_RSA_SIGN}  // authentication
};

//TCHAR szAliasName[OPENPGPKEYMAX][MAX_CONTAINER_NAME];
//TCHAR szAliasFor[OPENPGPKEYMAX][MAX_CONTAINER_NAME];

typedef struct _OPENPGP_FILE
{
	OPENPGP_FILE_ID File;
	DWORD dwTag;
	DWORD dwTlv;
} OPENPGP_FILE, *POPENPGP_FILE;


OPENPGP_FILE OpenPGPFiles[] =
{
	{OpenPGPFingerprint, 0x6E, 0xC5},
	{OpenPGPStatus, 0xC4, 0},
	{OpenPGPStatusPW1, 0xC4, 0},
	{OpenPGPApplicationIdentifier, 0x4F, 0},
	{OpenPGPLogin, 0x5E, 0},
	{OpenPGPName, 0x65, 0x5B},
	{OpenPGPLanguage, 0x65, 0x5F2D},
	{OpenPGPSex, 0x65, 0x5F35},
	{OpenPGPUrl, 0x5F50, 0},
	{OpenPGPHistoricalBytes, 0x5F52, 0},
	{OpenPGPCertificate, 0x7F21, 0},
	{OpenPGPExtendedCap, 0x6E, 0xC0},
	{OpenPGPAlgoAttributesSignature, 0x6E, 0xC1},
	{OpenPGPAlgoAttributesDecryption, 0x6E, 0xC2},
	{OpenPGPAlgoAttributesAuthentication, 0x6E, 0xC3 },
	{OpenPGPPUK, 0xD3, 0 },
	{OpenPGPSecureMessaging, 0xF4, 0 },
	{OpenPGPSecureMessagingCryptographicCheksum, 0xD2, 0 },
	{OpenPGPSecureMessagingCryptogram, 0xD1, 0 },
	{OpenPGPIdentifier, 0x4F, 0},
};

typedef struct _OPENPGP_SUPPORTED_SIGNATURE_ALGORITHM
{
	ALG_ID aiHashAlg;
	DWORD  dwHashSize;
	PBYTE pbEncodedOid;
	DWORD dwEncodedOidSize;
	PWSTR szAlgId;
} OPENPGP_SUPPORTED_SIGNATURE_ALGORITHM, *POPENPGP_SUPPORTED_SIGNATURE_ALGORITHM;

BYTE dwSHA1EncodedOid[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
	0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
BYTE dwSHA256EncodedOid[] = {0x30, 0x31, 0x30, 0x0D,0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
	0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
BYTE dwSHA384EncodedOid[] = {0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
	0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
BYTE dwSHA512EncodedOid[] = {0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
	0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

#define OPENPGP_NO_OID 0xFFFFFFFF
OPENPGP_SUPPORTED_SIGNATURE_ALGORITHM SignatureAlgorithm[] = 
{
	{CALG_SHA1,20, 
	dwSHA1EncodedOid,
	ARRAYSIZE(dwSHA1EncodedOid), BCRYPT_SHA1_ALGORITHM},
	//SHA256
	{CALG_SHA_256,32,
	dwSHA256EncodedOid,
	ARRAYSIZE(dwSHA256EncodedOid), BCRYPT_SHA256_ALGORITHM},
	//SHA384
	{CALG_SHA_384,48,
	dwSHA384EncodedOid,
	ARRAYSIZE(dwSHA384EncodedOid), BCRYPT_SHA384_ALGORITHM},
	//SHA512
	{CALG_SHA_512,64,
	dwSHA512EncodedOid,
	ARRAYSIZE(dwSHA512EncodedOid), BCRYPT_SHA512_ALGORITHM},
};

DWORD dwSignatureAlgorithmCount = ARRAYSIZE(SignatureAlgorithm);



DWORD getTlvSize(__in PBYTE pbPointer, __in PDWORD pdwOffset)
{
	DWORD dwSize;
	switch(*pbPointer)
	{
	case 0x81:
		*pdwOffset+=2;
		dwSize = pbPointer[1];
		break;
	case 0x82:
		*pdwOffset+=3;
		dwSize = pbPointer[1] * 0x100 + pbPointer[2];
		break;
	default:
		dwSize = *pbPointer;
		*pdwOffset+=1;
		break;
	}
	return dwSize;
}

/** used to parse tlv data returned when reading the public certificate */
BOOL find_tlv(__in PBYTE pbData, __in  DWORD dwTlvSearched, __in DWORD dwTotalSize, __out PBYTE *pbDataOut, __out PDWORD pdwSize)
{
	DWORD dwOffset = 0, dwTlv ;
	DWORD dwSize;
	BOOL bFound = FALSE;
	*pbDataOut = NULL;
	*pdwSize = 0;
	while (dwOffset < dwTotalSize)
	{
		// check the tlv
		// if it & with 0x1F => tlv of 2 bytes.
		// else 1 byte
		dwTlv = 0;
		if ((pbData[dwOffset] & 0x1F) == 0x1F)
		{
			dwTlv = pbData[dwOffset] * 0x100;
			dwOffset++;
		}
		dwTlv += pbData[dwOffset];
		dwOffset++;


		if (dwTlv == dwTlvSearched)
		{
			// size sequence
			dwSize = getTlvSize(pbData + dwOffset,&dwOffset);
			if (pdwSize)
			{
				*pdwSize = dwSize;
			}
			*pbDataOut = pbData + dwOffset;
			return TRUE;
		}
		else
		{
			dwSize = getTlvSize(pbData + dwOffset,&dwOffset);
			if (dwTlv != 0x73)
			{
				dwOffset += dwSize;
			}
		}
	}
	return FALSE;
}


/** send the select open pgp application apdu */
DWORD OpenPGPCardv2::Reinit()
{
	BYTE pbCmd[] = {0x00, 
		0xA4,
		0x04,
		0x00,
		0x06,
		0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
		0x00
	};

	return SendCommand(pbCmd, sizeof(pbCmd));
}

Card* OpenPGPCardv2::CreateContext(SCARDCONTEXT hContext, SCARDHANDLE hScard, BOOL fAllowUI, OPENPGP_AID Aid)
{
	DWORD dwReturn = SCARD_F_UNKNOWN_ERROR;
	OpenPGPCardv2* returnedCard = NULL;
	__try
	{
		returnedCard = AllocateCard();
		if (returnedCard == NULL)
		{
			Trace(TRACE_LEVEL_ERROR, L"No memory");
			__leave;
		}
		returnedCard->hContext = hContext;
		returnedCard->hScard = hScard;
		returnedCard->m_AllowUI = fAllowUI;
		returnedCard->Aid = Aid;
		dwReturn = returnedCard->Create();
		if (dwReturn)
		{
			delete returnedCard;
			returnedCard = NULL;
			Trace(TRACE_LEVEL_ERROR, L"Create 0x%08X", dwReturn);
			__leave;
		}
		dwReturn = 0;
	}
	__finally
	{
		SetLastError(dwReturn);
	}
	return returnedCard;
}

BOOL find_compacttlv(__in PBYTE pbData, __in DWORD dwTotalSize, __in BYTE bCode, __out PBYTE *pbDataOut, __out PDWORD pdwSize)
{
	DWORD dwOffset = 0;
	DWORD dwSize;
	*pbDataOut = NULL;
	*pdwSize = 0;
	while (dwOffset < dwTotalSize)
	{
		if (bCode * 0x10 == (pbData[dwOffset] & 0xF0) )
		{
			dwSize = (pbData[dwOffset] & 0x0F);
			if (pdwSize)
			{
				*pdwSize = dwSize;
			}
			dwOffset++;
			// size sequence

			*pbDataOut = pbData + dwOffset;
			return TRUE;
		}
		else
		{

			dwSize = (pbData[dwOffset] & 0x0F);
			dwOffset += dwSize + 1;
		}
	}
	return FALSE;
}

DWORD OpenPGPCardv2::Create()
{
	DWORD dwReturn = SCARD_F_UNKNOWN_ERROR;
	PBYTE					pbCapabilities = NULL, pbCardCapabilities = NULL;
	PBYTE					pbExtendedCapabilities = NULL;
	PBYTE					pbApplicationIdentifier = NULL;
	PBYTE					pbFingerPrint = NULL;
	DWORD					dwCapabilitiesSize=0, 
		dwCardCapabilitiesSize=0,
		dwApplicationIdentifierSize = 0,
		dwExtendedCapabilitiesSize=0,
		dwFingerPrintSize=0;
	DWORD dwI, dwJ;
	__try
	{
		m_fExtentedLeLcFields = 0;
		Trace(TRACE_LEVEL_INFO, L"specification version %d.%d", Aid.AidVersion[0], Aid.AidVersion[1]);
		dwReturn = ReadDO(OpenPGPHistoricalBytes, &pbCapabilities, &dwCapabilitiesSize);
		if (dwReturn)
		{
			__leave;
		}
		if (!find_compacttlv(pbCapabilities + 1, dwCapabilitiesSize - 1, 7, &pbCardCapabilities, &dwCardCapabilitiesSize))
		{
			Trace(TRACE_LEVEL_ERROR, L"tlv not found");
			dwReturn = SCARD_E_UNEXPECTED;
			__leave;
		}
		if (dwCardCapabilitiesSize != 3)
		{
			Trace(TRACE_LEVEL_ERROR, L"dwCardCapabilitiesSize = %02X", dwCardCapabilitiesSize);
			dwReturn = SCARD_E_UNEXPECTED;
			__leave;
		}
		dwReturn = ReadDO(OpenPGPExtendedCap, &pbExtendedCapabilities, &dwExtendedCapabilitiesSize);
		if (dwReturn)
		{
			__leave;
		}

		dwReturn = CheckCapabilities(pbCardCapabilities, dwCardCapabilitiesSize, pbExtendedCapabilities, dwExtendedCapabilitiesSize);
		if (dwReturn)
		{
			__leave;
		}

		dwReturn = ReadDO(OpenPGPFingerprint, &pbFingerPrint, &dwFingerPrintSize);
		if (dwReturn)
		{
			__leave;
		}
		if (dwFingerPrintSize != 60)
		{
			Trace(TRACE_LEVEL_ERROR, L"dwFingerPrintSize = %02X", dwFingerPrintSize);
			dwReturn = SCARD_E_UNEXPECTED;
			__leave;
		}
		memcpy(m_bFingerPrint, pbFingerPrint, 60);
		for(dwJ = 0; dwJ < OPENPGPKEYMAX; dwJ++)
		{
			m_fHasKey[dwJ] = FALSE;
			for( dwI = dwJ * 20; dwI < dwJ * 20 + 20; dwI++)
			{
				if (pbFingerPrint[dwI] != 0)
				{
					m_fHasKey[dwJ] = TRUE;
					break;
				}
			}
		}
		dwReturn = ERROR_SUCCESS;
	}
	__finally
	{
		if (pbApplicationIdentifier)
			free(pbApplicationIdentifier);
		if (pbCapabilities)
			free(pbCapabilities);
		if (pbExtendedCapabilities)
			free(pbExtendedCapabilities);
		if (pbFingerPrint)
			free(pbFingerPrint);
	}
	return dwReturn;
}

DWORD OpenPGPCardv2::CheckCapabilities(__in_bcount(dwCardCapabilitiesSize) PBYTE pbCardCapabilities, DWORD dwCardCapabilitiesSize,
									   __in_bcount(dwExtendedCapabilitiesSize) PBYTE pbExtendedCapabilities, DWORD dwExtendedCapabilitiesSize)
{
	m_fSupportAlgorithmAttributes = ((pbCardCapabilities[0] & (1<<3))?TRUE:FALSE);
	m_fExtentedLeLcFields = ((pbCardCapabilities[2] & 0x40)?TRUE:FALSE);

	m_fSupportCommandChaining = ((pbCardCapabilities[2] & 0x80)?TRUE:FALSE);
	if (pbExtendedCapabilities[0] & 0x80)
	{
		switch(pbExtendedCapabilities[1])
		{
		case 0:
			m_aiSecureMessagingAlg = CALG_3DES;
			break;
		case 1:
			m_aiSecureMessagingAlg = CALG_AES_128;
			break;
		}
		Trace(TRACE_LEVEL_VERBOSE, L"secure messaging supported with aiAlg = %d", m_aiSecureMessagingAlg);
	}
	else
	{
		m_aiSecureMessagingAlg = 0;
	}
	m_dwMaxChallengeLength = pbExtendedCapabilities[2] * 0x100 + pbExtendedCapabilities[3];
	m_dwMaxCertificateLength = pbExtendedCapabilities[4] * 0x100 + pbExtendedCapabilities[5];

	m_dwMaxResponseLength = pbExtendedCapabilities[8] * 0x100 + pbExtendedCapabilities[9];
	return ERROR_SUCCESS;
}
// read file
DWORD OpenPGPCardv2::ReadDO(__in OPENPGP_FILE_ID File,
							__out_bcount(*pdwResponseSize) PBYTE* ppbResponse, __out PDWORD pdwResponseSize)
{
	DWORD dwI;
	DWORD dwReturn = 0;
	BOOL fDirectoryFound = FALSE;
	BOOL fFileFound = FALSE;
	BYTE pbCmd[] = {0x00, 0xCA, 0x00, 0x00, 0x00, 0x00, 0x00};
	DWORD dwCmdSize = ARRAYSIZE(pbCmd);
	PBYTE pbData = NULL;
	__try
	{
		*pdwResponseSize = 0;
		for(dwI = 0; dwI < ARRAYSIZE(OpenPGPFiles); dwI++)
		{
			BOOL fMatch = FALSE;
			if (OpenPGPFiles[dwI].File == File)
			{
				fFileFound = TRUE;
				break;
			}
		}
		if (!fFileFound)
		{
			dwReturn = SCARD_E_FILE_NOT_FOUND;
			Trace(TRACE_LEVEL_ERROR, L"SCARD_E_FILE_NOT_FOUND %d",File);
			__leave;
		}
		pbCmd[2] = (BYTE) (OpenPGPFiles[dwI].dwTag / 0x100);
		pbCmd[3] = (BYTE) (OpenPGPFiles[dwI].dwTag % 0x100);

		dwReturn = GetData( pbCmd, dwCmdSize, &pbData, pdwResponseSize);
		if (dwReturn)
		{
			__leave;
		}
		if (OpenPGPFiles[dwI].dwTlv)
		{
			PBYTE pbPointer;
			//TraceDump(0,pbData,*pdwResponseSize);
			if (find_tlv(pbData, OpenPGPFiles[dwI].dwTlv, *pdwResponseSize, &pbPointer, pdwResponseSize))
			{
				*ppbResponse = (PBYTE) malloc(*pdwResponseSize);
				if (!*ppbResponse )
				{
					Trace(TRACE_LEVEL_ERROR, L"SCARD_E_NO_MEMORY");
					dwReturn = SCARD_E_NO_MEMORY;
					__leave;
				}
				memcpy(*ppbResponse, pbPointer, *pdwResponseSize);
			}
			else
			{
				dwReturn = SCARD_E_FILE_NOT_FOUND;
				Trace(TRACE_LEVEL_ERROR, L"SCARD_E_FILE_NOT_FOUND %d",File);
				__leave;
			}
		}
		else
		{
			*ppbResponse = pbData;
			// do not free the data !
			pbData = NULL;
		}
		// add to the cache
		dwReturn = 0;

	}
	__finally
	{
	}
	Trace(TRACE_LEVEL_VERBOSE, L"%d dwReturn = 0x%08X size = %d", File, dwReturn, *pdwResponseSize);
	return dwReturn;
}

DWORD OpenPGPCardv2::WriteDO(__in OPENPGP_FILE_ID File,
							 __in PBYTE pbData, __in DWORD dwSize)
{
	DWORD dwReturn = 0;
	BYTE pbCmd[5 + 256] = {0x00, 0xDA, 0x00, 0x00, 0x00};
	DWORD dwCmdSize = 0;
	PBYTE pbCmdExtended = NULL;
	DWORD dwI;
	BOOL fFileFound = FALSE;
	__try
	{
		if (dwSize > 0xFFFF)
		{
			dwReturn = SCARD_E_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_ERROR, L"dwSize %d",dwSize);
			__leave;
		}
		for(dwI = 0; dwI < ARRAYSIZE(OpenPGPFiles); dwI++)
		{
			BOOL fMatch = FALSE;
			if (OpenPGPFiles[dwI].File == File)
			{
				fFileFound = TRUE;
				break;
			}
		}
		if (!fFileFound)
		{
			dwReturn = SCARD_E_FILE_NOT_FOUND;
			Trace(TRACE_LEVEL_ERROR, L"SCARD_E_FILE_NOT_FOUND %d",File);
			__leave;
		}
		if (dwSize < 256)
		{
			if (OpenPGPFiles[dwI].dwTlv > 0)
			{
				pbCmd[2] = (BYTE) (OpenPGPFiles[dwI].dwTlv / 0x100);
				pbCmd[3] = (BYTE) (OpenPGPFiles[dwI].dwTlv % 0x100);
			}
			else
			{
				pbCmd[2] = (BYTE) (OpenPGPFiles[dwI].dwTag / 0x100);
				pbCmd[3] = (BYTE) (OpenPGPFiles[dwI].dwTag % 0x100);
			}
			pbCmd[4] = (BYTE) dwSize;
			if (dwSize)
			{
				memcpy(pbCmd + 5, pbData, dwSize);
			}
			dwCmdSize = dwSize + 5;
			dwReturn = SendCommand(pbCmd, dwCmdSize);
			if (dwReturn)
			{
				__leave;
			}
		}
		else
		{
			dwCmdSize = dwSize + 7;
			pbCmdExtended = (PBYTE) malloc(dwCmdSize);
			if (!pbCmdExtended)
			{
				Trace(TRACE_LEVEL_ERROR, L"SCARD_E_NO_MEMORY");
				dwReturn = SCARD_E_NO_MEMORY;
				__leave;
			}
			pbCmdExtended[0] = 0;
			pbCmdExtended[1] = 0xDA;
			if (OpenPGPFiles[dwI].dwTlv > 0)
			{
				pbCmdExtended[2] = (BYTE) (OpenPGPFiles[dwI].dwTlv / 0x100);
				pbCmdExtended[3] = (BYTE) (OpenPGPFiles[dwI].dwTlv % 0x100);
			}
			else
			{
				pbCmdExtended[2] = (BYTE) (OpenPGPFiles[dwI].dwTag / 0x100);
				pbCmdExtended[3] = (BYTE) (OpenPGPFiles[dwI].dwTag % 0x100);
			}
			pbCmdExtended[4] = 0;
			pbCmdExtended[5] = (BYTE)(dwSize / 0x100);
			pbCmdExtended[6] = (BYTE)(dwSize % 0x100);
			memcpy(pbCmdExtended + 7, pbData, dwSize);
			dwReturn = SendCommand(pbCmdExtended, dwCmdSize);
			if (dwReturn)
			{
				__leave;
			}
		}
	}
	__finally
	{
		if(pbCmdExtended)
			free(pbCmdExtended);
	}
	Trace(TRACE_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

BOOL OpenPGPCardv2::IsKeyCompatibleWithAlgId(__in DWORD dwKeyId, __in ALG_ID algId)
{
	return OpenPGPKeys[dwKeyId].aiKeyAlg == algId;
}

ALG_ID OpenPGPCardv2::GetAlgIdFromKeyId(__in DWORD dwKeyId)
{
	return OpenPGPKeys[dwKeyId].aiKeyAlg;
}

BOOL OpenPGPCardv2::LocateContainer(__in_opt PCSTR szContainer, __out PDWORD pdwId)
{
	*pdwId = INVALID_CONTAINER_ID;
	if (!szContainer)
	{
		// set default as authentication for smart card logon
		if (m_fHasKey[OPENPGP_KEY_AUTHENTICATION])
		{
			*pdwId = OPENPGP_KEY_AUTHENTICATION;
			return TRUE;
		}
		else if (m_fHasKey[OPENPGP_KEY_SIGNATURE])
		{
			*pdwId = OPENPGP_KEY_SIGNATURE;
			return TRUE;
		}
		else if (m_fHasKey[OPENPGP_KEY_CONFIDENTIALITY])
		{
			*pdwId = OPENPGP_KEY_CONFIDENTIALITY;
			return TRUE;
		}
		Trace(TRACE_LEVEL_ERROR, L"the card is empty");
		SetLastError(NTE_KEYSET_NOT_DEF);
		return FALSE;
	}
	if (CheckForAlias(szContainer, pdwId))
	{
		return TRUE;
	}
	for(DWORD dwI = 0; dwI < OPENPGPKEYMAX; dwI++)
	{
		if( m_fHasKey[dwI])
		{
			CHAR szKeyName[20 * 2 + 1];
			for(int i = 0; i < 20; i++)
			{
				sprintf_s(szKeyName + i * 2, 3, "%02X", m_bFingerPrint[dwI * 20 + i]);
			}
			if (strcmp(szKeyName, szContainer) == 0)
			{
				*pdwId = dwI;
				return TRUE;
			}
		}
	}
	Trace(TRACE_LEVEL_ERROR, L"the card doesn't contain the container %S", szContainer);
	SetLastError(NTE_KEYSET_NOT_DEF);
	return FALSE;
}

BOOL OpenPGPCardv2::GetContainerName(__in DWORD dwKeyId, __out_ecount(MAX_CONTAINER_NAME) PSTR szContainer)
{
	if (dwKeyId >= OPENPGPKEYMAX)
	{
		SetLastError(NTE_KEYSET_NOT_DEF);
		szContainer[0] = 0;
		return FALSE;
	}
	if (memcmp(m_bFingerPrint + dwKeyId * 20, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 20) == 0)
	{
		SetLastError(NTE_KEYSET_NOT_DEF);
		szContainer[0] = 0;
		return FALSE;
	}
	for(int i = 0; i < 20; i++)
	{
		sprintf_s(szContainer + i * 2, 3, "%02X", m_bFingerPrint[dwKeyId * 20 + i]);
	}
	return TRUE;
}


BOOL OpenPGPCardv2::GetPublicKey(__in DWORD dwKeyId, _Out_writes_bytes_to_opt_(*pdwSize, *pdwSize) PBYTE* ppbPubKey, __out PDWORD pdwSize)
{
	BOOL fReturn = FALSE;
	PBYTE pbData = NULL;
	DWORD dwResponseSize = 0, dwError;
	BYTE pbCmd[] = {0x00, 
		0x47, // GENERATE ASYMMETRIC KEY PAIR
		0x81, // Reading of actual public key template
		0x00, // P2 = 0
		0x00, 
		0x00,
		0x02,
		0x00,// key id
		0x00, // key length = 0
		0x00,
		0x00
	};
	DWORD dwCmdSize;
	DWORD dwTotalTlvSize, dwOffset;
	DWORD dwModulusSizeInBytes, dwExponentSize;
	PBYTE pbModulus;
	PBYTE pbExponent;
	__try
	{
		Trace(TRACE_LEVEL_VERBOSE, L"Enter dwKey=%d",dwKeyId);
		if (dwKeyId >= OPENPGPKEYMAX)
		{
			dwError = NTE_KEYSET_NOT_DEF;
			Trace(TRACE_LEVEL_INFO, L"NTE_KEYSET_NOT_DEF %d", dwKeyId);
			__leave;
		}
		pbCmd[7] = OpenPGPKeys[dwKeyId].bKeyTag;
		dwCmdSize = 9;
		if (m_fExtentedLeLcFields)
		{
			pbCmd[dwCmdSize++] = 0;
			pbCmd[dwCmdSize++] = 0;
		}
		else
		{
			pbCmd[dwCmdSize++] = 0x0;
		}

		dwError = GetData(pbCmd, dwCmdSize, &pbData, &dwResponseSize);
		if (dwError)
		{
			__leave;
		}
		dwOffset = 2;
		dwTotalTlvSize = getTlvSize(pbData + 2,&dwOffset) + 2;
		if (!find_tlv(pbData + dwOffset,0x81,dwTotalTlvSize,&pbModulus,&dwModulusSizeInBytes))
		{
			dwError = SCARD_E_UNEXPECTED;
			Trace(TRACE_LEVEL_ERROR, L"SCARD_E_UNEXPECTED 0x81");
			__leave;
		}
		if (!find_tlv(pbData + dwOffset,0x82,dwTotalTlvSize, (PBYTE*)&pbExponent,&dwExponentSize))
		{
			dwError = SCARD_E_UNEXPECTED;
			Trace(TRACE_LEVEL_ERROR, L"SCARD_E_UNEXPECTED 0x81");
			__leave;
		}
		Trace(TRACE_LEVEL_INFO, L"dwModulusSize %d bits", dwModulusSizeInBytes * 8);
		*pdwSize = (DWORD) (sizeof(RSAPUBLICKEYBLOB) + dwModulusSizeInBytes - sizeof(DWORD));
		*ppbPubKey = (PBYTE) malloc(*pdwSize);
		if (!*ppbPubKey)
		{
			dwError = ERROR_OUTOFMEMORY;
			Trace(TRACE_LEVEL_ERROR, L"ERROR_OUTOFMEMORY");
			__leave;
		}
		DWORD dwExponent = pbExponent[0] * 0x1000000  + pbExponent[1] * 0x10000  + pbExponent[2] * 0x100 + pbExponent[3];

		PRSAPUBLICKEYBLOB pbBlob = (PRSAPUBLICKEYBLOB) *ppbPubKey;
		memset(pbBlob,0,*pdwSize);
		pbBlob->blobheader.bType = PUBLICKEYBLOB;
		pbBlob->blobheader.bVersion = CUR_BLOB_VERSION;
		pbBlob->blobheader.reserved = 0;
		pbBlob->blobheader.aiKeyAlg = GetAlgIdFromKeyId(dwKeyId);
		pbBlob->rsapubkey.magic = 0x31415352; //'RSA1';
		pbBlob->rsapubkey.bitlen = dwModulusSizeInBytes*8;
		pbBlob->rsapubkey.pubexp = dwExponent;
		for(DWORD dwI = 0; dwI < dwModulusSizeInBytes; dwI++)
		{
			pbBlob->modulus[dwI] = pbModulus[dwModulusSizeInBytes -1 - dwI];
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pbData)
			free(pbData);
	}
	Trace(TRACE_LEVEL_VERBOSE, L"dwError = 0x%08X",dwError);
	SetLastError(dwError);
	return fReturn;
}

BOOL OpenPGPCardv2::GetCertificate(__in DWORD dwKeyId, _Out_writes_bytes_to_opt_(*pdwSize, *pdwSize) PBYTE pbData, __out PDWORD pdwSize)
{
	BOOL fReturn = FALSE;
	DWORD dwError = ERROR_INTERNAL_ERROR;
	PBYTE pbCertificate = NULL;
	DWORD dwCertificateSize = 0;
	__try
	{
		Trace(TRACE_LEVEL_VERBOSE, L"Enter dwKey=%d",dwKeyId);
		if (dwKeyId >= OPENPGPKEYMAX)
		{
			dwError = NTE_KEYSET_NOT_DEF;
			Trace(TRACE_LEVEL_INFO, L"NTE_KEYSET_NOT_DEF %d", dwKeyId);
			__leave;
		}
		if (dwKeyId != OPENPGP_KEY_AUTHENTICATION)
		{
			dwError = NTE_NOT_FOUND;
			Trace(TRACE_LEVEL_INFO, L"No cert found");
			__leave;
		}
		dwError = ReadDO(OpenPGPCertificate, &pbCertificate, &dwCertificateSize);
		if (dwError)
		{
			__leave;
		}
		if (dwCertificateSize == 0)
		{
			dwError = NTE_NOT_FOUND;
			Trace(TRACE_LEVEL_INFO, L"cert empty");
			__leave;
		}
		if (*pdwSize < dwCertificateSize)
		{
			*pdwSize = dwCertificateSize;
			if (!pbData)
			{
				fReturn = TRUE;
				__leave;
			}
			dwError = ERROR_MORE_DATA;
			__leave;
		}
		if (!pbData)
		{
			*pdwSize = dwCertificateSize;
			fReturn = TRUE;
			__leave;
		}
		memcpy(pbData, pbCertificate, dwCertificateSize);
		fReturn = TRUE;
	}
	__finally
	{
		if (pbCertificate)
			free(pbCertificate);
	}
	Trace(TRACE_LEVEL_VERBOSE, L"dwError = 0x%08X",dwError);
	SetLastError(dwError);
	return fReturn;
}

BOOL OpenPGPCardv2::SignData(__in DWORD dwKeyId,__in PCWSTR szAlgorithm, __in PBYTE pbHashValue, __in DWORD cbHashValue,
							 _Out_writes_bytes_to_(*pdwSigLen, *pdwSigLen) BYTE *pbSignature,
							 _Inout_  DWORD *pdwSigLen)
{
	BOOL fReturn = FALSE;
	DWORD dwError = ERROR_INTERNAL_ERROR;
	DWORD dwAlgIndex = 0;
	BOOL fNoHashOid = FALSE;
	__try
	{
		Trace(TRACE_LEVEL_VERBOSE, L"Enter dwKey=%d alg=%s",dwKeyId, szAlgorithm);
		if (dwKeyId >= OPENPGPKEYMAX)
		{
			dwError = NTE_KEYSET_NOT_DEF;
			Trace(TRACE_LEVEL_INFO, L"NTE_KEYSET_NOT_DEF %d", dwKeyId);
			__leave;
		}
		if (szAlgorithm == NULL)
		{
			if (!(dwKeyId == OPENPGP_KEY_AUTHENTICATION))
			{
				dwError = NTE_NOT_SUPPORTED;
				Trace(TRACE_LEVEL_INFO, L"signing without OID is not supported for this key");
				__leave;
			} 
			fNoHashOid = TRUE;
		}
		else if (wcscmp(szAlgorithm, BCRYPT_SHA1_ALGORITHM) == 0)
		{
			dwAlgIndex = 0;
		}
		else if (wcscmp(szAlgorithm, BCRYPT_SHA256_ALGORITHM) == 0)
		{
			dwAlgIndex = 1;
		}
		else if (wcscmp(szAlgorithm, BCRYPT_SHA384_ALGORITHM) == 0)
		{
			dwAlgIndex = 2;
		}
		else if (wcscmp(szAlgorithm, BCRYPT_SHA512_ALGORITHM) == 0)
		{
			dwAlgIndex = 3;
		}
		else
		{
			dwError = NTE_NOT_SUPPORTED;
			Trace(TRACE_LEVEL_INFO, L"NTE_NOT_SUPPORTED Alg Id %s", szAlgorithm);
			__leave;
		}

		switch(dwKeyId)
		{
		case OPENPGP_KEY_SIGNATURE:
			fReturn = SignHashWithSignatureKey(dwAlgIndex, pbHashValue, cbHashValue, pbSignature, pdwSigLen);
			break;
		case OPENPGP_KEY_AUTHENTICATION:
			fReturn = SignHashWithAuthenticationKey(dwAlgIndex, pbHashValue, cbHashValue, pbSignature, pdwSigLen, fNoHashOid);
			break;
		default:
			dwError = NTE_NOT_SUPPORTED;
			Trace(TRACE_LEVEL_ERROR, L"NTE_NOT_SUPPORTED Key Id %d", dwKeyId);
			__leave;
		}
	}
	__finally
	{
	}
	if (!fReturn)
	{
		Trace(TRACE_LEVEL_VERBOSE, L"dwError = 0x%08X",dwError);
		SetLastError(dwError);
	}
	return fReturn;

}

BOOL OpenPGPCardv2::SignHashWithSignatureKey(__in DWORD dwAlgIndex, __in PBYTE pbHashData, __in DWORD cbHashData, 
											 _Out_writes_bytes_to_(*pdwSigLen, *pdwSigLen) BYTE *pbSignature,
											 _Inout_  DWORD       *pdwSigLen)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	DWORD dwCmdSize = 0, dwI;
	BYTE pbCmd[6 + 256 + 256] = {0x00, 
		0x2A,
		0x9E,
		0x9A,
		0x00,
		0x00,
	};
	PBYTE pbSignedData = NULL;
	DWORD dwSignedData = 0;
	__try
	{
		dwCmdSize = 5;
		if (m_fExtentedLeLcFields)
		{
			dwCmdSize++;
		}
		pbCmd[dwCmdSize++] = (BYTE) (SignatureAlgorithm[dwAlgIndex].dwEncodedOidSize + cbHashData);
		memcpy(pbCmd + dwCmdSize , SignatureAlgorithm[dwAlgIndex].pbEncodedOid,SignatureAlgorithm[dwAlgIndex].dwEncodedOidSize);
		dwCmdSize += SignatureAlgorithm[dwAlgIndex].dwEncodedOidSize;
		memcpy(pbCmd + dwCmdSize, pbHashData,cbHashData);
		dwCmdSize += cbHashData;


		if (m_fExtentedLeLcFields)
		{
			pbCmd[dwCmdSize++] = 0;
			pbCmd[dwCmdSize++] = 0;
		}
		else
		{
			pbCmd[dwCmdSize++] = 0;
		}
		dwError = GetData(pbCmd, dwCmdSize, &pbSignedData, &dwSignedData);
		if (dwError)
		{
			__leave;
		}
		if (dwSignedData > *pdwSigLen)
		{
			dwError = ERROR_MORE_DATA;
			*pdwSigLen = dwSignedData;
			Trace(TRACE_LEVEL_ERROR, L"Invalid buffer length");
			__leave;
		}
		*pdwSigLen = dwSignedData;
		// revert the BYTES
		for(dwI = 0 ; dwI < dwSignedData ; dwI++)
		{
			pbSignature[dwI] = pbSignedData[dwSignedData -1 -dwI];
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pbSignedData)
			free(pbSignedData);
	}
	Trace(TRACE_LEVEL_VERBOSE, L"dwError = 0x%08X",dwError);
	SetLastError(dwError);
	return fReturn;
}

BOOL OpenPGPCardv2::SignHashWithAuthenticationKey(__in DWORD dwAlgIndex, __in PBYTE pbHashData, __in DWORD cbHashData, 
												  _Out_writes_bytes_to_(*pdwSigLen, *pdwSigLen) BYTE *pbSignature,
												  _Inout_  DWORD       *pdwSigLen, __in BOOL fNoHashOid)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	DWORD dwCmdSize = 0, dwI;
	BYTE pbCmd[6 + 256 + 256] = {0x00, 
		0x88,
		0x00,
		0x00,
		0x00,
		0x00,
	};
	PBYTE pbSignedData = NULL;
	DWORD dwSignedData = 0;
	__try
	{
		dwCmdSize = 5;
		if (m_fExtentedLeLcFields)
		{
			dwCmdSize++;
		}
		if (fNoHashOid)
		{
			pbCmd[dwCmdSize++] = (BYTE) (cbHashData);
		}
		else
		{
			pbCmd[dwCmdSize++] = (BYTE) (SignatureAlgorithm[dwAlgIndex].dwEncodedOidSize + cbHashData);
			memcpy(pbCmd + dwCmdSize , SignatureAlgorithm[dwAlgIndex].pbEncodedOid,SignatureAlgorithm[dwAlgIndex].dwEncodedOidSize);
			dwCmdSize += SignatureAlgorithm[dwAlgIndex].dwEncodedOidSize;
		}
		memcpy(pbCmd + dwCmdSize, pbHashData,cbHashData);
		dwCmdSize += cbHashData;

		if (m_fExtentedLeLcFields)
		{
			pbCmd[dwCmdSize++] = 0;
			pbCmd[dwCmdSize++] = 0;
		}
		else
		{
			pbCmd[dwCmdSize++] = 0;
		}
		dwError = GetData(pbCmd, dwCmdSize, &pbSignedData, &dwSignedData);
		if (dwError)
		{
			__leave;
		}
		if (*pdwSigLen < dwSignedData)
		{
			dwError = NTE_BUFFER_TOO_SMALL;
			Trace(TRACE_LEVEL_ERROR, L"buffer too small");
			*pdwSigLen = dwSignedData;
			__leave;
		}
		*pdwSigLen = dwSignedData;
		// revert the BYTES
		for(dwI = 0 ; dwI < dwSignedData ; dwI++)
		{
			pbSignature[dwI] = pbSignedData[dwSignedData -1 -dwI];
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pbSignedData)
			free(pbSignedData);
	}
	Trace(TRACE_LEVEL_VERBOSE, L"dwError = 0x%08X",dwError);
	SetLastError(dwError);
	return fReturn;
}

BOOL OpenPGPCardv2::Decrypt(__in DWORD dwKeyId,
					 __in PBYTE pbEncryptedData, __in DWORD cbEncryptedData,
					_Out_writes_bytes_to_(*pcbDecryptedData, *pcbDecryptedData) BYTE *pbDecryptedData,
					_Inout_  DWORD *pcbDecryptedData)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	__try
	{
		Trace(TRACE_LEVEL_VERBOSE, L"Enter dwContainer=%d",dwKeyId);
		if (dwKeyId != OPENPGP_KEY_CONFIDENTIALITY)
		{
			dwError = NTE_NOT_SUPPORTED;
			Trace(TRACE_LEVEL_ERROR, L"NTE_NOT_SUPPORTED Key Id %d", dwKeyId);
			__leave;
		}
		if (!DecryptOperation(pbEncryptedData, cbEncryptedData, pbDecryptedData, pcbDecryptedData))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"NTE_NOT_SUPPORTED Key Id %d", dwKeyId);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL OpenPGPCardv2::DecryptOperation(__in PBYTE pbEncryptedData, __in DWORD cbEncryptedData,
					_Out_writes_bytes_to_(*pcbDecryptedData, *pcbDecryptedData) BYTE *pbDecryptedData,
					_Inout_  DWORD *pcbDecryptedData)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	PBYTE pbTempDecryptedData = NULL;
	DWORD dwCmdSize = 0, dwResponseSize;
	BYTE pbCmd[6 + 256 + 256] = {0x00, 
		0x2A,
		0x80,
		0x86,
		0x00,
	};
	DWORD dwI;
	__try
	{
		// check the buffer size
		dwCmdSize = 5;
		if (m_fExtentedLeLcFields)
		{
			pbCmd[dwCmdSize++] = (BYTE)((cbEncryptedData +1) / 0x100);
			pbCmd[dwCmdSize++] = (BYTE)((cbEncryptedData +1) % 0x100);
		}
		else
		{
			pbCmd[dwCmdSize++] = (BYTE)((cbEncryptedData +1) % 0x100);
		}
		pbCmd[dwCmdSize++] = 0;
		//little endian => big endian
		for(dwI = 0; dwI < cbEncryptedData; dwI++)
		{
			pbCmd[dwCmdSize + dwI] = pbEncryptedData[cbEncryptedData -1 -dwI];
		}
		dwCmdSize += cbEncryptedData;
		if (m_fExtentedLeLcFields)
		{
			pbCmd[dwCmdSize++] = 0;
			pbCmd[dwCmdSize++] = 0;
		}
		else
		{
			pbCmd[dwCmdSize++] = 0;
		}
		dwError = GetData(pbCmd, dwCmdSize, &pbTempDecryptedData, &dwResponseSize);
		if (dwError)
		{
			__leave;
		}
		if ( *pcbDecryptedData < dwResponseSize)
		{
			dwError = SCARD_E_INSUFFICIENT_BUFFER;
			Trace(TRACE_LEVEL_ERROR, L"SCARD_E_INSUFFICIENT_BUFFER %d expected = %d", *pcbDecryptedData , dwResponseSize);
			__leave;
		}
		for(dwI = 0; dwI < dwResponseSize; dwI++)
		{
			pbDecryptedData[dwI] = pbTempDecryptedData[dwI];
		}
		*pcbDecryptedData = dwResponseSize;
		fReturn = TRUE;
	}
	__finally
	{
		if (pbTempDecryptedData)
		{
			SecureZeroMemory(pbTempDecryptedData, dwResponseSize);
			free(pbTempDecryptedData);
		}
	}
	Trace(TRACE_LEVEL_VERBOSE, L"dwError = 0x%08X",dwError);
	SetLastError(dwError);
	return fReturn;
}

BOOL OpenPGPCardv2::GetPIN(__in DWORD dwKeyId, __in DWORD dwOperationId, __out PDWORD dwPinId)
{
	switch(dwOperationId)
	{
	case PIN_OPERATION_SIGN:
	case PIN_OPERATION_DECRYPT:
		if (dwKeyId == OPENPGP_KEY_SIGNATURE)
			*dwPinId = OPENPGP_USER_SIGNATURE_PIN;
		else
			*dwPinId = OPENPGP_USER_PIN;
		return TRUE;
	case PIN_OPERATION_CREATE:
	case PIN_OPERATION_SAVE_CERT:
	case PIN_OPERATION_DELETE:
		*dwPinId = OPENPGP_ADMIN_PIN;
		return TRUE;
	case PIN_OPERATION_SET_KEYEXCHANGE_PIN:
	case PIN_OPERATION_SET_SIGNATURE_PIN:
		if (dwKeyId == OPENPGP_KEY_SIGNATURE)
			*dwPinId = OPENPGP_USER_SIGNATURE_PIN;
		else
			*dwPinId = OPENPGP_USER_PIN;
		return TRUE;
	case PIN_OPERATION_SET_ADMIN_PIN:
		*dwPinId = OPENPGP_ADMIN_PIN;
		return TRUE;
	default:
		SetLastError(NTE_NOT_SUPPORTED);
		*dwPinId = 0;
		return FALSE;
	}
}

BOOL OpenPGPCardv2::AuthenticatePIN(__in DWORD dwPinId,__in PSTR szPin, __out PDWORD pdwRemainingAttempt)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0, dwMaxPinSize, dwSize;
	PBYTE pbResponse = NULL;
	// 256 because the size of the PIN must fit in a Byte
	BYTE pbCmd[256 + 5] = {0x00, 
		0x20,
		0x00,
		0x82,
		0x00 
	};
	__try
	{
		Trace(TRACE_LEVEL_VERBOSE, L"Enter PinId=%d",dwPinId);
		if (strlen(szPin) > 256)
		{
			Trace(TRACE_LEVEL_ERROR, L"Error PIN too long");
			dwError = SCARD_E_INVALID_CHV;
			__leave;
		}
		if ((dwPinId == OPENPGP_USER_PIN || OPENPGP_USER_SIGNATURE_PIN) && strlen(szPin) < 6)
		{
			Trace(TRACE_LEVEL_ERROR, L"Error PIN too short");
			dwError = SCARD_E_INVALID_CHV;
			__leave;
		}
		if (dwPinId == OPENPGP_ADMIN_PIN && strlen(szPin) < 8)
		{
			Trace(TRACE_LEVEL_ERROR, L"Error PIN too short");
			dwError = SCARD_E_INVALID_CHV;
			__leave;
		}
		if (dwPinId == OPENPGP_USER_PIN)
			pbCmd[3] = (BYTE) OPENPGP_USER_PIN_ID;
		else if (dwPinId == OPENPGP_USER_SIGNATURE_PIN)
			pbCmd[3] = (BYTE) OPENPGP_USER_PIN_SIGNATURE_ID;
		else if (dwPinId == OPENPGP_ADMIN_PIN)
			pbCmd[3] = (BYTE) OPENPGP_ADMIN_PIN_ID;
		// check in status DO
		dwError = ReadDO(OpenPGPStatus, &pbResponse, &dwSize);
		if (dwError)
		{
			__leave;
		}
		switch(dwPinId)
		{
		case OPENPGP_USER_PIN:
		case OPENPGP_USER_SIGNATURE_PIN:
			dwMaxPinSize = pbResponse[1];
			break;
		case OPENPGP_ADMIN_PIN:
			dwMaxPinSize = pbResponse[3];
			break;
		default:
			dwError = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (strlen(szPin) > dwMaxPinSize)
		{
			Trace(TRACE_LEVEL_ERROR, L"pin too long");
			dwError = SCARD_W_WRONG_CHV;
			__leave;
		}
		BYTE cbPin = (BYTE) strlen(szPin);
		pbCmd[4] = (BYTE) cbPin;
		memcpy(pbCmd + 5, szPin, cbPin);
		dwError = SendCommand(pbCmd, 5 + cbPin);
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR, L"Authentication failed");
			__leave;
		}
		Trace(TRACE_LEVEL_VERBOSE, L"Authentication successfull");
		fReturn = TRUE;
	}
	__finally
	{
		SecureZeroMemory(pbCmd, ARRAYSIZE(pbCmd));
		if (pbResponse)
			free(pbResponse);
	}
	Trace(TRACE_LEVEL_VERBOSE, L"dwError = 0x%08X",dwError);
	SetLastError(dwError);
	return fReturn;
}

BOOL OpenPGPCardv2::Deauthenticate(__in DWORD dwPinId) 
{
	SetLastError(ERROR_CALL_NOT_IMPLEMENTED); 
	return FALSE;
}

BOOL OpenPGPCardv2::GenerateKey(__in ALG_ID Algid, __in DWORD dwKeyId, __in DWORD dwBitLen)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	__try
	{
		if (!IsKeyCompatibleWithAlgId(dwKeyId, Algid))
		{
			dwError = NTE_BAD_ALGID;
			Trace(TRACE_LEVEL_ERROR, L"NTE_BAD_ALGID");
			__leave;
		}
		dwError = CreateKey(dwKeyId, dwBitLen);
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR, L"CreateKey failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
	}
	Trace(TRACE_LEVEL_VERBOSE, L"dwError = 0x%08X",dwError);
	SetLastError(dwError);
	return fReturn;
}

BOOL OpenPGPCardv2::GetKeyIdForNewKey(__in ALG_ID Algid, __in_opt HWND hWndParent, __out PDWORD pdwKeyId)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	SelectOpenPGPv2KeyDialog dialog(Algid);
	if (!m_AllowUI)
	{
		Trace(TRACE_LEVEL_ERROR, L"Silent context");
		SetLastError(NTE_SILENT_CONTEXT);
		return FALSE;
	}
	Trace(TRACE_LEVEL_INFO, L"showing SelectOpenPGPv2KeyDialog dialog");
	if (dialog.Show(hWndParent) != IDOK)
	{
		Trace(TRACE_LEVEL_INFO, L"SelectOpenPGPv2KeyDialog dialog cancelled");
		SetLastError(ERROR_CANCELLED);
		return FALSE;
	}
	Trace(TRACE_LEVEL_INFO, L"SelectOpenPGPv2KeyDialog dialog ended with key id %d", dialog.m_dwKeyId);
	*pdwKeyId = dialog.m_dwKeyId;
	return TRUE;
}

BOOL OpenPGPCardv2::AskForPin(__in HWND hWndParent, __in PWSTR szPinPROMPT, __in DWORD dwPinId, __out_ecount(MAX_PIN_SIZE) PSTR szPin)
{
	DWORD dwResourceId = IDD_PIN;
	if (dwPinId == OPENPGP_ADMIN_PIN)
	{
		dwResourceId = IDD_PINADMIN;
	}
	else if (dwPinId == OPENPGP_USER_SIGNATURE_PIN)
	{
		dwResourceId = IDD_PIN_SIGNATURE;
	}
	PINDialog dialog(szPinPROMPT, dwResourceId);
	if (dialog.Show(hWndParent) != IDOK)
	{
		Trace(TRACE_LEVEL_INFO, L"Pin dialog cancelled");
		SetLastError(ERROR_CANCELLED);
		return FALSE;
	}
	dialog.GetPIN(szPin);
	return TRUE;
}

DWORD OpenPGPCardv2::CreateKey(DWORD dwKey, DWORD dwBitLen)
{
	DWORD dwReturn;
	PBYTE pbData = NULL;
	DWORD dwResponseSize = 0, dwCmdSize;
	OPENPGP_ALGORITHM_ATTRIBUTE Attributes;
	DWORD dwSecondsSince1970;
	PBYTE pbModulus, pbExponent;
	DWORD dwModulusSizeInBytes, dwExponent, dwExponentSize;
	BYTE pbCmd[] = {0x00, 
		0x47,
		0x80,
		0x00,
		0x00,
		0x00,
		0x02,
		0x00,
		0x00,
		0x00,
		0x00
	};
	DWORD dwTotalTlvSize, dwOffset;
	BYTE pbFingerPrint[20];
	__try
	{
		Trace(TRACE_LEVEL_VERBOSE, L"Enter dwKey=%d",dwKey);
		if (dwKey >= OPENPGPKEYMAX)
		{
			dwReturn = SCARD_E_NO_KEY_CONTAINER;
			Trace(TRACE_LEVEL_INFO, L"SCARD_E_NO_KEY_CONTAINER %d", dwKey);
			__leave;
		}

		// key len
		Attributes.wModulusLengthInBit = (unsigned short)dwBitLen;
		Attributes.wExponentLengthInBit = 4 * 8;
		Attributes.bAlgoId = 1;
		Attributes.bFormat = 0;
		dwReturn = SetKeyAlgorithmAttributes(dwKey, &Attributes);
		if (dwReturn)
		{
			__leave;
		}

		pbCmd[7] = OpenPGPKeys[dwKey].bKeyTag;
		dwCmdSize = 9;
		if (m_fExtentedLeLcFields)
		{
			pbCmd[dwCmdSize++] = 0;
			pbCmd[dwCmdSize++] = 0;
		}
		else
		{
			pbCmd[dwCmdSize++] = 0;
		}

		dwReturn = GetData(pbCmd, dwCmdSize, &pbData, &dwResponseSize);
		if (dwReturn)
		{
			__leave;
		}
		dwOffset = 2;
		dwTotalTlvSize = getTlvSize(pbData + 2,&dwOffset) + 2;
		if (!find_tlv(pbData + dwOffset,0x81,dwTotalTlvSize, &pbModulus,&dwModulusSizeInBytes))
		{
			dwReturn = SCARD_E_UNEXPECTED;
			Trace(TRACE_LEVEL_ERROR, L"SCARD_E_UNEXPECTED 0x81");
			__leave;
		}
		if (!find_tlv(pbData + dwOffset,0x82,dwTotalTlvSize, (PBYTE*)&pbExponent,&dwExponentSize))
		{
			dwReturn = SCARD_E_UNEXPECTED;
			Trace(TRACE_LEVEL_ERROR, L"SCARD_E_UNEXPECTED 0x82");
			__leave;
		}
		dwExponent = pbExponent[0] * 0x1000000  + pbExponent[1] * 0x10000  + pbExponent[2] * 0x100 + pbExponent[3];
		// save in the cache
		m_fHasKey[dwKey] = TRUE;
		dwReturn = CreateGenerationDateTime(&dwSecondsSince1970);
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = CreateFingerPrint(dwKey, dwSecondsSince1970, pbFingerPrint, pbModulus, dwModulusSizeInBytes, dwExponent);
		if (dwReturn)
		{
			__leave;
		}
		// avoid two key having the same fingerprint if generated too fast
		while (memcmp(pbFingerPrint, m_bFingerPrint, 20) == 0
			|| memcmp(pbFingerPrint, m_bFingerPrint + 20, 20) == 0
			|| memcmp(pbFingerPrint, m_bFingerPrint + 40, 20) == 0)
		{
			dwSecondsSince1970++;
			dwReturn = CreateFingerPrint(dwKey, dwSecondsSince1970, pbFingerPrint, pbModulus, dwModulusSizeInBytes, dwExponent);
			if (dwReturn)
			{
				__leave;
			}
		}
		dwReturn = UpdateGenerationDateTime(dwKey, dwSecondsSince1970);
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = UpdateFingerPrint(dwKey, pbFingerPrint);
		if (dwReturn)
		{
			__leave;
		}
		memcpy(m_bFingerPrint + 20 * dwKey, pbFingerPrint, 20);
	}
	__finally
	{
		if (pbData)
			free(pbData);
	}
	Trace(TRACE_LEVEL_VERBOSE, L"dwReturn = 0x%08X",dwReturn);
	return dwReturn;
}

DWORD OpenPGPCardv2::SetKeyAlgorithmAttributes(__in DWORD dwKey,
											   __out POPENPGP_ALGORITHM_ATTRIBUTE pAttributes)
{
	DWORD dwReturn;
	PSTR szAlgorithmAttributes = NULL;
	OPENPGP_ALGORITHM_ATTRIBUTE TempAttributes;
	WORD wTemp;
	OPENPGP_FILE_ID file;
	__try
	{
		Trace(TRACE_LEVEL_VERBOSE, L"Enter dwContainer=%d",dwKey);
		if (!m_fSupportAlgorithmAttributes) 
		{
			Trace(TRACE_LEVEL_VERBOSE, L"algorithm attributes not supported");
			dwReturn = ERROR_SUCCESS;
			__leave;
		}
		switch(dwKey)
		{
		case OPENPGP_KEY_SIGNATURE:
			file = OpenPGPAlgoAttributesSignature;
			break;
		case OPENPGP_KEY_AUTHENTICATION:
			file = OpenPGPAlgoAttributesAuthentication;
			break;
		case OPENPGP_KEY_CONFIDENTIALITY:
			file = OpenPGPAlgoAttributesDecryption;
			break;
		default:
			dwReturn = SCARD_E_NO_KEY_CONTAINER;
			Trace(TRACE_LEVEL_ERROR, L"SCARD_E_NO_KEY_CONTAINER %d", dwKey);
			__leave;
		}
		memcpy(&TempAttributes, pAttributes, sizeof(OPENPGP_ALGORITHM_ATTRIBUTE));
		wTemp = TempAttributes.wExponentLengthInBit;
		TempAttributes.wExponentLengthInBit = (wTemp % 0x100) * 0x100 + (wTemp / 0x100);
		wTemp = TempAttributes.wModulusLengthInBit;
		TempAttributes.wModulusLengthInBit = (wTemp % 0x100) * 0x100 + (wTemp / 0x100);

		dwReturn = WriteDO( file, (PBYTE) &TempAttributes, sizeof(OPENPGP_ALGORITHM_ATTRIBUTE));
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = ERROR_SUCCESS;
	}
	__finally
	{
	}
	Trace(TRACE_LEVEL_VERBOSE, L"dwReturn = 0x%08X for key = %d",dwReturn, dwKey);
	return dwReturn;
}

DWORD OpenPGPCardv2::CreateGenerationDateTime(__out PDWORD pdwSecondsSince1970)
{
	LARGE_INTEGER UnixZeroTime = {0}, WindowsTime;
	SYSTEMTIME WindowsSystemTime;
	FILETIME WindowsFileTime;
	UnixZeroTime.QuadPart = 116444736000000000I64; // january 1st 1970
	GetSystemTime(&WindowsSystemTime);
	SystemTimeToFileTime(&WindowsSystemTime, &WindowsFileTime);
	/* It is not recommended that you add and subtract values from the FILETIME
	structure to obtain relative times. Instead, you should copy the low- and high-order
	parts of the file time to a ULARGE_INTEGER  structure, perform 64-bit arithmetic
	on the QuadPart member, and copy the LowPart and HighPart  members into the 
	FILETIME structure.

	Do not cast a pointer to a FILETIME structure to either a ULARGE_INTEGER* 
	or __int64* value because it can cause alignment faults on 64-bit Windows.
	*/
	WindowsTime.HighPart = WindowsFileTime.dwHighDateTime;
	WindowsTime.LowPart = WindowsFileTime.dwLowDateTime;
	*pdwSecondsSince1970 = (DWORD)((WindowsTime.QuadPart - UnixZeroTime.QuadPart) / 10000000);
	return 0;
}



DWORD OpenPGPCardv2::UpdateGenerationDateTime(__in DWORD dwKey,
											  __in DWORD dwSecondsSince1970)
{
	DWORD dwReturn = 0;

	BYTE pbCommand[] = {0x00, 0xDA, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00};
	DWORD dwCommandSize = ARRAYSIZE(pbCommand);
	__try
	{


		pbCommand[3] = OpenPGPKeys[dwKey].bDateTimeTag;
		pbCommand[5] = (BYTE) (dwSecondsSince1970 / 0x1000000);
		pbCommand[6] = (BYTE) ((dwSecondsSince1970 % 0x1000000) / 0x10000);
		pbCommand[7] = (BYTE) ((dwSecondsSince1970 % 0x10000) / 0x100);
		pbCommand[8] = (BYTE) ((dwSecondsSince1970 % 0x100) / 0x1);
		dwReturn = SendCommand(pbCommand, dwCommandSize);
	}
	__finally
	{
	}
	Trace(TRACE_LEVEL_VERBOSE, L"dwReturn = 0x%08X for key = %d",dwReturn,dwKey);
	return dwReturn;
}

DWORD OpenPGPCardv2::CreateFingerPrint(__in DWORD dwKey, 
									   __in DWORD dwSecondsSince1970,
									   __inout BYTE pbFingerPrint[20],
									   __in PBYTE pbModulusInLittleEndian, __in DWORD dwModulusSizeInBytes,
									   __in DWORD dwExponent)
{
	// modulus in input are in big endian
	// rfc4880 12.2
	DWORD dwReturn = 0;
	PBYTE pbBuffer = NULL;
	DWORD dwBufferSize;
	DWORD dwOffset = 0;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	DWORD dwHashLen = 0x14;
	DWORD dwI;
	DWORD dwModulusSizeInBit;
	__try
	{
		dwModulusSizeInBit = dwModulusSizeInBytes * 8;
		dwBufferSize = dwModulusSizeInBytes + sizeof(DWORD) + 10  + 3;
		pbBuffer = (PBYTE) malloc(dwBufferSize);
		if (!pbBuffer)
		{
			dwReturn = SCARD_E_NO_MEMORY;
			Trace(TRACE_LEVEL_ERROR, L"SCARD_E_NO_MEMORY");
			__leave;
		}

		pbBuffer[dwOffset++] = 0x99;
		// -3 because of the header size
		pbBuffer[dwOffset++] = (BYTE) ((dwBufferSize-3) / 0x100);
		pbBuffer[dwOffset++] = (BYTE) ((dwBufferSize-3) % 0x100);
		// rfc4880 5.5.2
		// version
		pbBuffer[dwOffset++] = 4;
		// timestamp
		pbBuffer[dwOffset++] = (BYTE) (dwSecondsSince1970 / 0x1000000);
		pbBuffer[dwOffset++] = (BYTE) ((dwSecondsSince1970 % 0x1000000) / 0x10000);
		pbBuffer[dwOffset++] = (BYTE) ((dwSecondsSince1970 % 0x10000) / 0x100);
		pbBuffer[dwOffset++] = (BYTE) ((dwSecondsSince1970 % 0x100) / 0x1);
		// RSA
		pbBuffer[dwOffset++] = 1;
		// size of modulus
		pbBuffer[dwOffset++] = (BYTE) ((dwModulusSizeInBit % 0x10000) / 0x100);
		pbBuffer[dwOffset++] = (BYTE) ((dwModulusSizeInBit % 0x100) / 0x1);
		// little endian => big endian
		for(dwI = 0; dwI < dwModulusSizeInBytes; dwI++)
		{
			pbBuffer[dwOffset + dwI] = pbModulusInLittleEndian[dwModulusSizeInBytes - 1 - dwI];
		}
		// size of exponent
		pbBuffer[dwOffset++] = 0;
		pbBuffer[dwOffset++] = sizeof(DWORD);
		// exponent
		pbBuffer[dwOffset++] = (BYTE) (dwExponent / 0x1000000);
		pbBuffer[dwOffset++] = (BYTE) ((dwExponent % 0x1000000) / 0x10000);
		pbBuffer[dwOffset++] = (BYTE) ((dwExponent % 0x10000) / 0x100);
		pbBuffer[dwOffset++] = (BYTE) ((dwExponent % 0x100) / 0x1);

		// hash using SHA1
		if (!CryptAcquireContext(&hProv,  NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			dwReturn = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CryptAcquireContext 0x%08X", dwReturn);
			__leave;
		}
		if(!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) 
		{
			dwReturn = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CryptCreateHash 0x%08X", dwReturn);
			__leave;
		}
		if(!CryptHashData(hHash, pbBuffer, dwBufferSize, 0)) 
		{
			dwReturn = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CryptHashData 0x%08X", dwReturn);
			__leave;
		}
		if(!CryptGetHashParam(hHash, HP_HASHVAL, pbFingerPrint, &dwHashLen, 0)) {
			dwReturn = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CryptGetHashParam 0x%08X", dwReturn);
			__leave;
		}


	}
	__finally
	{
		if (pbBuffer)
			free(pbBuffer);
		if(hHash) 
			CryptDestroyHash(hHash);
		if(hProv) 
			CryptReleaseContext(hProv,0);

	}
	Trace(TRACE_LEVEL_VERBOSE, L"dwReturn = 0x%08X for key = %d",dwReturn, dwKey);
	return dwReturn;

}

DWORD OpenPGPCardv2::UpdateFingerPrint(__in DWORD dwKey, 
									   __inout BYTE pbFingerPrint[20])
{
	BYTE pbCommand[25] = {0x00, 0xDA, 0x00, 0x00, 0x14};
	DWORD dwCommandSize = ARRAYSIZE(pbCommand), dwReturn;
	__try
	{
		pbCommand[3] = OpenPGPKeys[dwKey].bSignatureTag;
		memcpy(pbCommand + 5, pbFingerPrint, 20);
		dwReturn = SendCommand(pbCommand, dwCommandSize);
	}
	__finally
	{
	}
	Trace(TRACE_LEVEL_VERBOSE, L"dwReturn = 0x%08X for key = %d",dwReturn,dwKey);
	return dwReturn;
}

BOOL OpenPGPCardv2::SaveCertificate(__in DWORD dwKeyId, __in_bcount(dwSize) PBYTE pbData, __in DWORD dwSize, __in DWORD dwKeySpec)
{
	if (dwKeyId >= OPENPGPKEYMAX)
	{
		SetLastError(NTE_KEYSET_NOT_DEF);
		return FALSE;
	}
	if (dwKeyId != OPENPGP_KEY_AUTHENTICATION)
	{
		SetLastError(NTE_NOT_SUPPORTED);
		return FALSE;
	}
	if (!IsKeyCompatibleWithAlgId(dwKeyId, CALG_RSA_SIGN))
	{
		SetLastError(NTE_NOT_SUPPORTED);
		return FALSE;
	}
	DWORD dwError = WriteDO(OpenPGPCertificate, pbData, dwSize);
	SetLastError(dwError);
	return (dwError == ERROR_SUCCESS);
}

DWORD BuildSingleTlv(__in PBYTE buffer, __in BYTE bTlv, __in DWORD dwTlvSize, __inout PDWORD pdwOffset)
{
	DWORD dwSize = 1;
	buffer[(*pdwOffset)++] = bTlv;
	// truncate if too long
	if (dwTlvSize > 0xFFFF) dwTlvSize = 0xFFFF;
	if (dwTlvSize < 0x7F)
	{
		buffer[(*pdwOffset)++] = (BYTE) dwTlvSize;
		dwSize++;
	}
	else if (dwTlvSize < 0xFF)
	{
		buffer[(*pdwOffset)++] = 0x81;
		buffer[(*pdwOffset)++] = (BYTE) dwTlvSize;
		dwSize+=2;
	}
	else
	{
		buffer[(*pdwOffset)++] = 0x82;
		buffer[(*pdwOffset)++] = (BYTE) (dwTlvSize / 0x100);
		buffer[(*pdwOffset)++] = (BYTE) (dwTlvSize % 0x100);
		dwSize+=3;
	}
	return dwSize;
}

DWORD BuildPrivateKeyTlv( __in PRSAPUBLICKEYBLOB pbPublicKeyBlob, 
						 __in DWORD dwKey, __in BYTE bFormat,
						 __out PBYTE * ppbTlv, __out PDWORD pdwTlvSize)
{
	// structure of the keyblob
	//BLOBHEADER blobheader;
	//RSAPUBKEY rsapubkey;
	//BYTE modulus[rsapubkey.bitlen/8];
	//BYTE prime1[rsapubkey.bitlen/16];
	//BYTE prime2[rsapubkey.bitlen/16];
	//BYTE exponent1[rsapubkey.bitlen/16];
	//BYTE exponent2[rsapubkey.bitlen/16];
	//BYTE coefficient[rsapubkey.bitlen/16];
	//BYTE privateExponent[rsapubkey.bitlen/8];
	DWORD dwReturn = 0;

	DWORD bitlen = pbPublicKeyBlob->rsapubkey.bitlen;
	PBYTE pbPublicKeyData = (PBYTE) &(pbPublicKeyBlob->modulus);
	// 7F48 len is < 7F so its encoded len is 1 bytes
	// 3 bytes max + length * 7 potential plv
	BYTE b7F48Header[(3 +1) * 7 + 3] = {0x7F, 0x48}; 
	BYTE b5F48Header[3 + 2] = {0x5F, 0x48};
	BYTE b4DHeader[3 + 1] = {0x4D};
	DWORD dwOffset = 0;
	DWORD dw7F48HeaderSize, dw5F48HeaderSize, dw4DHeaderSize;
	DWORD dwKeyDataSize, dwExtendedHeaderListSize;
	DWORD dwI;
	__try
	{
		// build the 7F48 header + the data into a buffer
		dwOffset = 3;
		dw7F48HeaderSize = 0;
		dw7F48HeaderSize += BuildSingleTlv(b7F48Header, 0x91, sizeof(DWORD), &dwOffset);
		dw7F48HeaderSize += BuildSingleTlv(b7F48Header, 0x92, bitlen / 16, &dwOffset);
		dw7F48HeaderSize += BuildSingleTlv(b7F48Header, 0x93, bitlen / 16, &dwOffset);
		if (bFormat & 2)
		{
			// add crt (chineese reminder theorem) template
			dw7F48HeaderSize += BuildSingleTlv(b7F48Header, 0x94, bitlen / 16, &dwOffset);
			dw7F48HeaderSize += BuildSingleTlv(b7F48Header, 0x95, bitlen / 16, &dwOffset);
			dw7F48HeaderSize += BuildSingleTlv(b7F48Header, 0x96, bitlen / 16, &dwOffset);
		}
		if (bFormat & 1)
		{
			dw7F48HeaderSize += BuildSingleTlv(b7F48Header, 0x97, bitlen / 8, &dwOffset);
		}
		b7F48Header[2] = (BYTE) dw7F48HeaderSize;
		dw7F48HeaderSize += 3; // before = only content, after += header size
		// build 5F48 header in a buffer
		// size of the data
		dwKeyDataSize = sizeof(DWORD) // e
			+ bitlen / 16 //prime1
			+ bitlen / 16 //prime2
			;
		if (bFormat & 2)
		{
			dwKeyDataSize+= bitlen / 16 //coefficient
				+ bitlen / 16 //exp1
				+ bitlen / 16 //exp2
				;
		}
		if (bFormat & 1)
		{
			dwKeyDataSize+= bitlen / 8 ; //modulus
		}
		dwOffset = 1;
		dw5F48HeaderSize = 1 + BuildSingleTlv(b5F48Header, 0x48, dwKeyDataSize, &dwOffset);
		// build the extended header list in a buffer
		dwExtendedHeaderListSize = 2 // for the crt to indicate the private key
			+ dw7F48HeaderSize
			+ dw5F48HeaderSize
			+ dwKeyDataSize;
		dwOffset = 0;
		dw4DHeaderSize = BuildSingleTlv(b4DHeader, 0x4D, dwExtendedHeaderListSize, &dwOffset);

		// allocate the memory
		*pdwTlvSize = dw4DHeaderSize + dwExtendedHeaderListSize;
		*ppbTlv = (PBYTE) malloc(*pdwTlvSize);
		if (! *ppbTlv)
		{
			dwReturn = SCARD_E_NO_MEMORY;
			__leave;
		}
		// 4D header
		dwOffset = 0;
		memcpy(*ppbTlv + dwOffset, b4DHeader, dw4DHeaderSize);
		dwOffset += dw4DHeaderSize;
		// control reference templace
		(*ppbTlv)[dwOffset++] = OpenPGPKeys[dwKey].bKeyTag;
		(*ppbTlv)[dwOffset++] = 0;
		// cardholder private key template
		memcpy(*ppbTlv + dwOffset, b7F48Header, dw7F48HeaderSize);
		dwOffset += dw7F48HeaderSize;
		// Concatenation of key data header
		memcpy(*ppbTlv + dwOffset, b5F48Header, dw5F48HeaderSize);
		dwOffset += dw5F48HeaderSize;
		// Concatenation of key data
		// exponent little => big endian
		(*ppbTlv)[dwOffset++] = (BYTE) (pbPublicKeyBlob->rsapubkey.pubexp / 0x1000000);
		(*ppbTlv)[dwOffset++] = (BYTE) ((pbPublicKeyBlob->rsapubkey.pubexp % 0x1000000) / 0x10000);
		(*ppbTlv)[dwOffset++] = (BYTE) ((pbPublicKeyBlob->rsapubkey.pubexp % 0x10000) / 0x100);
		(*ppbTlv)[dwOffset++] = (BYTE) ((pbPublicKeyBlob->rsapubkey.pubexp % 0x100) / 0x1);
		// prime1
		//memcpy(*ppbTlv + dwOffset, pbPublicKeyData + (2*bitlen)/16, bitlen / 16);
		for(dwI = 0; dwI < bitlen / 16; dwI++)
		{
			(*ppbTlv)[dwOffset+dwI] = pbPublicKeyData[(3*bitlen)/16 - 1 - dwI];
		}
		dwOffset += bitlen / 16;

		// prime2
		for(dwI = 0; dwI < bitlen / 16; dwI++)
		{
			(*ppbTlv)[dwOffset+dwI] = pbPublicKeyData[(4*bitlen)/16 - 1 - dwI];
		}
		//memcpy(*ppbTlv + dwOffset, pbPublicKeyData + (3*bitlen)/16, bitlen / 16);
		dwOffset += bitlen / 16;
		if (bFormat & 2)
		{
			// coeff
			//memcpy(*ppbTlv + dwOffset, pbPublicKeyData + (2+1 + 3) * bitlen / 16 , bitlen / 16);
			for(dwI = 0; dwI < bitlen / 16; dwI++)
			{
				(*ppbTlv)[dwOffset+dwI] = pbPublicKeyData[(7*bitlen)/16 - 1 - dwI];
			}
			dwOffset += bitlen / 16;
			// exponent1
			//memcpy(*ppbTlv + dwOffset, pbPublicKeyData + (2+1 + 1) * bitlen / 16 , bitlen / 16);
			for(dwI = 0; dwI < bitlen / 16; dwI++)
			{
				(*ppbTlv)[dwOffset+dwI] = pbPublicKeyData[(5*bitlen)/16 - 1 - dwI];
			}
			dwOffset += bitlen / 16;
			// exponent2
			//memcpy(*ppbTlv + dwOffset, pbPublicKeyData + (2+1 + 2) * bitlen / 16 , bitlen / 16);
			for(dwI = 0; dwI < bitlen / 16; dwI++)
			{
				(*ppbTlv)[dwOffset+dwI] = pbPublicKeyData[(6*bitlen)/16 - 1 - dwI];
			}
			dwOffset += bitlen / 16;
		}
		if (bFormat & 1)
		{
			// modulus
			//memcpy(*ppbTlv + dwOffset, pbPublicKeyData, bitlen / 8);
			for(dwI = 0; dwI < bitlen / 8; dwI++)
			{
				(*ppbTlv)[dwOffset+dwI] = pbPublicKeyData[bitlen / 8 - 1 - dwI];
			}
		}
	}
	__finally
	{
	}
	Trace(TRACE_LEVEL_VERBOSE, L"dwReturn = 0x%08X for key = %d", dwReturn, dwKey);
	return dwReturn;
}

BOOL OpenPGPCardv2::SaveKey(__in DWORD dwKeyId, __in ALG_ID Algid, __in_bcount(dwKeySize) PBYTE pBlob, __in DWORD dwKeySize)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	__try
	{
		if (!IsKeyCompatibleWithAlgId(dwKeyId,Algid))
		{
			dwError = NTE_BAD_ALGID;
			Trace(TRACE_LEVEL_ERROR, L"NTE_BAD_ALGID");
			__leave;
		}
		dwError = ImportKey(dwKeyId, pBlob, dwKeySize);
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR, L"CreateKey failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
	}
	Trace(TRACE_LEVEL_VERBOSE, L"dwError = 0x%08X",dwError);
	SetLastError(dwError);
	return fReturn;
}

DWORD OpenPGPCardv2::ImportKey(DWORD dwKey, PBYTE pBlob, DWORD dwKeySize)
{
	DWORD dwReturn;
	PSTR szAlgorithmAttributes = NULL;
	PBYTE pbTlv = NULL;
	DWORD dwTlvSize;
	PBYTE pbCommand = NULL;
	DWORD dwCommandSize;
	OPENPGP_ALGORITHM_ATTRIBUTE Attributes;
	PRSAPUBLICKEYBLOB pbPublicKeyBlob = (PRSAPUBLICKEYBLOB) pBlob;
	BYTE bCommand[] = {0x00,0xDB,0x3F,0xFF};
	DWORD dwSecondsSince1970;
	BYTE pbFingerPrint[20];
	__try
	{
		Trace(TRACE_LEVEL_VERBOSE, L"Enter dwContainer=%d",dwKey);
		// check blob
		if (pbPublicKeyBlob->blobheader.aiKeyAlg != CALG_RSA_SIGN &&
			pbPublicKeyBlob->blobheader.aiKeyAlg != CALG_RSA_KEYX)
		{
			Trace(TRACE_LEVEL_ERROR, L"Wrong aiKeyAlg %d", pbPublicKeyBlob->blobheader.aiKeyAlg);
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (pbPublicKeyBlob->blobheader.bType != PRIVATEKEYBLOB)
		{
			Trace(TRACE_LEVEL_ERROR, L"Wrong bType %d", pbPublicKeyBlob->blobheader.bType);
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}
		if (pbPublicKeyBlob->rsapubkey.magic != 0x32415352)
		{
			Trace(TRACE_LEVEL_ERROR, L"Wrong magic");
			dwReturn = SCARD_E_INVALID_PARAMETER;
			__leave;
		}

		Attributes.wModulusLengthInBit = (WORD) pbPublicKeyBlob->rsapubkey.bitlen;
		Attributes.wExponentLengthInBit = 4 * 8;
		Attributes.bAlgoId = 1;
		Attributes.bFormat = 0;
		dwReturn = SetKeyAlgorithmAttributes(dwKey, &Attributes);
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = BuildPrivateKeyTlv(pbPublicKeyBlob, dwKey, Attributes.bFormat, &pbTlv, &dwTlvSize);
		if (dwReturn)
		{
			__leave;
		}
		if (dwTlvSize > 0xFF)
		{
			dwCommandSize = 7 + dwTlvSize;

		}
		else
		{
			dwCommandSize = 5 + dwTlvSize;
		}
		pbCommand = (PBYTE) malloc(dwCommandSize);
		if (!pbCommand)
		{
			Trace(TRACE_LEVEL_ERROR, L"SCARD_E_NO_MEMORY");
			dwReturn = SCARD_E_NO_MEMORY;
			__leave;
		}
		memcpy(pbCommand, bCommand, 4);
		if (dwTlvSize > 0xFF)
		{
			pbCommand[4] = 0;
			pbCommand[5] = (BYTE)(dwTlvSize / 0x100);
			pbCommand[6] = (BYTE)(dwTlvSize % 0x100);
			memcpy(pbCommand + 7, pbTlv, dwTlvSize);
		}
		else
		{
			pbCommand[4] = (BYTE) dwTlvSize;
			memcpy(pbCommand + 5, pbTlv, dwTlvSize);
		}
		dwReturn = SendCommand(pbCommand, dwCommandSize);
		if (dwReturn)
		{
			__leave;
		}
		// save in the cache
		m_fHasKey[dwKey] = TRUE;

		dwReturn = CreateGenerationDateTime(&dwSecondsSince1970);
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = CreateFingerPrint(dwKey, dwSecondsSince1970, pbFingerPrint, pbPublicKeyBlob->modulus, (WORD) pbPublicKeyBlob->rsapubkey.bitlen / 8, pbPublicKeyBlob->rsapubkey.pubexp);
		if (dwReturn)
		{
			__leave;
		}
		// avoid two key having the same fingerprint if generated too fast
		while (memcmp(pbFingerPrint, m_bFingerPrint, 20) == 0
			|| memcmp(pbFingerPrint, m_bFingerPrint + 20, 20) == 0
			|| memcmp(pbFingerPrint, m_bFingerPrint + 40, 20) == 0)
		{
			dwSecondsSince1970++;
			dwReturn = CreateFingerPrint(dwKey, dwSecondsSince1970, pbFingerPrint, pbPublicKeyBlob->modulus, (WORD) pbPublicKeyBlob->rsapubkey.bitlen / 8, pbPublicKeyBlob->rsapubkey.pubexp);
			if (dwReturn)
			{
				__leave;
			}
		}
		dwReturn = UpdateGenerationDateTime(dwKey, dwSecondsSince1970);
		if (dwReturn)
		{
			__leave;
		}
		dwReturn = UpdateFingerPrint(dwKey, pbFingerPrint);
		if (dwReturn)
		{
			__leave;
		}
		memcpy(m_bFingerPrint + 20 * dwKey, pbFingerPrint, 20);
	}
	__finally
	{
		if (pbCommand)
		{
			SecureZeroMemory(pbCommand, dwCommandSize);
			free(pbCommand);
		}
		if (pbTlv)
		{
			SecureZeroMemory(pbTlv, dwTlvSize);
			free(pbTlv);
		}
	}
	Trace(TRACE_LEVEL_VERBOSE, L"dwReturn = 0x%08X for key = %d",dwReturn, dwKey);
	return dwReturn;
}


BOOL OpenPGPCardv2::RemoveKey(__in DWORD dwKey)
{

	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	BYTE pbFingerPrint[20] = {0};
	__try
	{
		// remove cert
		/*if (!SaveCertificate(dwKey, NULL, 0, 0))
		{
		Trace(TRACE_LEVEL_ERROR, L"removing cert failed 0x%08X", GetLastError());
		}*/

		// remove alias
		if (!RemoveAlias(dwKey))
		{
			Trace(TRACE_LEVEL_ERROR, L"RemoveAlias failed 0x%08X", GetLastError());
		}
		// remove key
		// not supported in the spec & confirmed by Achim
		fReturn = TRUE;
	}
	__finally
	{

	}
	Trace(TRACE_LEVEL_VERBOSE, L"dwError = 0x%08X",dwError);
	SetLastError(dwError);
	return fReturn;
}

class OpenPGPCardAliasHandle
{
public:
	CHAR szContainer[MAX_CONTAINER_NAME];
	BYTE pbFingerPrint[20];
	DWORD dwKeyId;
};

std::list<OpenPGPCardAliasHandle*> m_aliasHandles;

BOOL CleanOpenPGPCardv2Data()
{
	std::list<OpenPGPCardAliasHandle*>::const_iterator it (m_aliasHandles.begin());
	while (it!=m_aliasHandles.end()) 
	{
		delete (*it);
		it = m_aliasHandles.erase(it);
	}
	return TRUE;
}

BOOL OpenPGPCardv2::CheckForAlias(PCSTR szContainer, __out PDWORD pdwKeyId)
{
	*pdwKeyId = 0;
	std::list<OpenPGPCardAliasHandle*>::const_iterator it (m_aliasHandles.begin());
	for(;it!=m_aliasHandles.end();++it) 
	{
		if (strcmp(szContainer, (*it)->szContainer) == 0)
		{
			if (memcmp((*it)->pbFingerPrint, m_bFingerPrint + (*it)->dwKeyId * 20, 20) == 0)
			{
				*pdwKeyId = (*it)->dwKeyId;
				return TRUE;
			}
		}
	}
	return FALSE;
}

BOOL OpenPGPCardv2::RemoveAlias(DWORD dwKeyId)
{
	std::list<OpenPGPCardAliasHandle*>::const_iterator it (m_aliasHandles.begin());
	for(;it!=m_aliasHandles.end();++it) 
	{
		if (memcmp((*it)->pbFingerPrint, m_bFingerPrint + (*it)->dwKeyId * 20, 20) == 0)
		{
			delete (*it);
			it = m_aliasHandles.erase(it);
			return TRUE;
		}
	}
	return FALSE;
}

BOOL OpenPGPCardv2::SetContainerName(PSTR szContainer, DWORD dwKeyId)
{
	DWORD dwTempKeyId;
	if (CheckForAlias(szContainer, &dwTempKeyId))
		return TRUE;
	try
	{
		OpenPGPCardAliasHandle *handle = new OpenPGPCardAliasHandle();
		strcpy_s(handle->szContainer, MAX_CONTAINER_NAME, szContainer);
		handle->dwKeyId = dwKeyId;
		memcpy(handle->pbFingerPrint, m_bFingerPrint + 20 * dwKeyId, 20);
		m_aliasHandles.push_front(handle);
		return TRUE;
	}
	catch(std::bad_alloc&)
	{
		return FALSE;
	}
}

BOOL OpenPGPCardv2::GetKeySpec(__in DWORD dwKeyId, __out PDWORD pdwKeySpec)
{
	if (GetAlgIdFromKeyId(dwKeyId) == CALG_RSA_KEYX)
		*pdwKeySpec = AT_KEYEXCHANGE;
	else
		*pdwKeySpec = AT_SIGNATURE;
	return TRUE;
}

BOOL OpenPGPCardv2::GetKeyLength(__out PDWORD pdwDefaultLen, __out PDWORD pdwMinLen, __out PDWORD pdwMaxLen)
{
	*pdwDefaultLen = 2048;
	*pdwMinLen = 1024;
	*pdwMaxLen = 3072;
	return TRUE;
}

// {12F6CEE4-759C-401B-BB9F-F3E4E124A7D0}
static const GUID GUID_OPENPGP_DEFAULT = 
{ 0x12f6cee4, 0x759c, 0x401b, { 0xbb, 0x9f, 0xf3, 0xe4, 0xe1, 0x24, 0xa7, 0xd0 } };

BOOL OpenPGPCardv2::GetCardGUID(__inout GUID* pGuid)
{
	RtlCopyMemory(pGuid, &(GUID_OPENPGP_DEFAULT), sizeof(GUID));
	return TRUE;
}
