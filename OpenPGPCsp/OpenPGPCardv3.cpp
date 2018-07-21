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

Card* OpenPGPCardv3::CreateContext(SCARDCONTEXT hContext, SCARDHANDLE hScard, BOOL fAllowUI, OPENPGP_AID Aid)
{
	DWORD dwReturn = SCARD_F_UNKNOWN_ERROR;
	OpenPGPCardv3* returnedCard = NULL;
	__try
	{
		if ((Aid.AidVersion[0] == 3 && Aid.AidVersion[1] < 3) ||Aid.AidVersion[0] < 3)
		{
			Trace(TRACE_LEVEL_INFO, L"unsupported specification version %d.%d", Aid.AidVersion[0], Aid.AidVersion[1]);
			dwReturn = ERROR_REVISION_MISMATCH;
			__leave;
		}
		returnedCard = AllocateCard();
		if (returnedCard == NULL)
		{
			Trace(TRACE_LEVEL_ERROR, L"No memory");
			__leave;
		}
		returnedCard->hContext = hContext;
		returnedCard->hScard = hScard;
		returnedCard->m_AllowUI = fAllowUI;
		returnedCard->m_fSupportMse = FALSE;
		returnedCard->Aid = Aid;
		dwReturn = returnedCard->Create();
		if (dwReturn)
		{
			Trace(TRACE_LEVEL_ERROR, L"Create 0x%08X", dwReturn);
			__leave;
		}
		dwReturn = 0;
	}
	__finally
	{
		if (dwReturn)
		{
			delete returnedCard;
			returnedCard = NULL;
		}
		SetLastError(dwReturn);
	}
	return returnedCard;
}

DWORD OpenPGPCardv3::CheckCapabilities(__in_bcount(dwCardCapabilitiesSize) PBYTE pbCardCapabilities, DWORD dwCardCapabilitiesSize,
							__in_bcount(dwExtendedCapabilitiesSize) PBYTE pbExtendedCapabilities, DWORD dwExtendedCapabilitiesSize)
{
	OpenPGPCardv2::CheckCapabilities(pbCardCapabilities, dwCardCapabilitiesSize, pbExtendedCapabilities, dwExtendedCapabilitiesSize);
	m_fSupportMse = (dwExtendedCapabilitiesSize >= 10 &&  pbExtendedCapabilities[9] == 1);
	return ERROR_SUCCESS;
}

BOOL OpenPGPCardv3::IsKeyCompatibleWithAlgId(__in DWORD dwKeyId, __in ALG_ID algId)
{
	if (!m_fSupportMse || dwKeyId == OPENPGP_KEY_SIGNATURE)
		return (OpenPGPKeys[dwKeyId].aiKeyAlg == algId);
	if (algId == CALG_RSA_KEYX || algId == CALG_RSA_SIGN)
		return TRUE;
	return FALSE;

}

ALG_ID OpenPGPCardv3::GetAlgIdFromKeyId(__in DWORD dwKeyId)
{
	if (!m_fSupportMse || dwKeyId == OPENPGP_KEY_SIGNATURE)
		return OpenPGPKeys[dwKeyId].aiKeyAlg;
	return CALG_RSA_KEYX;
}

BOOL OpenPGPCardv3::Deauthenticate(__in DWORD dwPinId) 
{
	BYTE pbCmd[] = {0x00, 
				    0x20,
					0xFF,
					0x82,
					};
	if (dwPinId == OPENPGP_USER_PIN)
		pbCmd[3] = (BYTE) OPENPGP_USER_PIN_ID;
	else if (dwPinId == OPENPGP_USER_SIGNATURE_PIN)
		pbCmd[3] = (BYTE) OPENPGP_USER_PIN_SIGNATURE_ID;
	else if (dwPinId == OPENPGP_ADMIN_PIN)
		pbCmd[3] = (BYTE) OPENPGP_ADMIN_PIN_ID;
	DWORD dwError = SendCommand(pbCmd, ARRAYSIZE(pbCmd));
	if (dwError)
	{
		Trace(TRACE_LEVEL_ERROR, L"de Authentication failed");
	}
	return (dwError == ERROR_SUCCESS);
}

BOOL OpenPGPCardv3::SaveCertificate(__in DWORD dwKeyId, __in_bcount(dwSize) PBYTE pbData, __in DWORD dwSize, __in DWORD dwKeySpec)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	__try
	{
		if (dwKeyId >= OPENPGPKEYMAX)
		{
			dwError = NTE_KEYSET_NOT_DEF;
			__leave;
		}
		if (!dwSize && !IsKeyCompatibleWithAlgId(dwKeyId, (dwKeySpec == AT_SIGNATURE ? CALG_RSA_SIGN : CALG_RSA_KEYX)))
		{
			dwError = NTE_NOT_SUPPORTED;
			__leave;
		}
		// select cert
		if (dwKeyId != OPENPGP_KEY_AUTHENTICATION)
		{
			if (!SelectCertSubDO(dwKeyId))
			{
				__leave;
			}
		}
		dwError = WriteDO(OpenPGPCertificate, pbData, dwSize);
		// select cert back
		if (dwKeyId != OPENPGP_KEY_AUTHENTICATION)
		{
			if (!SelectCertSubDO(OPENPGP_KEY_AUTHENTICATION))
			{
				__leave;
			}
		}
		if (dwError)
		{
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


BOOL OpenPGPCardv3::SelectCertSubDO(__in DWORD dwKeyId)
{
	BOOL fReturn = FALSE;
	DWORD dwError = ERROR_INTERNAL_ERROR;
	BYTE pbCmd[] = {0x00,0xA5,0x00,0x04,0x06,0x60,0x04,0x5C,0x02,0x7F,0x21,0x00};
	__try
	{
		// select cert
		switch (dwKeyId)
		{
		case OPENPGP_KEY_CONFIDENTIALITY:
			pbCmd[2] = (BYTE)1;
			break;
		case OPENPGP_KEY_SIGNATURE:
			pbCmd[2] = (BYTE)2;
			break;
		case OPENPGP_KEY_AUTHENTICATION:
		default:
			pbCmd[2] = (BYTE)0;
			break;
		}
		
		dwError = SendCommand(pbCmd, ARRAYSIZE(pbCmd));
		if (dwError)
		{
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

BOOL OpenPGPCardv3::GetCertificate(__in DWORD dwKeyId, _Out_writes_bytes_to_opt_(*pdwSize, *pdwSize) PBYTE pbData, __out PDWORD pdwSize)
{
	BOOL fReturn = FALSE;
	DWORD dwError = ERROR_INTERNAL_ERROR;
	PBYTE pbCertificate = NULL;
	DWORD dwCertificateSize = 0;
	__try
	{
		Trace(TRACE_LEVEL_VERBOSE, L"Enter dwKey=%d",dwKeyId);
		// select cert
		if (dwKeyId != OPENPGP_KEY_AUTHENTICATION)
		{
			if (!SelectCertSubDO(dwKeyId))
			{
				__leave;
			}
		}
		dwError = ReadDO(OpenPGPCertificate, &pbCertificate, &dwCertificateSize);
		// select cert back
		if (dwKeyId != OPENPGP_KEY_AUTHENTICATION)
		{
			SelectCertSubDO(OPENPGP_KEY_AUTHENTICATION);
		}
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


BOOL OpenPGPCardv3::GetKeyIdForNewKey(__in ALG_ID Algid, __in_opt HWND hWndParent, __out PDWORD pdwKeyId)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	SelectOpenPGPv3KeyDialog dialog(Algid, m_fSupportMse);
	if (!m_AllowUI)
	{
		Trace(TRACE_LEVEL_ERROR, L"Silent context");
		SetLastError(NTE_SILENT_CONTEXT);
		return FALSE;
	}
	Trace(TRACE_LEVEL_INFO, L"showing SelectOpenPGPv3KeyDialog dialog");
	if (dialog.Show(hWndParent) != IDOK)
	{
		Trace(TRACE_LEVEL_INFO, L"SelectOpenPGPv3KeyDialog dialog cancelled");
		SetLastError(ERROR_CANCELLED);
		return FALSE;
	}
	Trace(TRACE_LEVEL_INFO, L"SelectOpenPGPv3KeyDialog dialog ended with key id %d", dialog.m_dwKeyId);
	*pdwKeyId = dialog.m_dwKeyId;
	return TRUE;
}

BOOL OpenPGPCardv3::ManageSecurityEnvironment(__in DWORD dwKeyId, __in DWORD dwOperationId)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	BYTE pbCmd[] = {0x00, 0x22, 0x41, 0x00,0x03,0x83,0x01,0x00};
	__try
	{	
		if (dwKeyId != OPENPGP_KEY_AUTHENTICATION && dwKeyId != OPENPGP_KEY_CONFIDENTIALITY)
		{
			Trace(TRACE_LEVEL_ERROR, L"dwKeyId invalid %d", dwKeyId);
			dwError = NTE_BAD_ALGID;
			__leave;
		}
		if (dwOperationId != PIN_OPERATION_DECRYPT && dwOperationId != PIN_OPERATION_SIGN)
		{
			Trace(TRACE_LEVEL_ERROR, L"dwOperationId invalid %d", dwOperationId);
			dwError = NTE_BAD_FLAGS;
			__leave;
		}
		Trace(TRACE_LEVEL_INFO,L"Manage security environment for operation %s", (dwOperationId == PIN_OPERATION_DECRYPT?L"PIN_OPERATION_DECRYPT":L"PIN_OPERATION_SIGN") );
		if (dwOperationId == PIN_OPERATION_DECRYPT)
			pbCmd[3] = 0xB8;
		else
			pbCmd[3] = 0xA4;
		if (dwKeyId == OPENPGP_KEY_CONFIDENTIALITY)
			pbCmd[7] = 0x02;
		else
			pbCmd[7] = 0x03;
		dwError = SendCommand(pbCmd, ARRAYSIZE(pbCmd));
		if (dwError)
		{
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

BOOL OpenPGPCardv3::Decrypt(__in DWORD dwKeyId,
					 __in PBYTE pbEncryptedData, __in DWORD cbEncryptedData,
					_Out_writes_bytes_to_(*pcbDecryptedData, *pcbDecryptedData) BYTE *pbDecryptedData,
					_Inout_  DWORD *pcbDecryptedData)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	__try
	{
		Trace(TRACE_LEVEL_VERBOSE, L"Enter dwContainer=%d",dwKeyId);
		if (!m_fSupportMse || dwKeyId == OPENPGP_KEY_CONFIDENTIALITY)
		{
			fReturn = OpenPGPCardv2::Decrypt(dwKeyId, pbEncryptedData, cbEncryptedData, pbDecryptedData, pcbDecryptedData);
			dwError = GetLastError();
			__leave;
		}
		if (!ManageSecurityEnvironment(dwKeyId, PIN_OPERATION_DECRYPT))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"DecryptOperation failed 0x%08X", dwError);
			__leave;
		}
		if (!DecryptOperation(pbEncryptedData, cbEncryptedData, pbDecryptedData, pcbDecryptedData))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"DecryptOperation failed 0x%08X", dwError);
			ManageSecurityEnvironment(OPENPGP_KEY_CONFIDENTIALITY, PIN_OPERATION_DECRYPT);
			__leave;
		}
		if (!ManageSecurityEnvironment(OPENPGP_KEY_CONFIDENTIALITY, PIN_OPERATION_DECRYPT))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"DecryptOperation failed 0x%08X", dwError);
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


BOOL OpenPGPCardv3::SignData(__in DWORD dwKeyId,__in PCWSTR szAlgorithm, __in PBYTE pbHashValue, __in DWORD cbHashValue,
							 _Out_writes_bytes_to_(*pdwSigLen, *pdwSigLen) BYTE *pbSignature,
							 _Inout_  DWORD *pdwSigLen)
{
	BOOL fReturn = FALSE;
	DWORD dwError = ERROR_INTERNAL_ERROR;
	DWORD dwAlgIndex = 0;
	PBYTE pbHash = NULL;
	__try
	{
		Trace(TRACE_LEVEL_VERBOSE, L"Enter dwKey=%d",dwKeyId);
		if (dwKeyId >= OPENPGPKEYMAX)
		{
			dwError = NTE_KEYSET_NOT_DEF;
			Trace(TRACE_LEVEL_INFO, L"NTE_KEYSET_NOT_DEF %d", dwKeyId);
			__leave;
		}
		if (!m_fSupportMse || dwKeyId == OPENPGP_KEY_SIGNATURE || dwKeyId == OPENPGP_KEY_AUTHENTICATION)
		{
			fReturn = OpenPGPCardv2::SignData(dwKeyId, szAlgorithm, pbHashValue, cbHashValue, pbSignature, pdwSigLen);
			dwError = GetLastError();
			__leave;
		}
		if (!ManageSecurityEnvironment(dwKeyId, PIN_OPERATION_SIGN))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"DecryptOperation failed 0x%08X", dwError);
			__leave;
		}
		if (!OpenPGPCardv2::SignData(OPENPGP_KEY_AUTHENTICATION, szAlgorithm, pbHashValue, cbHashValue, pbSignature, pdwSigLen))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"DecryptOperation failed 0x%08X", dwError);
			ManageSecurityEnvironment(OPENPGP_KEY_AUTHENTICATION, PIN_OPERATION_SIGN);
			__leave;
		}
		if (!ManageSecurityEnvironment(OPENPGP_KEY_AUTHENTICATION, PIN_OPERATION_SIGN))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"DecryptOperation failed 0x%08X", dwError);
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