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

typedef struct _CachedPin
{
	DWORD dwPinId;
	BYTE encryptedPin[MAX_PIN_SIZE + RTL_ENCRYPT_MEMORY_SIZE];
	BYTE Key[KEY_SIZE];
	FILETIME Timestamp;
} CachedPin;

std::list<CachedPin*> m_cachedPins;

////////////////////////////////////////////////////////////////////////////
// PIN Operations / Authentication
////////////////////////////////////////////////////////////////////////////



BOOL BaseContainer::RemovePinInCache(__in DWORD dwPinId)
{
	std::list<CachedPin*>::const_iterator it (m_cachedPins.begin());
	for(;it!=m_cachedPins.end();++it) 
	{
		if ((*it)->dwPinId == dwPinId && memcmp((*it)->Key,m_Key, KEY_SIZE) == 0)
		{
			CachedPin* cachedpin = *it;
			SecureZeroMemory(cachedpin, sizeof(CachedPin));
			m_cachedPins.erase(it);
			delete cachedpin;
			return TRUE;
		}
	}
	SetLastError(ERROR_NOT_FOUND);
	return FALSE;
}

BOOL BaseContainer::CleanPinCache()
{
	std::list<CachedPin*>::const_iterator it (m_cachedPins.begin());
	while (it!=m_cachedPins.end()) 
	{
		SecureZeroMemory((*it)->encryptedPin, MAX_PIN_SIZE);
		delete (*it);
		it = m_cachedPins.erase(it);
	}
	return TRUE;
}

BOOL BaseContainer::GetPinInCache(__in DWORD dwPinId, __out_ecount(MAX_PIN_SIZE) PSTR szPin, __out PFILETIME Timestamp)
{
	szPin[0] = 0;
	ZeroMemory(Timestamp, sizeof(FILETIME));
	std::list<CachedPin*>::const_iterator it (m_cachedPins.begin());
	for(;it!=m_cachedPins.end();++it) 
	{
		if ((*it)->dwPinId == dwPinId && memcmp((*it)->Key,m_Key, KEY_SIZE) == 0)
		{
			memcpy(szPin, (*it)->encryptedPin, MAX_PIN_SIZE);
			RtlDecryptMemory(szPin, MAX_PIN_SIZE, 0);
			memcpy(Timestamp, &((*it)->Timestamp), sizeof(FILETIME));
			return TRUE;
		}
	}
	SetLastError(ERROR_NOT_FOUND);
	return FALSE;
}

BOOL BaseContainer::SetPinInCache(__in DWORD dwPinId, __in_ecount(MAX_PIN_SIZE) PSTR szPin)
{
	SYSTEMTIME Timestamp = {0};
	GetSystemTime(&Timestamp);
	std::list<CachedPin*>::const_iterator it (m_cachedPins.begin());
	for(;it!=m_cachedPins.end();++it) 
	{
		if ((*it)->dwPinId == dwPinId && memcmp((*it)->Key,m_Key, KEY_SIZE) == 0)
		{
			memcpy((*it)->encryptedPin, szPin, MAX_PIN_SIZE);
			RtlEncryptMemory((*it)->encryptedPin, MAX_PIN_SIZE, 0);
			SystemTimeToFileTime(&Timestamp, &((*it)->Timestamp));
			return TRUE;
		}
	}
	CachedPin* pin = new CachedPin();
	pin->dwPinId = dwPinId;
	memcpy(pin->Key, m_Key, KEY_SIZE);
	memcpy(pin->encryptedPin, szPin, MAX_PIN_SIZE);
	RtlEncryptMemory(pin->encryptedPin, MAX_PIN_SIZE, 0);
	SystemTimeToFileTime(&Timestamp, &(pin->Timestamp));
	m_cachedPins.push_back(pin);
	return TRUE;
}

BOOL BaseContainer::AskPinToUserIfNeeded(__in HWND hWndParent, __in DWORD dwPinId)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	FILETIME LastSet = {0};
	CHAR szPin[MAX_PIN_SIZE];
	FILETIME TimeStamp;
	__try
	{
		if (m_VerifyContext)
		{
			dwError = NTE_FAIL;
			Trace(TRACE_LEVEL_ERROR, L"m_VerifyContext is TRUE");
			__leave;
		}
		if (!GetPinInCache(dwPinId, szPin, &TimeStamp))
		{
			if (!m_AllowUI)
			{
				dwError = NTE_SILENT_CONTEXT;
				Trace(TRACE_LEVEL_ERROR, L"NTE_SILENT_CONTEXT");
				__leave;
			}
			if (!m_Card->AskForPin(hWndParent, m_szPinPROMPT, dwPinId, szPin))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"AskForPin failed 0x%08X", dwError);
				__leave;
			}
			if (!SetPinInCache(dwPinId, szPin))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"SetPinInCache failed 0x%08X", dwError);
				__leave;
			}
		}
		fReturn = TRUE;
	}
	__finally
	{
		SecureZeroMemory(szPin, sizeof(szPin));
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL BaseContainer::ChangePin()
{
	Trace(TRACE_LEVEL_VERBOSE, L"Enter");
	//ChangePINDialog dialog;

	//CHAR szBeforePIN[MAX_PIN_SIZE];
	//CHAR szAfterPIN[MAX_PIN_SIZE];
	//if (!m_AllowUI)
	//{
	//	Trace(TRACE_LEVEL_INFO, L"NTE_SILENT_CONTEXT");
	//	SetLastError(NTE_SILENT_CONTEXT);
	//	return FALSE;
	//}
	//if (dialog.Show() != IDOK)
	//{
	//	Trace(TRACE_LEVEL_INFO, L"Pin dialog cancelled");
	//	SetLastError(ERROR_CANCELLED);
	//	return FALSE;
	//}
	//dialog.GetBeforePIN(szBeforePIN);
	//if (!Authenticate(0, szBeforePIN))
	//{
	//	Trace(TRACE_LEVEL_ERROR, L"SCARD_W_WRONG_CHV");
	//	SetLastError(SCARD_W_WRONG_CHV);
	//	return FALSE;
	//}

	//dialog.GetAfterPIN(szAfterPIN);
	////TODO
	BOOL fReturn = FALSE;
	//DWORD dwError = GetLastError();
	//if (fReturn) SetPinInCache(0, szAfterPIN);
	//SecureZeroMemory(szAfterPIN, sizeof(szAfterPIN));
	//SecureZeroMemory(szAfterPIN, sizeof(szBeforePIN));
	//SetLastError(dwError);
	return fReturn;
}

BOOL BaseContainer::SetPin(__in DWORD dwPinType, PSTR szPin)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	DWORD dwOperation = 0;
	DWORD dwPinId;
	__try
	{
		switch (dwPinType)
		{
			case PP_ADMIN_PIN :
				dwOperation = PIN_OPERATION_SET_ADMIN_PIN;
				break;
			case PP_KEYEXCHANGE_PIN:
				dwOperation = PIN_OPERATION_SET_KEYEXCHANGE_PIN;
				break;
			case PP_SIGNATURE_PIN:
				dwOperation = PIN_OPERATION_SET_SIGNATURE_PIN;
				break;
		}
		if (!GetPIN(dwOperation, &dwPinId))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"RemovePinInCache failed 0x%08X", dwError);
			__leave;
		}
		if (szPin)
		{
			if (strlen(szPin) +1 > MAX_PIN_SIZE)
			{
				dwError = NTE_BAD_FLAGS;
				Trace(TRACE_LEVEL_ERROR, L"Pin too long %S", szPin);
				__leave;
			}
			fReturn = SetPinInCache(dwPinId, szPin);
			if (!fReturn)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"SetPinInCache failed 0x%08X", dwError);
				__leave;
			}
		}
		else
		{
			fReturn = RemovePinInCache(dwPinId);
			if (!fReturn)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"RemovePinInCache failed 0x%08X", dwError);
				__leave;
			}
		}
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL BaseContainer::GetPIN(__in DWORD dwOperationId, __out PDWORD pdwPinId)
{
	return m_Card->GetPIN(m_dwCardContainerId, dwOperationId, pdwPinId);
}

BOOL BaseContainer::Authenticate(__in DWORD dwPinId)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	CHAR szPin[MAX_PIN_SIZE] = {0};
	FILETIME Timestamp = {0};
	DWORD dwAttemptRemaining = 0;
	__try
	{
		if (m_VerifyContext)
		{
			dwError = NTE_FAIL;
			Trace(TRACE_LEVEL_ERROR, L"m_VerifyContext is TRUE");
			__leave;
		}
		if (!GetPinInCache(dwPinId, szPin, &Timestamp))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetPin failed 0x%08X", dwError);
			__leave;
		}
		if (!m_Card->AuthenticatePIN(dwPinId, szPin, &dwAttemptRemaining))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetPin failed 0x%08X attempremaining=%d", dwError, dwAttemptRemaining);
			if (!RemovePinInCache(dwPinId))
			{
				DWORD dwError2 = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"RemovePinInCache failed 0x%08X", dwError2);
			}
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		SecureZeroMemory(szPin, sizeof(szPin));
	}
	SetLastError(dwError);
	return fReturn;
}


// Smart card transactions

Card* BaseContainer::CreateContext()
{
	OPENPGP_AID Aid = {0};
	DWORD dwReturn = 0;
	BYTE pbSelectOpenPGPAppletCmd[] = {0x00, 
				    0xA4,
					0x04,
					0x00,
					0x06,
					0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
					0x00
					};
	BYTE pbGetDataAid[] = {0x00,0xCA,0x00,0x4F,0x00,0x00,0x00};
	BYTE     recvbuf[256];
	DWORD     recvlen = sizeof(recvbuf);
	Card* returnedCard = NULL;
	__try
	{
		TraceAPDUIn(pbSelectOpenPGPAppletCmd, ARRAYSIZE(pbSelectOpenPGPAppletCmd));
		dwReturn = SCardTransmit(m_hCard, 
									SCARD_PCI_T1, 
									pbSelectOpenPGPAppletCmd, 
									ARRAYSIZE(pbSelectOpenPGPAppletCmd), 
									NULL, 
									recvbuf, 
									&recvlen);
		TraceAPDUOut(dwReturn, recvbuf, recvlen);
		if (dwReturn != ERROR_SUCCESS || recvlen < 2 || !(( recvbuf[recvlen-2] == 0x90 ) && ( recvbuf[recvlen-1] == 0x00 )))
		{
			Trace(TRACE_LEVEL_ERROR, L"unable to select the OpenPGP applet");
			dwReturn = SCARD_E_UNEXPECTED;
			__leave;
		}
		recvlen = sizeof(recvbuf);
		TraceAPDUIn(pbGetDataAid, ARRAYSIZE(pbGetDataAid));
		dwReturn = SCardTransmit(m_hCard, 
									SCARD_PCI_T1, 
									pbGetDataAid, 
									ARRAYSIZE(pbGetDataAid), 
									NULL, 
									recvbuf, 
									&recvlen);
		TraceAPDUOut(dwReturn, recvbuf, recvlen);
		if (dwReturn != ERROR_SUCCESS || recvlen < 2 || !(( recvbuf[recvlen-2] == 0x90 ) && ( recvbuf[recvlen-1] == 0x00 )))
		{
			Trace(TRACE_LEVEL_ERROR, L"unable to get the AID");
			dwReturn = SCARD_E_UNEXPECTED;
			__leave;
		}
		if (recvlen - 2 != sizeof(OPENPGP_AID))
		{
			Trace(TRACE_LEVEL_ERROR, L"dwApplicationIdentifierSize = %02X", recvlen-2);
			dwReturn = SCARD_E_UNEXPECTED;
			__leave;
		}
		Aid = *((OPENPGP_AID*) recvbuf);
		returnedCard = OpenPGPCardv3::CreateContext(m_hContext, m_hCard, m_AllowUI, Aid);
		if (returnedCard)
		{
			Trace(TRACE_LEVEL_INFO, L"selecting OpenPGPv3");
			__leave;
		}
		returnedCard = OpenPGPCardv2::CreateContext(m_hContext, m_hCard, m_AllowUI, Aid);
		if (returnedCard)
		{
			Trace(TRACE_LEVEL_INFO, L"selecting OpenPGPv2");
			__leave;
		}
		Trace(TRACE_LEVEL_ERROR, L"no applet found - stop");
	}
	__finally
	{
	}
	SetLastError(dwReturn);
	return returnedCard;
}

BOOL BaseContainer::StartTransaction()
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	__try
	{
		Trace(TRACE_LEVEL_VERBOSE, L"SCardBeginTransaction 0x%Ix", m_hCard);
#ifndef NO_TRANSACTION
		dwError = SCardBeginTransaction(m_hCard);
#endif
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR, L"SCardBeginTransaction failed 0x%08X", dwError);
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

BOOL BaseContainer::EndTransaction(DWORD dwPinId, BOOL fAuthenticated)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	BOOL fReset = FALSE;
	__try
	{
		if (!m_hCard)
		{
			fReturn = TRUE;
			__leave;
		}
		if (dwPinId != (DWORD) -1 && m_Card != NULL && fAuthenticated)
		{
			fReset = !(m_Card->Deauthenticate(dwPinId));
			if (fReset)
			{
				Trace(TRACE_LEVEL_INFO, L"Card reset programmed - deauthentication failed");
			}
		}
		Trace(TRACE_LEVEL_VERBOSE, L"SCardEndTransaction 0x%Ix with reset %s", m_hCard, (fReset?L"TRUE": L"FALSE"));
#ifndef NO_TRANSACTION
		dwError = SCardEndTransaction(m_hCard, (fReset ? SCARD_RESET_CARD : SCARD_LEAVE_CARD));
#endif
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR, L"SCardEndTransaction failed 0x%08X", dwError);
			__leave;
		}
		if (fReset)
		{
			m_Card->Reinit();
		}
		fReturn = TRUE;
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL ExtractReaderAndContainerFromGeneralNameA(__in PCSTR szSubmittedContainer, __in PSTR szBuffer, __in DWORD dwBufferSize,
											  __out PCSTR *pszReader, __out PCSTR *pszContainer)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	const CHAR szInvalidChar[] = "<>:\"/\\|?*";
	__try
	{
		// check container format name
		/////////////////////////////////////////////////
		// Type	Name	Format
		// I	Reader Name and Container Name	\\.\<Reader Name>\<Container Name>
		// II	Reader Name and Container Name (NULL)	\\.\<Reader Name>\
		// III	Container Name Only	<Container Name>
		// IV	Default Container (NULL) Only	NULL

		if (szSubmittedContainer)
		{
			if (strncmp(szSubmittedContainer, "\\\\.\\",4) == 0)
			{
				if (szSubmittedContainer[4] == 0)
				{
					Trace(TRACE_LEVEL_ERROR, L"container name \\\\.\\");
					dwError = NTE_BAD_KEYSET;
					__leave;
				}
				PCSTR szPos = strchr(szSubmittedContainer + 4, '\\');
				if (szPos)
				{
					DWORD dwSize = (DWORD) (szPos - szSubmittedContainer - 4);
					if (dwSize + 1 > dwBufferSize)
					{
						Trace(TRACE_LEVEL_ERROR, L"container name %S contains a reader whose name is too long", szSubmittedContainer);
						dwError = NTE_BAD_KEYSET;
						__leave;
					}
					strncpy_s(szBuffer, dwBufferSize, szSubmittedContainer + 4, dwSize);
					*pszReader = szBuffer;
					if (szPos[1] != 0)
					{
						*pszContainer = szPos + 1;
					}
				}
				else
				{
					*pszReader = szSubmittedContainer + 4;
				}
			}
			else
			{
				*pszContainer = szSubmittedContainer;
			}
		}
		// check container name
		if (*pszContainer)
		{
			if (strlen(*pszContainer) > MAX_CONTAINER_NAME-1)
			{
				Trace(TRACE_LEVEL_ERROR, L"container name '%S' too long", *pszContainer);
				dwError = NTE_BAD_KEYSET;
				__leave;
			}
			for (DWORD i = 0; i< strlen(szInvalidChar); i++)
			{
				if (strchr(*pszContainer,szInvalidChar[i]))
				{
					Trace(TRACE_LEVEL_ERROR, L"character '%C' found in container name '%S'", szInvalidChar[i], *pszContainer);
					dwError = NTE_BAD_KEYSET;
					__leave;
				}
			}
		}
		fReturn = TRUE;
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL ExtractReaderAndContainerFromGeneralNameW(__in PCWSTR szSubmittedContainer, __in PWSTR szBuffer, __in DWORD dwBufferSize,
											  __out PCWSTR *pszReader, __out PCWSTR *pszContainer)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	const WCHAR szInvalidChar[] = L"<>:\"/\\|?*";
	__try
	{
		// check container format name
		/////////////////////////////////////////////////
		// Type	Name	Format
		// I	Reader Name and Container Name	\\.\<Reader Name>\<Container Name>
		// II	Reader Name and Container Name (NULL)	\\.\<Reader Name>\
		// III	Container Name Only	<Container Name>
		// IV	Default Container (NULL) Only	NULL

		if (szSubmittedContainer)
		{
			if (wcsncmp(szSubmittedContainer, L"\\\\.\\",4) == 0)
			{
				if (szSubmittedContainer[4] == 0)
				{
					Trace(TRACE_LEVEL_ERROR, L"container name \\\\.\\");
					dwError = NTE_BAD_KEYSET;
					__leave;
				}
				PCWSTR szPos = wcschr(szSubmittedContainer + 4, L'\\');
				if (szPos)
				{
					DWORD dwSize = (DWORD) (szPos - szSubmittedContainer - 4);
					if (dwSize + 1 > dwBufferSize)
					{
						Trace(TRACE_LEVEL_ERROR, L"container name %s contains a reader whose name is too long", szSubmittedContainer);
						dwError = NTE_BAD_KEYSET;
						__leave;
					}
					wcsncpy_s(szBuffer, dwBufferSize, szSubmittedContainer + 4, dwSize);
					*pszReader = szBuffer;
					if (szPos[1] != 0)
					{
						*pszContainer = szPos + 1;
					}
				}
				else
				{
					*pszReader = szSubmittedContainer + 4;
				}
			}
			else
			{
				*pszContainer = szSubmittedContainer;
			}
		}
		// check container name
		if (*pszContainer)
		{
			if (wcslen(*pszContainer) > MAX_CONTAINER_NAME-1)
			{
				Trace(TRACE_LEVEL_ERROR, L"container name '%S' too long", *pszContainer);
				dwError = NTE_BAD_KEYSET;
				__leave;
			}
			for (DWORD i = 0; i< wcslen(szInvalidChar); i++)
			{
				if (wcschr(*pszContainer,szInvalidChar[i]))
				{
					Trace(TRACE_LEVEL_ERROR, L"character '%c' found in container name '%s'", szInvalidChar[i], *pszContainer);
					dwError = NTE_BAD_KEYSET;
					__leave;
				}
			}
		}
		fReturn = TRUE;
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}

////////////////////////////////////////////////////////////////////////////
// store operations
////////////////////////////////////////////////////////////////////////////


BOOL BaseContainer::GetUserStore(__in PTSTR szProviderName, __out HCERTSTORE* phStore)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	HCERTSTORE hStore = NULL;
	BOOL fEndTransaction = FALSE;
	BOOL fAuthenticated = FALSE;
	__try
	{
		if (!m_Card)
		{
			Trace(TRACE_LEVEL_ERROR, L"defensive programming for user store");
			dwError = NTE_NOT_SUPPORTED;
			__leave;
		}
		hStore = CertOpenStore(CERT_STORE_PROV_MEMORY,0,0,0,NULL);
		if (!hStore)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CertOpenStore failed 0x%08X", dwError);
			__leave;
		}
		if (!StartTransaction())
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"StartTransaction failed 0x%08X", dwError);
			__leave;
		}
		fEndTransaction = TRUE;
		DWORD dwMaxContainer = m_Card->GetMaxContainer();
		for(DWORD dwI = 0; dwI < dwMaxContainer; dwI++)
		{
			CHAR szContainer[MAX_CONTAINER_NAME];
			BYTE pbBuffer[4096];
			DWORD dwSize = sizeof(pbBuffer);
			DWORD dwKeySpec = AT_SIGNATURE;
			if (m_Card->GetContainerName(dwI, szContainer)
				&& m_Card->GetKeySpec(dwI, &dwKeySpec)
				&& m_Card->GetCertificate(dwI, pbBuffer, &dwSize))
			{
				PopulateUserStoreFromContainerName(hStore, szProviderName, szContainer, dwKeySpec, pbBuffer, dwSize);
			}
		}
		*phStore = hStore;
		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			if (hStore) 
				CertCloseStore(hStore, 0);
		}
		if (fEndTransaction)
			EndTransaction(0, fAuthenticated);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL BaseContainer::PopulateUserStoreFromContainerName(__in HCERTSTORE hStore, __in PTSTR szProviderName, __in PSTR szContainer, __in DWORD dwKeySpec, __in PBYTE pbData, __in DWORD dwSize)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	PCCERT_CONTEXT pCertContext = NULL;
	CRYPT_KEY_PROV_INFO propInfo;
	WCHAR szWideContainerName[MAX_CONTAINER_NAME];
	__try
	{
		pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING,	pbData, dwSize);
		if (!pCertContext)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CertCreateCertificateContext failed 0x%08X", dwError);
			__leave;
		}
		MultiByteToWideChar(CP_ACP, 0, szContainer, -1, szWideContainerName, MAX_CONTAINER_NAME);
		ZeroMemory(&propInfo,sizeof(propInfo));
		propInfo.pwszContainerName = szWideContainerName;
		propInfo.pwszProvName = szProviderName;
		propInfo.dwProvType = PROV_RSA_FULL;
		propInfo.dwFlags = 0;
		propInfo.cProvParam = 0;
		propInfo.rgProvParam = 0;
		propInfo.dwKeySpec = dwKeySpec;
		if (!CertSetCertificateContextProperty(pCertContext,CERT_KEY_PROV_INFO_PROP_ID,
			0,&propInfo))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CertSetCertificateContextProperty failed 0x%08X", dwError);
			__leave;
		}
		if (!CertAddCertificateContextToStore(hStore,pCertContext, CERT_STORE_ADD_ALWAYS,NULL))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CertAddCertificateContextToStore failed 0x%08X", dwError);
			__leave;
		}
		Trace(TRACE_LEVEL_INFO, L"added one certificate for container %S", szContainer);
		fReturn = TRUE;
	}
	__finally
	{
		if (pCertContext) 
			CertFreeCertificateContext(pCertContext);
	}
	SetLastError(dwError);
	return fReturn;
}

////////////////////////////////////////////////////////////////////////////
// cryto operations
////////////////////////////////////////////////////////////////////////////
BOOL BaseContainer::SignData(__in PCWSTR szAlgorithm, __in PBYTE pbHashValue, __in DWORD cbHashValue,
					_Out_writes_bytes_to_(*pdwSigLen, *pdwSigLen) BYTE *pbSignature,
					_Inout_  DWORD *pdwSigLen)
{
	return m_Card->SignData(m_dwCardContainerId, szAlgorithm, pbHashValue, cbHashValue, pbSignature, pdwSigLen);
}

BOOL BaseContainer::LoadCertificate(_Out_writes_bytes_to_opt_(*pdwSize, *pdwSize) PBYTE pbData, __inout PDWORD pdwSize)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	BOOL fEndTransaction = FALSE;
	BOOL fAuthenticated = FALSE;
	__try
	{
		if (!m_Card)
		{
			Trace(TRACE_LEVEL_ERROR, L"Card is not initialized");
			__leave;
		}
		if (!StartTransaction())
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"StartTransaction failed 0x%08X", dwError);
			__leave;
		}
		fEndTransaction = TRUE;
		if (!m_Card->GetCertificate(m_dwCardContainerId, pbData, pdwSize))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetCertificate failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (fEndTransaction)
			EndTransaction(0, fAuthenticated);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL BaseContainer::SaveCertificate(__in_bcount(dwSize) PBYTE pbData, __in  DWORD dwSize, __in DWORD dwKeySpec)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	BOOL fEndTransaction = FALSE;
	BOOL fAuthenticated = FALSE;
	DWORD dwPinId = 0;
	if (!m_Card)
	{
		Trace(TRACE_LEVEL_ERROR, L"Card is not initialized");
		return FALSE;
	}
	__try
	{
		if (!GetPIN(PIN_OPERATION_SAVE_CERT, &dwPinId))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetPIN failed 0x%08X", dwError);
			__leave;
		}
		if (!StartTransaction())
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"StartTransaction failed 0x%08X", dwError);
			__leave;
		}
		fEndTransaction = TRUE;
		// authenticate
		if (!Authenticate(dwPinId))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"Authenticate failed 0x%08X", dwError);
			__leave;
		}
		fAuthenticated = TRUE;
		if (!m_Card->SaveCertificate(m_dwCardContainerId, pbData, dwSize, dwKeySpec))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"SaveCertificate failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (fEndTransaction)
			EndTransaction(dwPinId, fAuthenticated);
	}
	SetLastError(dwError);
	return fReturn;
}

PWSTR DuplicateUnicodeString(PWSTR source)
{
	if (source == NULL)
		return NULL;
	size_t len = wcslen(source) + 1;
	PWSTR output = (PWSTR) malloc(sizeof(WCHAR) * len);
	if (!output)
		return NULL;
	wcscpy_s(output, len, source);
	return output;
}
