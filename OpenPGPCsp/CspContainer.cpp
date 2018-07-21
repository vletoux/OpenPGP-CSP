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

#define FILE_PRIVATE_KEY 0
#define FILE_PUBLIC_KEY 1
#define FILE_CERTIFICATE 2
#define FILE_SEARCH 3
#define FILE_CONTAINER_DIRECTORY 4
#define FILE_MASTER_KEY 5
#define FILE_SMARTCARD_DIRECTORY 6

std::list<CspContainer*> m_containers;

#ifdef _DEBUG
//if defined do not enable smart card transaction
// usefull for debugging and bypass the 1,5 second CPU timeout in SC transaction ...
#define NO_TRANSACTION 1
#endif _DEBUG

CspContainer::CspContainer()
{
	m_hProv = NULL;
	m_VerifyContext = FALSE;
	m_AllowUI = TRUE;
	m_szContainerName[0] = '\0';
	m_szReader[0] = '\0';
	m_hKey = NULL;
	m_containers.push_front(this);
	m_hContext = NULL;
	m_hCard = NULL;
	m_dwKeySpec = 0;
	m_szPinPROMPT = NULL;
	m_szUIPROMPT = NULL;
	BOOL fReturn = CryptAcquireContext(&m_hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
	if (!fReturn)
	{
		DWORD dwError = GetLastError();
		Trace(TRACE_LEVEL_ERROR, L"CryptAcquireContext failed 0x%08X", dwError);
	}
}

CspContainer::~CspContainer()
{
	Trace(TRACE_LEVEL_VERBOSE, L"free hash and keys");
	std::list<ContainerKeyHandle*>::const_iterator it1 (m_keyHandles.begin());
	for(;it1!=m_keyHandles.end();++it1) 
	{
		ContainerKeyHandle* handle = *(it1);
		if (handle->m_dwKeySpec == 0)
			CryptDestroyKey(handle->m_hKey);
		delete handle;
	}
	std::list<ContainerHashHandle*>::const_iterator it2 (m_hashHandles.begin());
	for(;it2!=m_hashHandles.end();++it2) 
	{
		ContainerHashHandle* handle = *(it2);
		CryptDestroyHash(handle->m_hHash);
		delete handle;
	}
	if (m_szUIPROMPT)
		free (m_szUIPROMPT);
	if (m_szPinPROMPT)
		free (m_szPinPROMPT);
	if (m_hKey)
		CryptDestroyKey(m_hKey);
	if (m_hProv)
	{
		if (!CryptReleaseContext(m_hProv, 0))
		{
			Trace(TRACE_LEVEL_ERROR, L"CryptReleaseContext failed 0x%08X", GetLastError());
		}
		m_hProv = 0;
	}
	if (m_Card)
		delete m_Card;
	if (m_hCard) SCardDisconnect(m_hCard, SCARD_LEAVE_CARD);
	if (m_hContext) SCardReleaseContext(m_hContext);
}

BOOL CleanOpenPGPCardv2Data();
BOOL CspContainer::Clean()
{
	if (!CleanPinCache()) return FALSE;
	if (!CleanProviders()) return FALSE;
	if (!CleanOpenPGPCardv2Data()) return FALSE;
	return TRUE;
}

_Ret_maybenull_ HCRYPTHASH CspContainer::GetHash(__in HCRYPTHASH hHash)
{
	if (!hHash) 
	{
		return NULL;
	}
	std::list<ContainerHashHandle*>::const_iterator it (m_hashHandles.begin());
	for(;it!=m_hashHandles.end();++it) 
	{
		if (((HCRYPTHASH)(ContainerHashHandle*)(*it)) == hHash)
		{
			return (*it)->m_hHash;
		}
	}
	Trace(TRACE_LEVEL_ERROR, L"Hash 0x%Ix not found", hHash);
	SetLastError(NTE_BAD_UID);
	return NULL;
}
_Ret_maybenull_ HCRYPTKEY CspContainer::GetKey(__in HCRYPTKEY hKey, __out_opt PDWORD pdwKeySpec)
{
	if (!hKey) 
	{
		if (pdwKeySpec)
				*pdwKeySpec = 0;
		return NULL;
	}
	std::list<ContainerKeyHandle*>::const_iterator it (m_keyHandles.begin());
	for(;it!=m_keyHandles.end();++it) 
	{
		if (((HCRYPTKEY)(ContainerKeyHandle*)(*it)) == hKey)
		{
			if (pdwKeySpec)
				*pdwKeySpec = (*it)->m_dwKeySpec;
			if ((*it)->m_dwKeySpec == m_dwKeySpec)
			{
				Trace(TRACE_LEVEL_VERBOSE, L"GetKey returns hKey 0x%Ix %d", m_hKey, m_dwKeySpec);
				return m_hKey;
			}
			Trace(TRACE_LEVEL_VERBOSE, L"GetKey returns hKey 0x%Ix no rsa", (*it)->m_hKey);
			return (*it)->m_hKey;
		}
	}
	Trace(TRACE_LEVEL_ERROR, L"Key 0x%Ix not found", hKey);
	if (pdwKeySpec)
		*pdwKeySpec = 0;
	SetLastError(NTE_BAD_UID);
	return NULL;
}


// the string must be freed using RpcStringFree
PSTR GetUniqueIDString()
{
	UUID pUUID;
	PSTR sTemp = NULL;
	RPC_STATUS hr;
	DWORD dwError = 0;
	hr = UuidCreate(&pUUID);
	if (hr == RPC_S_OK || hr == RPC_S_UUID_LOCAL_ONLY)
	{
		hr = UuidToStringA(&pUUID, ( RPC_CSTR *)&sTemp); 
		if (hr != RPC_S_OK)
		{
			Trace(TRACE_LEVEL_ERROR,L"UuidToString 0x%08x",hr);
			dwError = HRESULT_CODE(hr);
		}
	}
	else
	{
		Trace(TRACE_LEVEL_ERROR,L"UuidCreate 0x%08x",hr);
		dwError = HRESULT_CODE(hr);
	}
	SetLastError(dwError);
	return sTemp;
}

_Ret_maybenull_ CspContainer* CspContainer::Create(PCSTR szReader, PCSTR szContainer, BOOL allowUI, BOOL  bMachineKeySet)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	PSTR szGuid = NULL;
	CspContainer* container = NULL;
	__try
	{
		container = CspContainer::Allocate();
		if (!container)
		{
			dwError = NTE_NO_MEMORY;
			Trace(TRACE_LEVEL_ERROR,L"NTE_NO_MEMORY");
			__leave;
		}
		// generate name if not exists
		if (!szContainer)
		{
			szGuid = GetUniqueIDString();
			if (!szGuid)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR,L"GetUniqueIDString failed 0x%08X", dwError);
				__leave;
			}
			szContainer = szGuid;
		}
		if (!container->CreateContainer(szReader, szContainer, allowUI))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"CreateContainer failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (szGuid) RpcStringFree((RPC_WSTR *) &szGuid);
		if (!fReturn && container)
		{
			container->Unload();
			container = NULL;
		}
	}
	SetLastError(dwError);
	return container;
}

BOOL CspContainer::AskForSmartCardReader()
{
	CHAR szCard[256] = {0};
	m_szReader[0] = 0;
	OPENCARDNAME_EXA data = {sizeof(data), 0};
	data.hSCardContext = m_hContext;
	GetHWND(&data.hwndOwner);
	data.dwFlags = SC_DLG_FORCE_UI;
	//data.lpstrSearchDesc = m_szUIPROMPT;
	data.nMaxRdr = MAX_READER_NAME;
	data.lpstrRdr = m_szReader;
	data.lpstrCard = szCard;
	data.nMaxCard = ARRAYSIZE(szCard);
	DWORD dwError = SCardUIDlgSelectCardA(&data);
	SetLastError(dwError);
	return dwError == 0;
}

BOOL CspContainer::CreateContainer(__in_opt PCSTR szReaderGiven, __in PCSTR szContainer, __in BOOL allowUI)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	DWORD dwProtocol = 0;
	DWORD cch = SCARD_AUTOALLOCATE;
	PSTR pmszReaders = NULL;
	PSTR szCurrentReader = NULL;
	CHAR szPin[MAX_PIN_SIZE];
	BOOL fEndTransaction = FALSE;
	__try
	{
		Trace(TRACE_LEVEL_INFO, L"Trying to create the container %S", szContainer);
		if (szContainer == NULL || szContainer[0] == 0)
		{
			Trace(TRACE_LEVEL_ERROR,L"NULL container name");
			dwError = NTE_INVALID_PARAMETER;
			__leave;
		}
		dwError = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &m_hContext);
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR,L"SCardEstablishContext failed 0x%08X", dwError);
			__leave;
		}
		// reader name is submitted
		if (szReaderGiven)
		{
			strcpy_s(m_szReader, MAX_READER_NAME, szReaderGiven);
			dwError = SCardConnectA(m_hContext, m_szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &m_hCard, &dwProtocol);
			if (dwError)
			{
				Trace(TRACE_LEVEL_ERROR,L"SCardConnectA failed 0x%08X", dwError);
				__leave;
			}
			if (!StartTransaction())
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
				__leave;
			}
			fEndTransaction = TRUE;
			m_Card = CreateContext();
			if (!m_Card)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
				__leave;
			}
			// set key in locatecontainer
			if (LocateContainer(szContainer))
			{
				// already exists
				dwError = NTE_EXISTS;
				Trace(TRACE_LEVEL_ERROR,L"container %S NTE_EXISTS", szContainer);
				__leave;
			}
		}
		else
		{
			// identity a reader
			dwError = SCardListReadersA(m_hContext,
                           NULL,
                           (LPSTR)&pmszReaders,
                           &cch );
			if (dwError || !pmszReaders)
			{
				Trace(TRACE_LEVEL_ERROR,L"SCardListReadersA failed 0x%08X", dwError);
				__leave;
			}
			szCurrentReader = pmszReaders;
			while('\0' != *szCurrentReader)
			{
				dwError = SCardConnectA(m_hContext, szCurrentReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &m_hCard, &dwProtocol);
				if (dwError)
				{
					Trace(TRACE_LEVEL_INFO, L"reader %S is empty 0x%08X", szCurrentReader, dwError);
					szCurrentReader = szCurrentReader + strlen(szCurrentReader) + 1;
					if (m_Card) delete m_Card;
					m_Card = NULL;
					if (m_hCard) SCardDisconnect(m_hCard, SCARD_LEAVE_CARD);
					m_hCard = NULL;
					continue;
				}
				if (!StartTransaction())
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
					__leave;
				}
				fEndTransaction = TRUE;
				m_Card = CreateContext();
				if (!m_Card)
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
					__leave;
				}
				// set key in locatecontainer
				if (LocateContainer(szContainer))
				{
					dwError = NTE_EXISTS;
					Trace(TRACE_LEVEL_ERROR,L"container %S NTE_EXISTS in reader %S", szContainer, szCurrentReader);
					__leave;
				} 
				// handle multiple smart card with the same container name ?
				strcpy_s(m_szReader, MAX_READER_NAME, szCurrentReader);
				break;
			}
			if (m_szReader[0] == 0)
			{
				Trace(TRACE_LEVEL_ERROR, L"unable to find a valid reader containing the container - empty ?");
				if (!m_AllowUI)
				{
					dwError = NTE_UI_REQUIRED;
					__leave;
				}
				if (!AskForSmartCardReader())
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR, L"AskForSmartCardReader failed 0x%08X", dwError);
					__leave;
				}
				dwError = SCardConnectA(m_hContext, m_szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &m_hCard, &dwProtocol);
				if (dwError)
				{
					Trace(TRACE_LEVEL_INFO, L"reader %S is empty 0x%08X", m_szReader, dwError);
					__leave;
				}
				m_Card = CreateContext();
				if (!m_Card)
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR,L"CreateContext failed 0x%08X", dwError);
					__leave;
				}
				// set key in locatecontainer
				if (LocateContainer(szContainer))
				{
					dwError = NTE_EXISTS;
					Trace(TRACE_LEVEL_ERROR,L"container %S NTE_EXISTS in reader %S", szContainer, szCurrentReader);
					__leave;
				} 
			}
			//OK
		}

		strcpy_s(m_szContainerName, MAX_CONTAINER_NAME, szContainer);

		m_AllowUI = allowUI;
		fReturn = TRUE;
	}
	__finally
	{
		if (fEndTransaction)
			EndTransaction(0, FALSE);
		if (!fReturn)
		{
			if (m_Card)
			{
				delete m_Card;
				m_Card = NULL;
			}
		}
		SecureZeroMemory(szPin, sizeof(szPin));
	}
	SetLastError(dwError);
	return fReturn;
}
				

_Ret_maybenull_ CspContainer* CspContainer::Load(PCSTR szReader, PCSTR szContainer, BOOL allowUI, BOOL  bMachineKeySet, BOOL fVerifyContext)
{
	DWORD dwError = 0;
	CspContainer* container = NULL;
	__try
	{
		container = CspContainer::Allocate();
		if (!container)
		{
			dwError = NTE_NO_MEMORY;
			Trace(TRACE_LEVEL_ERROR,L"NTE_NO_MEMORY");
			__leave;
		}
		if (!container->LoadContainer(szReader, szContainer, allowUI, fVerifyContext))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
			delete container;
			container = NULL;
			__leave;
		}
	}
	__finally
	{
	}
	SetLastError(dwError);
	return container;
}

BOOL CspContainer::LocateContainer(__in_opt PCSTR szContainer)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	TCHAR szPath[MAX_PATH] = TEXT("");
	__try
	{
		if (m_Card == NULL)
		{
			dwError = ERROR_INTERNAL_ERROR;
			Trace(TRACE_LEVEL_ERROR, L"Defensive programming: Card NULL in LocateContainer");
			__leave;
		}
		Trace(TRACE_LEVEL_VERBOSE, L"calling LocateContainer on card");
		fReturn = m_Card->LocateContainer(szContainer, &m_dwCardContainerId);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"LocateContainer returned 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CspContainer::LoadContainer(__in_opt PCSTR szReaderGiven, __in_opt PCSTR szContainer, __in BOOL allowUI, __in BOOL fVerifyContext)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	DWORD dwProtocol = 0;
	DWORD cch = SCARD_AUTOALLOCATE;
	PSTR pmszReaders = NULL;
	PSTR szCurrentReader = NULL;
	BOOL fLoadDefaultOptionalContainer = FALSE;
	PBYTE pPubKey = NULL;
	BOOL fEndTransaction = FALSE;
	__try
	{
		m_AllowUI = allowUI;
		m_VerifyContext = fVerifyContext;
		Trace(TRACE_LEVEL_INFO, L"Trying to load the container %S", (szContainer?szContainer : "<<DEFAULT>>"));
		dwError = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &m_hContext);
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR,L"SCardEstablishContext failed 0x%08X", dwError);
			__leave;
		}
		// reader name is submitted
		if (szReaderGiven)
		{
			strcpy_s(m_szReader, MAX_READER_NAME, szReaderGiven);
			dwError = SCardConnectA(m_hContext, m_szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &m_hCard, &dwProtocol);
			if (dwError)
			{
				Trace(TRACE_LEVEL_ERROR,L"SCardConnectA failed 0x%08X", dwError);
				__leave;
			}
			if (!StartTransaction())
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
				__leave;
			}
			fEndTransaction = TRUE;
			m_Card = CreateContext();
			if (!m_Card)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
				__leave;
			}
			if (!LocateContainer(szContainer))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR,L"LocateContainer failed 0x%08X", dwError);
				__leave;
			}
			//OK
		}
		else
		{
			// identity a reader
			dwError = SCardListReadersA(m_hContext,
                           NULL,
                           (LPSTR)&pmszReaders,
                           &cch );
			if (dwError || !pmszReaders)
			{
				Trace(TRACE_LEVEL_ERROR,L"SCardListReadersA failed 0x%08X", dwError);
				__leave;
			}
			szCurrentReader = pmszReaders;
			while('\0' != *szCurrentReader)
			{
				dwError = SCardConnectA(m_hContext, szCurrentReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &m_hCard, &dwProtocol);
				if (dwError)
				{
					Trace(TRACE_LEVEL_INFO, L"reader %S is empty", szCurrentReader);
					szCurrentReader = szCurrentReader + strlen(szCurrentReader) + 1;
					continue;
				}
				if (!StartTransaction())
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
					__leave;
				}
				fEndTransaction = TRUE;
				m_Card = CreateContext();
				if (!m_Card)
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
					__leave;
				}
				if (!LocateContainer(szContainer))
				{
					Trace(TRACE_LEVEL_INFO, L"couldn't locate container in reader %S", szCurrentReader);
					szCurrentReader = szCurrentReader + strlen(szCurrentReader) + 1;
					SCardEndTransaction(m_hCard, SCARD_LEAVE_CARD);
					delete m_Card;
					m_Card = NULL;
					SCardDisconnect(m_hCard, SCARD_LEAVE_CARD);
					m_hCard = NULL;
					fEndTransaction = FALSE;
					continue;
				} 
				// handle multiple smart card with the same container name ?
				strcpy_s(m_szReader, MAX_READER_NAME, szCurrentReader);
				break;
			}
			if (m_szReader[0] == 0)
			{
				Trace(TRACE_LEVEL_ERROR, L"unable to find a valid reader containing the container - empty ?");
				if (!szContainer && m_VerifyContext)
				{
					// special case with null container for query capabilities
					fLoadDefaultOptionalContainer = TRUE;
				}
				else
				{
					if (!m_AllowUI)
					{
						dwError = NTE_SILENT_CONTEXT;
						Trace(TRACE_LEVEL_ERROR, L"NTE_SILENT_CONTEXT");
						__leave;
					}
					if (!AskForSmartCardReader())
					{
						dwError = GetLastError();
						Trace(TRACE_LEVEL_ERROR, L"AskForSmartCardReader failed 0x%08X", dwError);
						__leave;
					}
					dwError = SCardConnectA(m_hContext, m_szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &m_hCard, &dwProtocol);
					if (dwError)
					{
						Trace(TRACE_LEVEL_INFO, L"reader %S is empty 0x%08X", m_szReader, dwError);
						__leave;
					}
					if (!StartTransaction())
					{
						dwError = GetLastError();
						Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
						__leave;
					}
					fEndTransaction = TRUE;
					// set key in locatecontainer
					m_Card = CreateContext();
					if (!m_Card)
					{
						dwError = GetLastError();
						Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
						__leave;
					}
					if (!LocateContainer(szContainer))
					{
						dwError = NTE_KEYSET_NOT_DEF;
						Trace(TRACE_LEVEL_ERROR,L"container %S NTE_EXISTS in reader %S", szContainer, szCurrentReader);
						__leave;
					} 
				}
			}
			//OK
		}

		if (fLoadDefaultOptionalContainer)
		{
			Trace(TRACE_LEVEL_INFO, L"special case : default container with verify context when non existing");
		}
		else
		{
			if (!szContainer)
			{
				if (!m_Card->GetContainerName(m_dwCardContainerId, m_szContainerName))
				{
					dwError = NTE_KEYSET_NOT_DEF;
					Trace(TRACE_LEVEL_ERROR,L"unable to load the container name");
					__leave;
				}
			}
			else
			{
				strcpy_s(m_szContainerName, MAX_CONTAINER_NAME, szContainer);
			}
			Trace(TRACE_LEVEL_VERBOSE, L"load container %S", m_szContainerName);
			Trace(TRACE_LEVEL_VERBOSE, L"load in reader %S", m_szReader);
			DWORD dwSize = 0;
			if (!m_Card->GetPublicKey(m_dwCardContainerId, &pPubKey, &dwSize))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR,L"GetPublicKey failed 0x%08X", dwError);
				__leave;
			}
			if (!CryptImportKey(m_hProv, pPubKey, dwSize, NULL, NULL, &m_hKey))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR,L"CryptImportKey failed 0x%08X", dwError);
				__leave;
			}
			m_dwKeySpec = (((BLOBHEADER*) pPubKey)->aiKeyAlg == CALG_RSA_KEYX ? AT_KEYEXCHANGE : AT_SIGNATURE);
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pPubKey)
			free(pPubKey);
		if (m_hContext && pmszReaders) SCardFreeMemory( m_hContext, pmszReaders );
		if (fEndTransaction)
			EndTransaction(0, FALSE);
		if (!fReturn)
		{
			if (m_Card)
			{
				delete m_Card;
				m_Card = NULL;
			}
		}
	}
	SetLastError(dwError);
	return fReturn;
}


BOOL CspContainer::Remove(PCSTR szReader, PCSTR szContainer, BOOL allowUI, BOOL  bMachineKeySet)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	CspContainer* container = NULL;
	__try
	{
		container = CspContainer::Allocate();
		if (!container)
		{
			dwError = NTE_NO_MEMORY;
			Trace(TRACE_LEVEL_ERROR,L"NTE_NO_MEMORY");
			__leave;
		}
		if (!container->RemoveContainer(szReader, szContainer, allowUI))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"RemoveContainer failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (container)
		{
			container->Unload();
			container = NULL;
		}
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CspContainer::RemoveContainer(__in_opt PCSTR szReaderGiven, __in_opt PCSTR szContainer, __in BOOL allowUI)
{
	DWORD dwError = 0;
	CspContainer* container = NULL;
	// double null terminated
	WCHAR szPath[MAX_PATH] = {0};
	BOOL fReturn = FALSE;
	DWORD dwProtocol = 0;
	PSTR szCurrentReader = NULL;
	PSTR pmszReaders = NULL;
	DWORD cch = SCARD_AUTOALLOCATE;
	BYTE Key[KEY_SIZE] = {0};
	BOOL fEndTransaction = FALSE;
	BOOL fAuthenticated = FALSE;
	DWORD dwPinId = 0;
	__try
	{
		dwError = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &m_hContext);
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR,L"SCardEstablishContext failed 0x%08X", dwError);
			__leave;
		}
		// reader name is submitted
		if (szReaderGiven)
		{
			dwError = SCardConnectA(m_hContext, szReaderGiven, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &m_hCard, &dwProtocol);
			if (dwError)
			{
				Trace(TRACE_LEVEL_ERROR,L"SCardConnectA failed 0x%08X", dwError);
				__leave;
			}
			m_Card = CreateContext();
			if (!m_Card)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
				__leave;
			}
			if (!LocateContainer(szContainer))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR,L"LocateContainer failed 0x%08X", dwError);
				__leave;
			}
			//OK
		}
		else
		{
			// identity a reader
			dwError = SCardListReadersA(m_hContext,
                           NULL,
                           (LPSTR)&pmszReaders,
                           &cch );
			if (dwError || !pmszReaders)
			{
				Trace(TRACE_LEVEL_ERROR,L"SCardListReadersA failed 0x%08X", dwError);
				__leave;
			}
			szCurrentReader = pmszReaders;
			while('\0' != *szCurrentReader)
			{
				dwError = SCardConnectA(m_hContext, szCurrentReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &m_hCard, &dwProtocol);
				if (dwError)
				{
					Trace(TRACE_LEVEL_INFO, L"reader %S is empty", szCurrentReader);
					szCurrentReader = szCurrentReader + strlen(szCurrentReader) + 1;
					continue;
				}
				m_Card = CreateContext();
				if (!m_Card)
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
					__leave;
				}
				if (!LocateContainer(szContainer))
				{
					Trace(TRACE_LEVEL_INFO, L"couldnt locate container in reader %S", szCurrentReader);
					szCurrentReader = szCurrentReader + strlen(szCurrentReader) + 1;
					SCardDisconnect(m_hCard, SCARD_LEAVE_CARD);
					m_hCard = NULL;
					continue;
				} 
				break;
			}
			if ('\0' == *szCurrentReader)
			{
				Trace(TRACE_LEVEL_ERROR, L"unable to find a valid reader containing the container - empty ?");
				dwError = NTE_KEYSET_NOT_DEF;
				__leave;
			}
			//OK
		}
		if (!GetPIN(PIN_OPERATION_DELETE, &dwPinId))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetPIN failed 0x%08X", dwError);
			__leave;
		}
		if (!AskPinToUserIfNeeded(GetParentHwnd(), dwPinId))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"StartTransaction failed 0x%08X", dwError);
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
		if (!m_Card->RemoveKey(m_dwCardContainerId))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"RemoveKey failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (fEndTransaction)
			EndTransaction(dwPinId, fAuthenticated);
		if (m_hCard) 
		{
			SCardDisconnect(m_hCard, SCARD_LEAVE_CARD);
			m_hCard = NULL;
		}
		if (m_hContext) 
		{
			if (pmszReaders) SCardFreeMemory( m_hContext, pmszReaders );	
			SCardReleaseContext(m_hContext);
			m_hContext = NULL;
		}
		if (!fReturn)
		{
			if (m_Card)
			{
				delete m_Card;
				m_Card = NULL;
			}
		}
	}
	SetLastError(dwError);
	return fReturn;
}

_Ret_maybenull_ CspContainer* CspContainer::GetContainerFromHandle(HCRYPTPROV handle)
{
 	if (!handle)
	{
		Trace(TRACE_LEVEL_ERROR, L"handle NULL");
		SetLastError( ERROR_INVALID_PARAMETER );
		return NULL;
	}
	std::list<CspContainer*>::const_iterator it (m_containers.begin());
	for(;it!=m_containers.end();++it) 
	{
		if ((HCRYPTPROV)((CspContainer*)(*it)) == handle)
		{
			return (CspContainer*) handle;
		}
	}
	Trace(TRACE_LEVEL_ERROR, L"handle 0x%Ix unknown", handle);
	SetLastError( NTE_KEYSET_NOT_DEF );
	return NULL;
}

BOOL CspContainer::CleanProviders()
{
	std::list<CspContainer*>::const_iterator it (m_containers.begin());
	while (it!=m_containers.end()) 
	{
		//delete (*it);
		it = m_containers.erase(it);
	}
	return TRUE;
}

BOOL CspContainer::Unload()
{
	Trace(TRACE_LEVEL_VERBOSE, L"free this");
	m_containers.remove(this);
	delete this;
	return TRUE;
}

_Success_(return) BOOL CspContainer::GetProvParam(
						_In_    DWORD dwParam,
						_Out_writes_bytes_to_opt_(*pdwDataLen, *pdwDataLen) LPBYTE  pbData,
						_Inout_  DWORD *pdwDataLen,
						_In_    DWORD  dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	PROV_ENUMALGS_EX* ppEnumAlgEx = NULL;
	__try
	{
		if (!pdwDataLen)
		{
			dwError = ERROR_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_ERROR, L"pdwDataLen NULL");
			__leave;
		}
		switch(dwParam)
		{
		case PP_CHANGE_PASSWORD:
			fReturn = ChangePin();
			if (!fReturn)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"ChangePin failed 0x%08X", dwError);
				__leave;
			}
			break;
		case PP_CONTAINER:
		case PP_UNIQUE_CONTAINER:
			Trace(TRACE_LEVEL_VERBOSE, L"PP_CONTAINER");
			if (*pdwDataLen < strlen(m_szContainerName) + 1)
			{
				Trace(TRACE_LEVEL_ERROR, L"*pdwDataLen = %d", *pdwDataLen);
				*pdwDataLen = (DWORD) strlen(m_szContainerName) + 1;
				dwError = ERROR_MORE_DATA;
				if (pbData)
				{
					__leave;
				}
			}
			*pdwDataLen = (DWORD) strlen(m_szContainerName) + 1;
			if (pbData)
			{
				strcpy_s((PSTR)pbData, *pdwDataLen, m_szContainerName);
			}
			fReturn = TRUE;
			break;

		case PP_ENUMCONTAINERS:
			Trace(TRACE_LEVEL_VERBOSE, L"PP_ENUMCONTAINERS");
			fReturn = EnumerateContainer((PSTR) pbData, pdwDataLen, dwFlags);
			if (!fReturn)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"EnumerateContainer failed 0x%08X flag 0x%08X", dwError, dwFlags);
				__leave;
			}
			break;
		case PP_USER_CERTSTORE :
			Trace(TRACE_LEVEL_VERBOSE, L"PP_USER_CERTSTORE");
			if (*pdwDataLen < sizeof(HCERTSTORE))
			{
				Trace(TRACE_LEVEL_ERROR, L"*pdwDataLen = %d", *pdwDataLen);
				*pdwDataLen =  sizeof(HCERTSTORE);
				dwError = ERROR_MORE_DATA;
				if (pbData)
				{
					__leave;
				}
			}
			*pdwDataLen =  sizeof(HCERTSTORE);
			if (pbData)
			{
				fReturn = GetUserStore(TEXT(CSPNAME), (HCERTSTORE*)pbData);
				if (!fReturn)
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR, L"GetUserStore failed 0x%08X", dwError);
					__leave;
				}
			}
			else
			{
				fReturn = TRUE;
			}
			break;
		case PP_SMARTCARD_READER:
			Trace(TRACE_LEVEL_VERBOSE, L"PP_SMARTCARD_READER");
			if (*pdwDataLen < strlen(m_szReader)+1)
			{
				Trace(TRACE_LEVEL_ERROR, L"*pdwDataLen = %d", *pdwDataLen);
				*pdwDataLen = (DWORD) strlen(m_szReader)+1;
				dwError = ERROR_MORE_DATA;
				if (pbData)
				{
					__leave;
				}
			}
			*pdwDataLen = (DWORD) strlen(m_szReader)+1;
			if (pbData)
			{
				strcpy_s((PSTR)pbData,*pdwDataLen, m_szReader);
			}
			fReturn = TRUE;
			break;
		case PP_SMARTCARD_GUID:
			Trace(TRACE_LEVEL_VERBOSE, L"PP_SMARTCARD_GUID");
			if (*pdwDataLen < sizeof(GUID))
			{
				Trace(TRACE_LEVEL_ERROR, L"*pdwDataLen = %d", *pdwDataLen);
				*pdwDataLen = sizeof(GUID);
				dwError = ERROR_MORE_DATA;
				if (pbData)
				{
					__leave;
				}
			}
			*pdwDataLen = sizeof(GUID);
			if (pbData)
			{
				GUID* guid = (GUID*) pbData;
				ZeroMemory(pbData, sizeof(GUID));
				memcpy(pbData, m_Key, min(KEY_SIZE, sizeof(GUID)));
			}
			fReturn = TRUE;
			break;
		case PP_ENUMALGS:
		case PP_ENUMEX_SIGNING_PROT:
		case PP_KEYX_KEYSIZE_INC:
		case PP_SIG_KEYSIZE_INC:
		case PP_PROVTYPE:
			Trace(TRACE_LEVEL_VERBOSE, L"PP_ENUMALGS PP_ENUMEX_SIGNING_PROT PP_KEYX_KEYSIZE_INC PP_PROVTYPE");
			fReturn = CryptGetProvParam(m_hProv, dwParam, pbData, pdwDataLen, dwFlags);
			if (!fReturn)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"CryptGetProvParam failed 0x%08X with dwParam 0x%08X", dwError, dwParam);
				__leave;
			}
			break;
		case PP_ENUMALGS_EX:
			Trace(TRACE_LEVEL_VERBOSE, L"PP_ENUMALGS_EX");
			fReturn = CryptGetProvParam(m_hProv, dwParam, pbData, pdwDataLen, dwFlags);
			if (!fReturn)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"CryptGetProvParam failed 0x%08X with dwParam 0x%08X", dwError, dwParam);
				__leave;
			}
			ppEnumAlgEx = (PROV_ENUMALGS_EX*) pbData;
			if (m_Card && (ppEnumAlgEx->aiAlgid == CALG_RSA_SIGN || ppEnumAlgEx->aiAlgid == CALG_RSA_KEYX))
			{
				if (!m_Card->GetKeyLength(&(ppEnumAlgEx->dwDefaultLen),&(ppEnumAlgEx->dwMinLen),&(ppEnumAlgEx->dwMaxLen)))
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR, L"GetKeyLength failed 0x%08X", dwError);
					__leave;
				}
			}
			break;
		case PP_IMPTYPE:
			Trace(TRACE_LEVEL_VERBOSE, L"PP_IMPTYPE");
			if (*pdwDataLen < sizeof(DWORD))
			{
				Trace(TRACE_LEVEL_ERROR, L"*pdwDataLen = %d", *pdwDataLen);
				*pdwDataLen = sizeof(DWORD);
				dwError = ERROR_MORE_DATA;
				if (pbData)
				{
					__leave;
				}
			}
			*pdwDataLen = sizeof(DWORD);
			if (pbData)
			{
				*((PDWORD)pbData)= CRYPT_IMPL_MIXED;
			}
			fReturn = TRUE;
			break;
		case PP_KEYSPEC:
			Trace(TRACE_LEVEL_VERBOSE, L"PP_KEYSPEC");
			if (*pdwDataLen < sizeof(DWORD))
			{
				Trace(TRACE_LEVEL_ERROR, L"*pdwDataLen = %d", *pdwDataLen);
				*pdwDataLen = sizeof(DWORD);
				dwError = ERROR_MORE_DATA;
				__leave;
			}
			*pdwDataLen = sizeof(DWORD);
			if (pbData)
			{
				*((PDWORD)pbData)= AT_KEYEXCHANGE | AT_SIGNATURE;
			}
			fReturn = TRUE;
			break;
		case PP_KEYSET_TYPE:
			Trace(TRACE_LEVEL_VERBOSE, L"PP_KEYSET_TYPE");
			if (*pdwDataLen < sizeof(DWORD))
			{
				Trace(TRACE_LEVEL_ERROR, L"*pdwDataLen = %d", *pdwDataLen);
				*pdwDataLen = sizeof(DWORD);
				dwError = ERROR_MORE_DATA;
				if (pbData)
				{
					__leave;
				}
			}
			*pdwDataLen = sizeof(DWORD);
			if (pbData)
			{
				*((PDWORD)pbData) = CRYPT_MACHINE_KEYSET;
			}
			fReturn = TRUE;
			break;
		case PP_NAME:
			Trace(TRACE_LEVEL_VERBOSE, L"PP_NAME");
			if (*pdwDataLen < strlen(CSPNAME)+1)
			{
				Trace(TRACE_LEVEL_ERROR, L"*pdwDataLen = %d", *pdwDataLen);
				*pdwDataLen = (DWORD) strlen(CSPNAME)+1;
				dwError = ERROR_MORE_DATA;
				if (pbData)
				{
					__leave;
				}
			}
			*pdwDataLen = (DWORD) strlen(CSPNAME)+1;
			if (pbData)
			{
				strcpy_s((PSTR)pbData,*pdwDataLen, CSPNAME);
			}
			fReturn = TRUE;
			break;
		case PP_VERSION:
			Trace(TRACE_LEVEL_VERBOSE, L"PP_VERSION");
			if (*pdwDataLen < sizeof(DWORD))
			{
				Trace(TRACE_LEVEL_ERROR, L"*pdwDataLen = %d", *pdwDataLen);
				*pdwDataLen = sizeof(DWORD);
				dwError = ERROR_MORE_DATA;
				if (pbData)
				{
					__leave;
				}
			}
			*pdwDataLen = sizeof(DWORD);
			if (pbData)
			{
				*((PDWORD)pbData)= 0x100;
			}
			fReturn = TRUE;
			break;
		default:
			dwError = NTE_BAD_TYPE;
			Trace(TRACE_LEVEL_ERROR, L"dwParam = %d not supported", dwParam);
			__leave;
		}
	}
	__finally
	{
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

BOOL CspContainer::SetProvParam(
						__in    DWORD dwParam,
						__in     CONST  BYTE *pbData,
						__in    DWORD  dwFlags)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	DWORD dwPinId = 0;
	__try
	{
		switch(dwParam)
		{
		// this case made by cryptoapi directly
		// case PP_CLIENT_HWND:
			
		case PP_ADMIN_PIN :
		case PP_KEYEXCHANGE_PIN:
		case PP_SIGNATURE_PIN:

			if (m_Card != NULL)
			{
				Trace(TRACE_LEVEL_VERBOSE, L"set pin");
				fReturn = SetPin(dwParam, (PSTR) pbData);
				if (!fReturn)
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR, L"SetPin failed 0x%08X", dwError);
					__leave;
				}
			}
			break;
		case PP_PIN_PROMPT_STRING:
			if (m_szPinPROMPT)
				free (m_szPinPROMPT);
			m_szPinPROMPT = DuplicateUnicodeString((PWSTR) pbData);
			fReturn = TRUE;
			break;
		case PP_UI_PROMPT:
			if (m_szUIPROMPT)
				free (m_szUIPROMPT);
			m_szUIPROMPT = DuplicateUnicodeString((PWSTR) pbData);
			fReturn = TRUE;
			break;
		case PP_USE_HARDWARE_RNG:
			dwError = ERROR_NOT_SUPPORTED;
			Trace(TRACE_LEVEL_ERROR, L"PP_USE_HARDWARE_RNG ERROR_NOT_SUPPORTED");
			__leave;
		default:
			dwError = NTE_BAD_TYPE;
			Trace(TRACE_LEVEL_ERROR, L"dwParam = %d not supported", dwParam);
			__leave;
		}
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CspContainer::GenRandom(
					_In_                    DWORD   dwLen,
					_Inout_updates_bytes_(dwLen)   BYTE    *pbBuffer)
{
	DWORD dwError = 0;
	BOOL fReturn = CryptGenRandom(m_hProv, dwLen, pbBuffer);
	if (!fReturn)
	{
		dwError = GetLastError();
		Trace(TRACE_LEVEL_ERROR, L"CryptGenRandom failed 0x%08X", dwError);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CspContainer::CreateHash(
					__in     ALG_ID  Algid,
					__in     HCRYPTKEY   hKey,
					__in     DWORD  dwFlags,
					__out     HCRYPTHASH  *phHash)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	HCRYPTHASH hHash = NULL;
	DWORD dwKeySpec = 0;
	__try
	{
		if (dwFlags)
		{
			dwError = NTE_BAD_FLAGS;
			Trace(TRACE_LEVEL_ERROR, L"dwFlags = %d not null", dwFlags);
			__leave;
		}
		HCRYPTKEY hMyKey = GetKey(hKey, &dwKeySpec);
		if (hKey && !hMyKey)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"key not null 0x%Ix and not found (0x%08X)", hKey, dwError);
			__leave;
		}
		fReturn = CryptCreateHash(m_hProv, Algid, hMyKey, dwFlags, &hHash);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CryptCreateHash failed 0x%08X", dwError);
			__leave;
		}
		ContainerHashHandle* hHandle = ContainerHashHandle::Create(hHash, (ContainerKeyHandle*)hKey, Algid);
		if (!hHandle)
		{
			dwError = NTE_NO_MEMORY;
			Trace(TRACE_LEVEL_ERROR, L"NTE_NO_MEMORY");
			__leave;
		}
		m_hashHandles.push_back(hHandle);
		*phHash = (HCRYPTHASH) hHandle;
		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			if (hHash) CryptDestroyHash(hHash);
		}
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CspContainer::HashData(
					__in     HCRYPTHASH  hHash,
					_In_reads_bytes_(dwDataLen)     CONST  BYTE *pbData,
					__in    DWORD dwDataLen,
					__in    DWORD  dwFlags)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	__try
	{
		HCRYPTHASH hMyHash = GetHash(hHash);
		if (!hMyHash)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetHash failed 0x%08X", dwError);
			__leave;
		}
		fReturn =  CryptHashData(hMyHash, pbData, dwDataLen, dwFlags);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CryptHashData failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}
BOOL CspContainer::HashSessionKey(
					__in     HCRYPTHASH  hHash,
					__in     HCRYPTKEY   hKey,
					__in    DWORD  dwFlags)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	__try
	{
		HCRYPTHASH hMyHash = GetHash(hHash);
		if (!hMyHash)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetHash failed 0x%08X", dwError);
			__leave;
		}
		HCRYPTKEY hMyKey = GetKey(hKey, NULL);
		if (!hMyKey)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKey failed 0x%08X", dwError);
			__leave;
		}
		fReturn = CryptHashSessionKey(hMyHash, hMyKey, dwFlags);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CryptHashSessionKey failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}
BOOL CspContainer::SignHash(
					__in     HCRYPTHASH  hHash,
					__in    DWORD  dwKeySpec,
					_In_opt_    LPCTSTR szDescription,
					__in    DWORD  dwFlags,
					_Out_writes_bytes_to_opt_(*pdwSigLen, *pdwSigLen) BYTE *pbSignature,
					_Inout_  DWORD       *pdwSigLen)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	DWORD dwPinId = (DWORD) -1;
	BOOL fEndTransaction = FALSE;
	BOOL fAuthenticated = FALSE;
	PWSTR szAlgorithm = NULL;
	PBYTE pbHash = NULL;
	__try
	{
		HCRYPTHASH hMyHash = GetHash(hHash);
		if (!hMyHash)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetHash failed 0x%08X", dwError);
			__leave;
		}
		if (dwKeySpec != m_dwKeySpec)
		{
			dwError = NTE_KEYSET_NOT_DEF;
			Trace(TRACE_LEVEL_ERROR, L"Invalid keyspec");
			__leave;
		}
		ALG_ID AlgId = 0;
		DWORD dwSize = sizeof(ALG_ID);
		if (!CryptGetHashParam(hMyHash, HP_ALGID, (PBYTE) &AlgId, &dwSize, 0))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CryptGetHashParam failed 0x%08X", dwError);
			__leave;
		}
		if (dwFlags == CRYPT_NOHASHOID)
		{
			szAlgorithm = NULL;
		}
		else if (dwFlags != 0)
		{
			dwError = NTE_NOT_SUPPORTED;
			Trace(TRACE_LEVEL_INFO, L"NTE_NOT_SUPPORTED dwFlags 0x%08X", dwFlags);
			__leave;
		}
		else
		{
			switch (AlgId)
			{
				case CALG_SHA1:
					szAlgorithm = BCRYPT_SHA1_ALGORITHM;
					break;
				case CALG_SHA_256:
					szAlgorithm = BCRYPT_SHA256_ALGORITHM;
					break;
				case CALG_SHA_384:
					szAlgorithm = BCRYPT_SHA384_ALGORITHM;
					break;
				case CALG_SHA_512:
					szAlgorithm = BCRYPT_SHA512_ALGORITHM;
					break;
				case CALG_SSL3_SHAMD5:
					szAlgorithm = NULL;
					break;
				default:
					dwError = NTE_BAD_ALGID;
					Trace(TRACE_LEVEL_ERROR, L"Unsupported Algid 0x%08X", AlgId);
					__leave;
			}
		}
		if (pbSignature == NULL)
		{
			// optimization
			DWORD dwKeySizeInBits, dwSize = sizeof(DWORD);
			if (!CryptGetKeyParam(m_hKey, KP_KEYLEN, (PBYTE) &dwKeySizeInBits, &dwSize, 0))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"CryptGetKeyParam failed 0x%08X", dwError);
				__leave;
			}
			*pdwSigLen = dwKeySizeInBits / 8;
			fReturn = TRUE;
			__leave;
		}
		DWORD dwHashSize = 0;
		dwSize = sizeof(DWORD);
		if (!CryptGetHashParam(hMyHash, HP_HASHSIZE, (PBYTE) &dwHashSize, &dwSize, 0))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CryptGetHashParam failed 0x%08X", dwError);
			__leave;
		}
		pbHash = (PBYTE) malloc(dwHashSize);
		if (!pbHash)
		{
			dwError = ERROR_OUTOFMEMORY;
			Trace(TRACE_LEVEL_ERROR, L"ERROR_OUTOFMEMORY");
			__leave;
		}
		if (!CryptGetHashParam(hMyHash, HP_HASHVAL, pbHash, &dwHashSize, 0))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CryptGetHashParam failed 0x%08X", dwError);
			__leave;
		}
		if (!GetPIN(PIN_OPERATION_SIGN, &dwPinId))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetPIN failed 0x%08X", dwError);
			__leave;
		}
		if (!AskPinToUserIfNeeded(GetParentHwnd(), dwPinId))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"StartTransaction failed 0x%08X", dwError);
			__leave;
		}
		if (!StartTransaction())
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"StartTransaction failed 0x%08X", dwError);
			__leave;
		}
		fEndTransaction = TRUE;
		if (!Authenticate(dwPinId))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"Authenticate failed 0x%08X", dwError);
			__leave;
		}
		fAuthenticated = TRUE;
		if (!SignData(szAlgorithm, pbHash, dwHashSize, pbSignature, pdwSigLen))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"SignHash failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pbHash)
			free(pbHash);
		if (fEndTransaction)
			EndTransaction(dwPinId, fAuthenticated);
	}
	SetLastError(dwError);
	return fReturn;
}
BOOL CspContainer::DestroyHash(
			        __in     HCRYPTHASH  hHash)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	__try
	{
		HCRYPTHASH hMyHash = GetHash(hHash);
		if (!hMyHash)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetHash failed 0x%08X", dwError);
			__leave;
		}
		m_hashHandles.remove((ContainerHashHandle*)hHash);
		delete (ContainerHashHandle*)hHash;
		fReturn = CryptDestroyHash(hMyHash);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CryptDestroyHash failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CspContainer::SetHashParam(
					__in     HCRYPTHASH  hHash,
					__in    DWORD dwParam,
					__in     CONST  BYTE *pbData,
					__in    DWORD  dwFlags)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	__try
	{
		HCRYPTHASH hMyHash = GetHash(hHash);
		if (!hMyHash)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetHash failed 0x%08X", dwError);
			__leave;
		}
		fReturn = CryptSetHashParam(hMyHash, dwParam, pbData, dwFlags);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CryptSetHashParam failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}
BOOL CspContainer::GetHashParam(
					__in     HCRYPTHASH  hHash,
					__in    DWORD dwParam,
					_Out_writes_bytes_to_opt_(*pdwDataLen, *pdwDataLen)  LPBYTE  pbData,
					__inout  LPDWORD pdwDataLen,
					__in    DWORD  dwFlags)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	__try
	{
		HCRYPTHASH hMyHash = GetHash(hHash);
		if (!hMyHash)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetHash failed 0x%08X", dwError);
			__leave;
		}
		fReturn = CryptGetHashParam(hMyHash, dwParam, pbData, pdwDataLen, dwFlags);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CryptSetHashParam failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CspContainer::GenKey(
					__in     ALG_ID  Algid,
					__in    DWORD  dwFlags,
					__out   HCRYPTKEY  *phKey)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	HCRYPTKEY hMyKey = NULL;
	ContainerKeyHandle* handle = NULL;
	PBYTE pPubKey = NULL;
	DWORD dwSize;
	DWORD dwBitlen;
	BOOL fEndTransaction = FALSE;
	BOOL fAuthenticated = FALSE;
	DWORD dwPinId = 0;
	HWND hWndParent = NULL;
	__try
	{
		if (Algid == AT_KEYEXCHANGE)
		{
			Algid = CALG_RSA_KEYX;
		}
		else if (Algid == AT_SIGNATURE)
		{
			Algid = CALG_RSA_SIGN;
		}
		if (Algid == CALG_RSA_KEYX || Algid == CALG_RSA_SIGN)
		{
			if (dwFlags & CRYPT_EXPORTABLE)
			{
				Trace(TRACE_LEVEL_ERROR, L"dwFlags CRYPT_EXPORTABLE 0x%08X", dwFlags);
				dwError = NTE_BAD_FLAGS;
				__leave;
			}
			dwBitlen = (dwFlags & 0xFFFF0000) >> 16;
			if (dwBitlen == 0)
			{
				dwBitlen = (RSA1024BIT_KEY*2) >> 16;
			}
			Trace(TRACE_LEVEL_INFO, L"Bit len = %d", dwBitlen >> 16);
			GetHWND(&hWndParent);
			if (!m_Card->GetKeyIdForNewKey(Algid, hWndParent, &m_dwCardContainerId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"GetKeyIdForNewKey failed 0x%08X", dwError);
				__leave;
			}
			if (!GetPIN(PIN_OPERATION_CREATE, &dwPinId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"GetPIN failed 0x%08X", dwError);
				__leave;
			}
			if (!AskPinToUserIfNeeded(GetParentHwnd(), dwPinId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"StartTransaction failed 0x%08X", dwError);
				__leave;
			} 
			if (!StartTransaction())
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"StartTransaction failed 0x%08X", dwError);
				__leave;
			}
			fEndTransaction = TRUE; 
			if (!Authenticate(dwPinId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"Authenticate failed 0x%08X", dwError);
				__leave;
			}
			fAuthenticated = TRUE;
			if ( Algid == m_dwKeySpec && m_hKey)
			{
				CryptDestroyKey(m_hKey);
				m_hKey = NULL;
			}
			Trace(TRACE_LEVEL_VERBOSE, L"before GenerateKey");
			if (!m_Card->GenerateKey(Algid, m_dwCardContainerId, dwBitlen))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"GenerateKey failed 0x%08X", dwError);
				__leave;
			}
			Trace(TRACE_LEVEL_VERBOSE, L"before SetContainerName");
			if (!m_Card->SetContainerName(m_szContainerName, m_dwCardContainerId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"RegisterAlias failed 0x%08X", dwError);
				__leave;
			}
			Trace(TRACE_LEVEL_VERBOSE, L"before GetPublicKey");
			if (!m_Card->GetPublicKey(m_dwCardContainerId, &pPubKey, &dwSize))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR,L"GetPublicKey failed 0x%08X", dwError);
				__leave;
			}
			if (!CryptImportKey(m_hProv, pPubKey, dwSize, NULL, NULL, &m_hKey))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR,L"CryptImportKey failed 0x%08X", dwError);
				__leave;
			}
			m_dwKeySpec = (((BLOBHEADER*) pPubKey)->aiKeyAlg == CALG_RSA_KEYX ? AT_KEYEXCHANGE : AT_SIGNATURE);
			handle = ContainerKeyHandle::Create(m_hKey, m_dwKeySpec);
			if (!handle)
			{
				dwError = NTE_NO_MEMORY;
				Trace(TRACE_LEVEL_ERROR, L"NTE_NO_MEMORY");
				__leave;
			}
		}
		else
		{
			if (!CryptGenKey(m_hProv, Algid, dwFlags, &hMyKey))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"CryptGenKey failed 0x%08X", dwError);
				__leave;
			}
			handle = ContainerKeyHandle::Create(hMyKey, 0);
			if (!handle)
			{
				dwError = NTE_NO_MEMORY;
				Trace(TRACE_LEVEL_ERROR, L"NTE_NO_MEMORY");
				__leave;
			}
		}
		m_keyHandles.push_back(handle);
		*phKey = (HCRYPTKEY) handle;
		fReturn = TRUE;
	}
	__finally
	{
		if (pPubKey)
			free(pPubKey);
		if (!fReturn)
		{
			if (hMyKey) CryptDestroyKey(hMyKey);
		}
		if (fEndTransaction)
			EndTransaction(dwPinId, fAuthenticated);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CspContainer::DeriveKey(
					__in     ALG_ID  Algid,
					__in     HCRYPTHASH  hHash,
					__in    DWORD  dwFlags,
					__out   HCRYPTKEY  *phKey)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	HCRYPTKEY hMyKey = NULL;
	__try
	{
		HCRYPTHASH hMyHash = GetHash(hHash);
		if (!hMyHash)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetHash failed 0x%08X", dwError);
			__leave;
		}
		if (!CryptDeriveKey(m_hProv, Algid, hMyHash, dwFlags, &hMyKey))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CryptDeriveKey failed 0x%08X", dwError);
			__leave;
		}
		ContainerKeyHandle* handle = ContainerKeyHandle::Create(hMyKey, 0);
		if (!handle)
		{
			dwError = NTE_NO_MEMORY;
			Trace(TRACE_LEVEL_ERROR, L"NTE_NO_MEMORY");
			__leave;
		}
		m_keyHandles.push_back(handle);
		*phKey = (HCRYPTKEY) handle;
		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			if (hMyKey) CryptDestroyKey(hMyKey);
		}
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CspContainer::DestroyKey(
					__in     HCRYPTKEY   hKey)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	DWORD dwKeySpec = 0;
	__try
	{
		HCRYPTKEY hMyKey = GetKey(hKey, &dwKeySpec);
		if (!hMyKey)
		{
			dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"GetKey failed 0x%08X", dwError);
				__leave;
		}
		m_keyHandles.remove((ContainerKeyHandle*)hKey);
		delete (ContainerKeyHandle*)hKey;
		if (!dwKeySpec)
		{
			fReturn = CryptDestroyKey(hMyKey);
			if (!fReturn)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"CryptDestroyKey failed 0x%08X", dwError);
				__leave;
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

///////////////////////////////////////////////////////////////////////////////
// Returns length of a ASN.1 SEQUENCE-OF.  Note that this function is extremely
// dangerous.  If non-ASN.1 encoded data is passed in then bad things could
// happen.
//
// Parameters:
//  buf        - BYTE buffer
//  withHeader - (default: true) Returns length with ASN.1 header length
//               included
//
// Returns:
//  length
///////////////////////////////////////////////////////////////////////////////
ULONG ASN1Len(CONST BYTE * buf, bool withHeader = true)
{
   // Make a very simplistic check for valid data since this
   // function is inherently dangerous
   if (buf[0] != 0x30)
      return 0;

   ULONG used_length = 1; // Skip the tag
   ULONG data_length = buf[used_length++];;

   if (data_length & 0x80) 
   {
      ULONG len_count = data_length & 0x7f;
      data_length = 0;
      while (len_count-- > 0) 
         data_length = (data_length << 8) | buf[used_length++];
    }

   if (withHeader)
      return data_length + used_length;
   else
      return data_length;
}

BOOL CspContainer::SetKeyParam(
					__in     HCRYPTKEY   hKey,
					__in    DWORD dwParam,
					__in     CONST  BYTE *pbData,
					__in    DWORD  dwFlags)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	DWORD dwKeySpec = 0;
	PCCERT_CONTEXT pCertContext = NULL;
	HCRYPTKEY hMyKey;
	__try
	{
		hMyKey = GetKey(hKey, &dwKeySpec);
		if (!hMyKey)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKey failed 0x%08X", dwError);
			__leave;
		}
		switch(dwParam)
		{
		case KP_CERTIFICATE:
			if (!dwKeySpec)
			{
				dwError = NTE_BAD_TYPE;
				Trace(TRACE_LEVEL_ERROR, L"KP_CERTIFICATE with no RSA key");
				__leave;
			}
			if (pbData != NULL)
			{
				pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pbData, ASN1Len(pbData));
				if (!pCertContext)
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR, L"CertCreateCertificateContext failed 0x%08X", dwError);
					__leave;
				}
				fReturn = SaveCertificate(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, dwKeySpec);
				if (!fReturn)
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR, L"SaveCertificate failed 0x%08X", dwError);
					__leave;
				}
			}
			else
			{
				fReturn = SaveCertificate(NULL, 0, dwKeySpec);
				if (!fReturn)
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR, L"SaveCertificate failed 0x%08X", dwError);
					__leave;
				}
			}
			break;
		case KP_PERMISSIONS:
			if (dwKeySpec == 0)
			{
				fReturn = CryptSetKeyParam(hMyKey, dwParam, pbData, dwFlags);
				if (!fReturn)
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR, L"CryptSetKeyParam failed 0x%08X", dwError);
					__leave;
				}
			}
			else
			{
				// ignore setting permission on the card keys
				dwError = ERROR_SUCCESS;
				fReturn = TRUE;
				Trace(TRACE_LEVEL_ERROR, L"KP_PERMISSIONS with dwKeySpec = %d", dwKeySpec);
				__leave;
			}
			break;
		case KP_ALGID:
		case KP_SALT:
		case KP_SALT_EX:
		case KP_G:
		case KP_P:
		case KP_Q:
		case KP_X:
		case KP_CMS_DH_KEY_INFO:
		case KP_PUB_PARAMS:
		case KP_EFFECTIVE_KEYLEN:
		case KP_HIGHEST_VERSION:
		case KP_IV:
		case KP_KEYVAL:
		case KP_PADDING:
		case KP_MODE:
		case KP_MODE_BITS:
		case KP_OAEP_PARAMS:
			fReturn = CryptSetKeyParam(hMyKey, dwParam, pbData, dwFlags);
			if (!fReturn)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"CryptSetKeyParam failed 0x%08X", dwError);
				__leave;
			}
			break;
		default:
			dwError = NTE_BAD_TYPE;
			Trace(TRACE_LEVEL_ERROR, L"dwParam = %d not supported", dwParam);
			__leave;
		}
	}
	__finally
	{
		if (pCertContext) CertFreeCertificateContext(pCertContext);
	}
	SetLastError(dwError);
	return fReturn;
}
_Success_(return) BOOL CspContainer::GetKeyParam(
					__in     HCRYPTKEY   hKey,
					__in    DWORD dwParam,
					_Out_writes_bytes_to_opt_(*pdwDataLen, *pdwDataLen) LPBYTE  pbData,
					__inout  LPDWORD pdwDataLen,
					__in    DWORD  dwFlags)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	DWORD dwKeySpec = 0;
	__try
	{
		if (!pdwDataLen)
		{
			dwError = ERROR_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_ERROR, L"pdwDataLen NULL");
			__leave;
		}
		HCRYPTKEY hMyKey = GetKey(hKey, &dwKeySpec);
		if (!hMyKey)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKey failed 0x%08X", dwError);
			__leave;
		}
		switch(dwParam)
		{
		case KP_CERTIFICATE:
			fReturn = LoadCertificate(pbData, pdwDataLen);
			if (!fReturn)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"LoadCertificate failed 0x%08X", dwError);
				__leave;
			}
			break;
		case KP_PERMISSIONS:
			if (dwKeySpec == 0)
			{
				fReturn = CryptGetKeyParam(hMyKey, dwParam, pbData, pdwDataLen, dwFlags);
				if (!fReturn)
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR, L"CryptGetKeyParam failed 0x%08X", dwError);
					__leave;
				}
				fReturn = TRUE;
				break;
			}
			if (*pdwDataLen < sizeof(DWORD))
			{
				*pdwDataLen = sizeof(DWORD);
				dwError = ERROR_MORE_DATA;
				__leave;
			}
			*pdwDataLen = sizeof(DWORD);
			if (pbData)
			{
				*((PDWORD)pbData) = (dwKeySpec == AT_KEYEXCHANGE ? CRYPT_ENCRYPT|CRYPT_DECRYPT|CRYPT_MAC|CRYPT_READ : CRYPT_MAC|CRYPT_READ);	
			}
			fReturn = TRUE;
			break;
		case KP_ALGID:
		case KP_BLOCKLEN:
		case KP_KEYLEN:
		case KP_SALT:
		case KP_P:
		case KP_Q:
		case KP_G:
		case KP_EFFECTIVE_KEYLEN:
		case KP_IV:
		case KP_PADDING:
		case KP_MODE:
		case KP_MODE_BITS:
		case KP_VERIFY_PARAMS:
		case KP_KEYVAL:
			fReturn = CryptGetKeyParam(hMyKey, dwParam, pbData, pdwDataLen, dwFlags);
			if (!fReturn)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"CryptGetKeyParam failed 0x%08X", dwError);
				__leave;
			}
			break;
		default:
			dwError = NTE_BAD_TYPE;
			Trace(TRACE_LEVEL_ERROR, L"dwParam = %d not supported", dwParam);
			__leave;
		}
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;

}
BOOL CspContainer::ExportKey(
					__in     HCRYPTKEY   hKey,
					__in     HCRYPTKEY  hPubKey,
					__in    DWORD dwBlobType,
					__in    DWORD  dwFlags,
					_Out_writes_bytes_to_opt_(*pdwDataLen, *pdwDataLen)  LPBYTE  pbData,
					__inout  LPDWORD pdwDataLen)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	DWORD dwKeySpec = 0;
	__try
	{
		HCRYPTKEY hMyKey = GetKey(hKey, &dwKeySpec);
		if (!hMyKey)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKey failed 0x%08X", dwError);
			__leave;
		}
		HCRYPTKEY hMyPubKey = GetKey(hPubKey, NULL);
		if (hPubKey && !hMyPubKey)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKey failed 0x%08X with not null", dwError);
			__leave;
		}
		if (dwKeySpec == AT_SIGNATURE || dwKeySpec == AT_KEYEXCHANGE)
		{
			if (dwBlobType != PUBLICKEYBLOB)
			{
				dwError = NTE_BAD_TYPE;
				Trace(TRACE_LEVEL_ERROR, L"dwBlobType %d <> PUBLICKEYBLOB", dwBlobType);
				__leave;
			}
		}
		fReturn = CryptExportKey(hMyKey, hMyPubKey, dwBlobType, dwFlags, pbData, pdwDataLen);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CryptExportKey failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}
BOOL CspContainer::ImportKey(
					__in     CONST  BYTE *pbData,
					__in    DWORD cbDataLen,
					__in     HCRYPTKEY  hPubKey,
					__in    DWORD  dwFlags,
					__out   HCRYPTKEY  *phKey)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	HCRYPTKEY hMyKey = NULL;
	HCRYPTKEY hTempKey = NULL;
	ContainerKeyHandle* handle = NULL;
	BOOL fEndTransaction = FALSE;
	BOOL fAuthenticated = FALSE;
	DWORD dwPinId = 0;
	DWORD dwTempSize = 0;
	PBYTE pbTempKey = NULL;
	HCRYPTKEY hMyPubKey = NULL;
	PPLAINTEXTKEYBLOBTYPE pbImportKeyBlob = NULL;
	HWND hWndParent = NULL;
	__try
	{
		*phKey = NULL;
		if (!pbData)
		{
			dwError = ERROR_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_ERROR, L"pbData NULL");
			__leave;
		}
		if (cbDataLen < sizeof(BLOBHEADER))
		{
			dwError  = NTE_BAD_DATA;
			Trace(TRACE_LEVEL_ERROR, L"cbDataLen %d < BLOB", cbDataLen);
			__leave;
		}
		Trace(TRACE_LEVEL_VERBOSE, L"dwFlags %d", dwFlags);

		if (hPubKey)
		{
			Trace(TRACE_LEVEL_VERBOSE, L"hPubKey 0x%Ix", hPubKey);
			hMyPubKey = GetKey(hPubKey, NULL);
			if (!hMyPubKey)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"GetKey failed 0x%08X", dwError);
				__leave;
			}
		}
		BLOBHEADER* header = (BLOBHEADER*) pbData;
		Trace(TRACE_LEVEL_VERBOSE, L"header %d", header->bType);
		Trace(TRACE_LEVEL_VERBOSE, L"algid %d", header->aiKeyAlg);
		if (header->bType == PRIVATEKEYBLOB)
		{
			if (dwFlags & CRYPT_EXPORTABLE)
			{
				dwError  = NTE_BAD_FLAGS;
				Trace(TRACE_LEVEL_ERROR, L"dwFlags 0x%08X exportable", dwFlags);
				__leave;
			}
			if (dwFlags & CRYPT_USER_PROTECTED)
			{
				Trace(TRACE_LEVEL_INFO, L"CRYPT_USER_PROTECTED was set");
				dwFlags &= ~CRYPT_USER_PROTECTED;
			}
			if (m_dwCardContainerId == INVALID_CONTAINER_ID)
			{
				Trace(TRACE_LEVEL_INFO, L"no key id");
				GetHWND(&hWndParent);
				if (!m_Card->GetKeyIdForNewKey(header->aiKeyAlg,hWndParent, &m_dwCardContainerId))
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR, L"GetPIN failed 0x%08X", dwError);
					__leave;
				}
			}
			if (!GetPIN(PIN_OPERATION_CREATE, &dwPinId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"GetPIN failed 0x%08X", dwError);
				__leave;
			}
			if (!AskPinToUserIfNeeded(GetParentHwnd(), dwPinId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"StartTransaction failed 0x%08X", dwError);
				__leave;
			}
			if (!StartTransaction())
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"StartTransaction failed 0x%08X", dwError);
				__leave;
			}
			fEndTransaction = TRUE;
			if (!Authenticate(dwPinId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"Authenticate failed 0x%08X", dwError);
				__leave;
			}
			fAuthenticated = TRUE;
			if (!CryptImportKey(m_hProv, pbData, cbDataLen, hMyPubKey, dwFlags | CRYPT_EXPORTABLE, &hTempKey))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"CryptImportKey failed 0x%08X", dwError);
				__leave;
			}
			if (!CryptExportKey(hTempKey, NULL, PRIVATEKEYBLOB, 0, NULL, &dwTempSize))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"CryptExportKey failed 0x%08X", dwError);
				__leave;
			}
			pbTempKey = (PBYTE) malloc( dwTempSize);
			if (!pbTempKey)
			{
				dwError = ERROR_OUTOFMEMORY;
				Trace(TRACE_LEVEL_INFO, L"ERROR_OUTOFMEMORY");
				__leave;
			}
			if (!CryptExportKey(hTempKey, NULL, PRIVATEKEYBLOB, 0, pbTempKey, &dwTempSize))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"CryptExportKey failed 0x%08X", dwError);
				__leave;
			}
			switch (header->aiKeyAlg)
			{
			case CALG_RSA_KEYX:
				m_dwKeySpec = AT_KEYEXCHANGE;
				break;
			case CALG_RSA_SIGN:
				m_dwKeySpec = AT_SIGNATURE;
				break;
			default:
				dwError = NTE_BAD_ALGID;
				Trace(TRACE_LEVEL_ERROR, L"NTE_BAD_ALGID");
				__leave;
			}
			if (!m_Card->SaveKey(m_dwCardContainerId, header->aiKeyAlg, pbTempKey, dwTempSize))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"SaveKey failed 0x%08X", dwError);
				__leave;
			}
			if (!m_Card->SetContainerName(m_szContainerName, m_dwCardContainerId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"RegisterAlias failed 0x%08X", dwError);
				__leave;
			}
			
			// keep only the public part in memory
			// public key size < private key size
			if (!CryptExportKey(hTempKey, NULL, PUBLICKEYBLOB, 0, pbTempKey, &dwTempSize))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"CryptExportKey failed 0x%08X", dwError);
				__leave;
			}
			if (!CryptImportKey(m_hProv, pbTempKey, dwTempSize, NULL, 0, &hMyKey))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"CryptImportKey failed 0x%08X", dwError);
				__leave;
			}

			if (m_hKey) CryptDestroyKey(m_hKey);
			m_hKey = hMyKey;
			handle = ContainerKeyHandle::Create(hMyKey, m_dwKeySpec);
			hMyKey = NULL;
			if (!handle)
			{
				dwError = NTE_NO_MEMORY;
				Trace(TRACE_LEVEL_ERROR, L"NTE_NO_MEMORY");
				__leave;
			}
			Trace(TRACE_LEVEL_INFO, L"done");
		}
		else if (header->bType == SIMPLEBLOB && hMyPubKey)
		{
			// transcode a SIMPLEBLOB to a PLAINTEXTKEYBLOB
			PSIMPLEKEYBLOBTYPE pbSimpleBlob = (PSIMPLEKEYBLOBTYPE) pbData;
			Trace(TRACE_LEVEL_VERBOSE, L"algid %d", header->aiKeyAlg);
			Trace(TRACE_LEVEL_VERBOSE, L"KeyBlobId %d", pbSimpleBlob->algid);
			DWORD dwEncryptKeySize = cbDataLen - sizeof(BLOBHEADER) - sizeof(ALG_ID);

			pbImportKeyBlob = (PPLAINTEXTKEYBLOBTYPE) malloc(dwEncryptKeySize + sizeof(PLAINTEXTKEYBLOBTYPE));
			if (!pbImportKeyBlob)
			{
				dwError = NTE_NO_MEMORY;
				Trace(TRACE_LEVEL_ERROR, L"NTE_NO_MEMORY");
				__leave;
			}
			Trace(TRACE_LEVEL_VERBOSE, L"Kc");
			pbImportKeyBlob->blobheader.aiKeyAlg = header->aiKeyAlg;
			pbImportKeyBlob->blobheader.bVersion =  CUR_BLOB_VERSION;
			pbImportKeyBlob->blobheader.reserved = 0;
			pbImportKeyBlob->blobheader.bType = PLAINTEXTKEYBLOB;
			memcpy(pbImportKeyBlob->rgbKeyData, pbSimpleBlob->encryptedkey, dwEncryptKeySize);
			pbImportKeyBlob->dwKeySize = dwEncryptKeySize;
			Trace(TRACE_LEVEL_VERBOSE, L"Kcz");
			if (!GetPIN(PIN_OPERATION_DECRYPT, &dwPinId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"GetPIN failed 0x%08X", dwError);
				__leave;
			}
			if (!AskPinToUserIfNeeded(GetParentHwnd(), dwPinId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"StartTransaction failed 0x%08X", dwError);
				__leave;
			}
			if (!StartTransaction())
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"StartTransaction failed 0x%08X", dwError);
				__leave;
			}
			fEndTransaction = TRUE; 
			if (!Authenticate(dwPinId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"Authenticate failed 0x%08X", dwError);
				__leave;
			}
			fAuthenticated = TRUE;
			if (!m_Card->Decrypt(m_dwCardContainerId, pbImportKeyBlob->rgbKeyData, pbImportKeyBlob->dwKeySize, pbImportKeyBlob->rgbKeyData, &pbImportKeyBlob->dwKeySize))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"CryptDecrypt failed 0x%08X", dwError);
				__leave;
			}
			if (!CryptImportKey(m_hProv, (PBYTE) pbImportKeyBlob, pbImportKeyBlob->dwKeySize + sizeof(BLOBHEADER) + sizeof(DWORD), NULL, dwFlags, &hMyKey))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"CryptImportKey failed 0x%08X", dwError);
				__leave;
			}
			handle = ContainerKeyHandle::Create(hMyKey, 0);
			if (!handle)
			{
				dwError = NTE_NO_MEMORY;
				Trace(TRACE_LEVEL_ERROR, L"NTE_NO_MEMORY");
				__leave;
			}
			Trace(TRACE_LEVEL_INFO, L"done");
		}
		else
		{
			//TraceDump(TRACE_LEVEL_VERBOSE, (PBYTE) pbData, cbDataLen);
			if (!CryptImportKey(m_hProv, pbData, cbDataLen, hMyPubKey, dwFlags, &hMyKey))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"CryptImportKey failed 0x%08X", dwError);
				__leave;
			}
			handle = ContainerKeyHandle::Create(hMyKey, 0);
			if (!handle)
			{
				dwError = NTE_NO_MEMORY;
				Trace(TRACE_LEVEL_ERROR, L"NTE_NO_MEMORY");
				__leave;
			}
			Trace(TRACE_LEVEL_INFO, L"done");
		}
		m_keyHandles.push_back(handle);
		*phKey = (HCRYPTKEY) handle;
		fReturn = TRUE;
	}
	__finally
	{
		if (pbImportKeyBlob)
		{
			SecureZeroMemory(pbImportKeyBlob->rgbKeyData, pbImportKeyBlob->dwKeySize);
			free(pbImportKeyBlob);
		}
		if (hTempKey)
			CryptDestroyKey(hTempKey);
		if (pbTempKey)
		{
			SecureZeroMemory(pbTempKey, dwTempSize);
			free(pbTempKey);
		}
		if (!fReturn)
		{
			if (hMyKey) CryptDestroyKey(hMyKey);
		}
		if (fEndTransaction)
			EndTransaction(dwPinId, fAuthenticated);
	}
	SetLastError(dwError);
	return fReturn;
}
BOOL CspContainer::Encrypt(
					__in     HCRYPTKEY   hKey,
					__in     HCRYPTHASH  hHash,
					__in     BOOL  fFinal,
					__in    DWORD  dwFlags,
					__inout  LPBYTE  pbData,
					__inout  LPDWORD pcbDataLen,
					__in    DWORD cbBufLen)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	__try
	{
		HCRYPTHASH hMyHash = GetHash(hHash);
		if (hHash && !hMyHash)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetHash failed 0x%08X", dwError);
			__leave;
		}
		HCRYPTKEY hMyKey = GetKey(hKey, NULL);
		if (!hMyKey)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKey failed 0x%08X", dwError);
			__leave;
		}
		fReturn = CryptEncrypt(hMyKey, hMyHash, fFinal, dwFlags, pbData, pcbDataLen, cbBufLen);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CryptEncrypt failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}
BOOL CspContainer::Decrypt(
					__in     HCRYPTKEY   hKey,
					__in     HCRYPTHASH  hHash,
					__in     BOOL  fFinal,
					__in    DWORD  dwFlags,
					__inout  LPBYTE  pbData,
					__inout  LPDWORD pcbDataLen)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	DWORD dwKeySpec = 0;
	BOOL fEndTransaction = FALSE;
	BOOL fAuthenticated = FALSE;
	DWORD dwPinId = 0;
	__try
	{
		HCRYPTHASH hMyHash = GetHash(hHash);
		if (hHash && !hMyHash)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetHash failed 0x%08X", dwError);
			__leave;
		}
		HCRYPTKEY hMyKey = GetKey(hKey, &dwKeySpec);
		if (!hMyKey)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKey failed 0x%08X", dwError);
			__leave;
		}
		if (dwKeySpec == AT_SIGNATURE)
		{
			dwError = NTE_NOT_SUPPORTED;
			Trace(TRACE_LEVEL_ERROR, L"NTE_NOT_SUPPORTED");
			__leave;
		}
		if (dwKeySpec == AT_KEYEXCHANGE)
		{
			if (!fFinal)
			{
				dwError = NTE_BAD_FLAGS;
				Trace(TRACE_LEVEL_ERROR, L"NTE_BAD_FLAGS");
				__leave;
			}
			if (dwFlags)
			{
				dwError = NTE_BAD_FLAGS;
				Trace(TRACE_LEVEL_ERROR, L"NTE_BAD_FLAGS");
				__leave;
			}
			if (!GetPIN(PIN_OPERATION_DECRYPT, &dwPinId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"GetPIN failed 0x%08X", dwError);
				__leave;
			}
			if (!AskPinToUserIfNeeded(GetParentHwnd(), dwPinId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"StartTransaction failed 0x%08X", dwError);
				__leave;
			}
			if (!StartTransaction())
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"StartTransaction failed 0x%08X", dwError);
				__leave;
			}
			fEndTransaction = TRUE; 
			if (!Authenticate(dwPinId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"Authenticate failed 0x%08X", dwError);
				__leave;
			}
			fAuthenticated = TRUE;
			if (!m_Card->Decrypt(m_dwCardContainerId, pbData, *pcbDataLen, pbData, pcbDataLen))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"CryptDecrypt failed 0x%08X", dwError);
				__leave;
			}
			if (hHash)
			{
				if (!CryptHashData(hMyHash, pbData, *pcbDataLen, 0))
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR, L"CryptHashData failed 0x%08X", dwError);
					__leave;
				}
			}
		}
		else
		{
			if (!CryptDecrypt(hMyKey, hMyHash, fFinal, dwFlags, pbData, pcbDataLen))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"CryptDecrypt failed 0x%08X", dwError);
				__leave;
			}
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
BOOL CspContainer::VerifySignature(
					__in     HCRYPTHASH  hHash,
					__in     CONST  BYTE *pbSignature,
					__in    DWORD cbSigLen,
					__in     HCRYPTKEY  hPubKey,
					__in    LPCWSTR szDescription,
					__in    DWORD  dwFlags)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	__try
	{
		HCRYPTHASH hMyHash = GetHash(hHash);
		if (!hMyHash)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetHash failed 0x%08X", dwError);
			__leave;
		}
		HCRYPTKEY hMyKey = GetKey(hPubKey, NULL);
		if (!hMyKey)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKey failed 0x%08X", dwError);
			__leave;
		}
		fReturn = CryptVerifySignature(hMyHash, pbSignature, cbSigLen, hMyKey, szDescription, dwFlags);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CryptVerifySignature failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CspContainer::GetUserKey(
					__in    DWORD  dwKeySpec,
					__out   HCRYPTKEY  *phUserKey)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	HCRYPTKEY hKey = NULL;
	ContainerKeyHandle* handle = NULL;
	__try
	{
		if (!phUserKey)
		{
			dwError = ERROR_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_ERROR, L"phUserKey NULL");
			__leave;
		}
		*phUserKey = NULL;
		if (dwKeySpec == m_dwKeySpec)
		{
			if (!m_hKey)
			{
				dwError = NTE_NO_KEY;
				Trace(TRACE_LEVEL_ERROR, L"AT_KEYEXCHANGE NTE_NO_KEY");
				__leave;
			}
			handle = ContainerKeyHandle::Create(m_hKey, dwKeySpec);
		}
		else
		{
			Trace(TRACE_LEVEL_ERROR, L"invalid keyspec %d", dwKeySpec);
			dwError = NTE_BAD_KEY;
			__leave;
		}
		if (!handle)
		{
			dwError = NTE_NO_MEMORY;
			__leave;
		}
		m_keyHandles.push_back(handle);
		*phUserKey = (HCRYPTKEY) handle;
		fReturn = TRUE;
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CspContainer::EnumerateContainer(_Out_writes_bytes_to_opt_(*pdwDataLen, *pdwDataLen) PSTR szContainer, __inout PDWORD pdwDataLen, DWORD dwFlags)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	BOOL fEndTransaction = FALSE;
	BOOL fAuthenticated = FALSE;
	__try
	{
		Trace(TRACE_LEVEL_VERBOSE, L"Enter");
		if (*pdwDataLen < MAX_CONTAINER_NAME)
		{
			dwError = ERROR_MORE_DATA;
			Trace(TRACE_LEVEL_ERROR, L"*pdwDataLen %d < %d", *pdwDataLen, MAX_CONTAINER_NAME);
			*pdwDataLen = MAX_CONTAINER_NAME;
			fReturn = TRUE;
			__leave;
		}
		if (!szContainer)
		{
			dwError = ERROR_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_ERROR, L"szContainer NULL");
			__leave;
		}
		szContainer[0] = 0;
		if ((dwFlags & (CRYPT_FIRST | CRYPT_NEXT)) == (CRYPT_FIRST | CRYPT_NEXT))
		{
			dwError = NTE_BAD_FLAGS;
			Trace(TRACE_LEVEL_ERROR, L"NTE_BAD_FLAGS dwFlags = 0x%08X", dwFlags);
			__leave;
		}
		if (!m_Card)
		{
			dwError = NTE_BAD_UID;
			Trace(TRACE_LEVEL_ERROR, L"Context not assigned to a card");
			__leave;
		}
		if (!StartTransaction())
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"StartTransaction failed 0x%08X", dwError);
			__leave;
		}
		fEndTransaction = TRUE;
		// first enumeration
		DWORD dwMaxContainer = m_Card->GetMaxContainer();
		for(DWORD dwI = (dwFlags & CRYPT_FIRST?0:m_dwPreviousEnumeratedContainer +1 ); dwI < dwMaxContainer; dwI++)
		{
			if (m_Card->GetContainerName(dwI, szContainer))
			{
				Trace(TRACE_LEVEL_INFO, L"Current container %S %d", szContainer, dwI);
				m_dwPreviousEnumeratedContainer = dwI;
				fReturn = TRUE;
				__leave;
			}
		}
		dwError = ERROR_NO_MORE_ITEMS;
		Trace(TRACE_LEVEL_INFO, L"No more container to enumerate");
	}
	__finally
	{
		if (fEndTransaction)
			EndTransaction(0, fAuthenticated);
	}
	SetLastError(dwError);
	return fReturn;
}

HWND CspContainer::GetParentHwnd()
{
	HWND hWndParent = 0;
	GetHWND(&hWndParent);
	return hWndParent;
}

