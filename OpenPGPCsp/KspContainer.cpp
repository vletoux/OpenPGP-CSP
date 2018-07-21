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

typedef struct KspCachedPin
{
	BYTE encryptedPin[MAX_PIN_SIZE * sizeof(TCHAR) + RTL_ENCRYPT_MEMORY_SIZE];
	WCHAR szContainerName[MAX_CONTAINER_NAME];
	FILETIME Timestamp;
} KspCachedPin;

std::list<KspContainer*> m_kspcontainers;
std::list<KspCachedPin*> m_kspcachedPins;

_Ret_maybenull_ KspContainer* KspContainer::Create()
{
	KspContainer* container = KspContainer::Allocate();
	if (!container)
		return NULL;
	return container;
}

KspContainer::KspContainer()
{
	m_hWnd = 0;
	m_kspcontainers.push_front(this);
}

KspContainer::~KspContainer()
{

}


_Ret_maybenull_ KspContainer* KspContainer::GetContainerFromHandle(NCRYPT_PROV_HANDLE handle)
{
 	if (!handle)
	{
		Trace(TRACE_LEVEL_ERROR, L"handle NULL");
		SetLastError( ERROR_INVALID_PARAMETER );
		return NULL;
	}
	std::list<KspContainer*>::const_iterator it (m_kspcontainers.begin());
	for(;it!=m_kspcontainers.end();++it) 
	{
		if ((NCRYPT_PROV_HANDLE)((KspContainer*)(*it)) == handle)
		{
			return (KspContainer*) handle;
		}
	}
	Trace(TRACE_LEVEL_ERROR, L"handle 0x%Ix unknown", handle);
	SetLastError( NTE_KEYSET_NOT_DEF );
	return NULL;
}

BOOL KspContainer::CleanProviders()
{
	std::list<KspContainer*>::const_iterator it (m_kspcontainers.begin());
	while (it!=m_kspcontainers.end()) 
	{
		//delete (*it);
		it = m_kspcontainers.erase(it);
	}
	return TRUE;
}

BOOL KspContainer::Unload()
{
	Trace(TRACE_LEVEL_VERBOSE, L"free this");
	m_kspcontainers.remove(this);
	delete this;
	return TRUE;
}

BOOL KspContainer::Clean()
{
	if (!CleanProviders()) return FALSE;
	if (!CleanPinCache()) return FALSE;
	return TRUE;
}

KspKey* KspContainer::LocateKey(__in    NCRYPT_KEY_HANDLE hKey)
{
	if (!hKey)
	{
		Trace(TRACE_LEVEL_ERROR, L"hKey NULL");
		SetLastError( ERROR_INVALID_PARAMETER );
		return NULL;
	}
	std::list<KspKey*>::const_iterator it (m_keyHandles.begin());
	for(;it!=m_keyHandles.end();++it) 
	{
		if ((NCRYPT_PROV_HANDLE)((KspKey*)(*it)) == hKey)
		{
			return (KspKey*) hKey;
		}
	}
	Trace(TRACE_LEVEL_ERROR, L"handle 0x%Ix unknown", hKey);
	SetLastError( NTE_KEYSET_NOT_DEF );
	return NULL;
}

KspKey* KspContainer::OpenKey(__in PCWSTR pszKeyName,__in_opt DWORD  dwLegacyKeySpec, BOOL fSilent)
{
	KspKey* key = NULL;
	DWORD dwError = 0;
	DWORD dwKeyType = 0;
	PCWSTR szReader = NULL;
	WCHAR szBuffer[256];
	PCWSTR szContainer = NULL;
	__try
	{
		Trace(TRACE_LEVEL_VERBOSE, L"load container %s", pszKeyName);
		
		if (!ExtractReaderAndContainerFromGeneralNameW(pszKeyName, szBuffer, ARRAYSIZE(szBuffer), &szReader, &szContainer))
		{
			dwError = GetLastError();
			__leave;
		}

		key = KspKey::LoadKey(this, szReader, szContainer);
		if (!key)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"error LoadKey 0x%08X", dwError);
			__leave;
		}
		m_keyHandles.push_back(key);
	}
	__finally
	{
	}
	SetLastError(dwError);
	return key;
}

// this function is both used to create & import key
// if a key is submitted via a handle, this key is imported
KspKey* KspContainer::CreateNonPersistedKey(__in_opt LPCWSTR pszKeyName,
			__in    DWORD   dwLegacyKeySpec,
			__in    DWORD   dwFlags,
			__in_opt BCRYPT_ALG_HANDLE hProv,
			__in_opt BCRYPT_KEY_HANDLE hKey)
{
	UNREFERENCED_PARAMETER(dwFlags);
	KspKey* key = NULL;
	DWORD dwError = 0;
	__try
	{
		Trace(TRACE_LEVEL_VERBOSE, L"create container %s", pszKeyName);
		
		key = KspKey::CreateNonPersitedKey(this, pszKeyName, dwLegacyKeySpec, hProv, hKey);
		if (!key)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"error LoadKey 0x%08X", dwError);
			__leave;
		}
		m_keyHandles.push_back(key);
	}
	__finally
	{
	}
	SetLastError(dwError);
	return key;
}

KspKey* KspContainer::GetKeyFromHandle(__in    NCRYPT_PROV_HANDLE hProvider, __in    NCRYPT_KEY_HANDLE hKey)
{
	KspContainer* container = GetContainerFromHandle(hProvider);
	if (!container)
		return NULL;
	return container->LocateKey(hKey);
}

_Success_(return) BOOL KspContainer::FreeKey(__in    NCRYPT_KEY_HANDLE hKey)
{
	KspKey* key = LocateKey(hKey);
	if (!key)
		return NULL;
	std::list<KspKey*>::const_iterator it (m_keyHandles.begin());
	while (it!=m_keyHandles.end()) 
	{
		if ((NCRYPT_PROV_HANDLE)((KspKey*)(*it)) == hKey)
		{
			delete (*it);
			it = m_keyHandles.erase(it);
			return TRUE;
		}
	}
	Trace(TRACE_LEVEL_ERROR, L"handle 0x%Ix unknown", hKey);
	SetLastError( NTE_KEYSET_NOT_DEF );
	return NULL;
}


_Success_(return) BOOL KspContainer::GetProviderProperty(
							__in    LPCWSTR pszProperty,
							__out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
							__in    DWORD   cbOutput,
							__out   DWORD * pcbResult,
							__in    DWORD   dwFlags)
{
	
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	__try
	{

		if((pszProperty == NULL)||(pcbResult == NULL))
		{
			dwError = NTE_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_ERROR, L"pszProperty NULL");
			__leave;
		}
		*pcbResult = 0;
		if (pbOutput)
		{
			ZeroMemory(pbOutput, cbOutput);
		}
		if(wcslen(pszProperty) > NCRYPT_MAX_PROPERTY_NAME)
		{
			dwError = NTE_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_ERROR, L"pszProperty too long");
			__leave;
		}
		if((dwFlags & ~(NCRYPT_SILENT_FLAG)) != 0)
		{
			dwError = NTE_BAD_FLAGS;
			Trace(TRACE_LEVEL_ERROR, L"bad dwFlags");
			__leave;
		}

		//
		//Determine the size of the properties.
		//

		if(wcscmp(pszProperty, NCRYPT_USER_CERTSTORE_PROPERTY) == 0)
		{
			* pcbResult = sizeof(HCERTSTORE);
		}
		else if(wcscmp(pszProperty, NCRYPT_IMPL_TYPE_PROPERTY) == 0)
		{
			* pcbResult = sizeof(DWORD);
		}
		else if(wcscmp(pszProperty, NCRYPT_MAX_NAME_LENGTH_PROPERTY) == 0)
		{
			* pcbResult = sizeof(DWORD);
		}
		else if(wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0)
		{
			* pcbResult = sizeof(TEXT(KSPNAME));
		} 
		else if(wcscmp(pszProperty, NCRYPT_VERSION_PROPERTY) == 0)
		{
			* pcbResult = sizeof(DWORD);
		}
		else
		{
			dwError = NTE_NOT_SUPPORTED;
			Trace(TRACE_LEVEL_ERROR, L"property not supported");
			__leave;
		}

		//Output buffer is empty, this is a property length query, and we can exit early.
		if (pbOutput==NULL)
		{
			fReturn = TRUE;
			__leave;
		}

		//Otherwise, validate the size.
		if(cbOutput <* pcbResult)
		{
			dwError = NTE_BUFFER_TOO_SMALL;
			Trace(TRACE_LEVEL_ERROR, L"NTE_BUFFER_TOO_SMALL");
			__leave;
		}
		if(wcscmp(pszProperty, NCRYPT_USER_CERTSTORE_PROPERTY) == 0)
		{
			__try
			{
				HCERTSTORE hStore = NULL;
				fReturn = GetUserStoreWithAllCard(&hStore);
				if (!fReturn)
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR, L"GetUserStoreWithAllCard failed 0x%08X", dwError);
					__leave;
				}
				*(HCERTSTORE *)pbOutput = hStore;
			}
			__finally
			{
			}
		}
		else if(wcscmp(pszProperty, NCRYPT_IMPL_TYPE_PROPERTY) == 0)
		{
            *(DWORD *)pbOutput = NCRYPT_IMPL_HARDWARE_FLAG;
		}
		else if(wcscmp(pszProperty, NCRYPT_MAX_NAME_LENGTH_PROPERTY) == 0)
		{
			*(DWORD *)pbOutput = MAX_PATH;
		}
		else if(wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0)
		{
			CopyMemory(pbOutput, TEXT(KSPNAME), *pcbResult);
		}
		else if(wcscmp(pszProperty, NCRYPT_VERSION_PROPERTY) == 0)
		{
			*(DWORD *)pbOutput =1;
		}
		fReturn = TRUE;
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}

_Success_(return) BOOL KspContainer::SetProviderProperty(__in    LPCWSTR pszProperty,
							__in_bcount(cbInput) PBYTE pbInput,
							__in    DWORD   cbInput,
							__in    DWORD   dwFlags)
{
	
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	__try
	{

		if((pszProperty == NULL))
		{
			dwError = NTE_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_ERROR, L"pszProperty NULL");
			__leave;
		}
		if((pszProperty == NULL)||
			(wcslen(pszProperty) > NCRYPT_MAX_PROPERTY_NAME)||
			(pbInput == NULL))
		{
			dwError = NTE_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_ERROR, L"pszProperty invalid");
			__leave;
		}

		if((dwFlags & ~(NCRYPT_SILENT_FLAG)) != 0)
		{
			dwError = NTE_BAD_FLAGS;
			Trace(TRACE_LEVEL_ERROR, L"bad dwFlags");
			__leave;
		}
		if (wcscmp(pszProperty, NCRYPT_WINDOW_HANDLE_PROPERTY) == 0)
		{
			m_hWnd = *((HWND*)pbInput);
			fReturn = TRUE;
		}
		else if (wcscmp(pszProperty, NCRYPT_USE_CONTEXT_PROPERTY) == 0)
		{
			fReturn = TRUE;
		}
		else
		{
			dwError = NTE_NOT_SUPPORTED;
		}
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}

_Success_(return) BOOL  KspContainer::IsAlgSupported( __in    LPCWSTR pszAlgId,   __in    DWORD   dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	__try
	{
	    if(pszAlgId == NULL)
		{
			dwError = NTE_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_ERROR, L"pszAlgId NULL");
			__leave;
		}

		if((dwFlags & ~(NCRYPT_SILENT_FLAG)) != 0)
		{
			dwError = NTE_BAD_FLAGS;
			Trace(TRACE_LEVEL_ERROR, L"bad dwFlags");
			__leave;
		}

		// This KSP only supports the RSA algorithm.
		if(wcscmp(pszAlgId, NCRYPT_RSA_ALGORITHM) != 0)
		{
			dwError = NTE_NOT_SUPPORTED;
			Trace(TRACE_LEVEL_ERROR, L"invalid alg %s", pszAlgId);
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
_Success_(return) BOOL KspContainer::EnumAlgorithms(
							__in    DWORD   dwAlgOperations, // this is the crypto operations that are to be enumerated
							__out   DWORD * pdwAlgCount,
							__deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
							__in    DWORD   dwFlags)
{
    NCryptAlgorithmName *pCurrentAlg = NULL;
    PBYTE pbCurrent = NULL;
    PBYTE pbOutput = NULL;
    DWORD cbOutput = 0;

	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	__try
	{
		if(pdwAlgCount == NULL || ppAlgList == NULL)
		{
			dwError = NTE_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_ERROR, L"pdwAlgCount NULL");
			__leave;
		}
		if((dwFlags & ~(NCRYPT_SILENT_FLAG)) != 0)
		{
			dwError = NTE_BAD_FLAGS;
			Trace(TRACE_LEVEL_ERROR, L"bad dwFlags");
			__leave;
		}


		if (dwAlgOperations == 0 ||
			dwAlgOperations & NCRYPT_SIGNATURE_OPERATION ||
			dwAlgOperations & NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION )
		{
			cbOutput += sizeof(NCryptAlgorithmName) +
						sizeof(BCRYPT_RSA_ALGORITHM);
		}
		else
		{
			dwError = ERROR_SUCCESS;
			*pdwAlgCount = 0;
			Trace(TRACE_LEVEL_ERROR, L"invalid dwAlgOperations %d", dwAlgOperations);
			fReturn = TRUE;
			__leave;
		}

		//Allocate the output buffer.
		pbOutput = (PBYTE)malloc(cbOutput);
		if (pbOutput == NULL)
		{
			dwError = NTE_NO_MEMORY;
			Trace(TRACE_LEVEL_ERROR, L"NTE_NO_MEMORY");
			__leave;
		}

		pCurrentAlg = (NCryptAlgorithmName *)pbOutput;
		pbCurrent = pbOutput + sizeof(NCryptAlgorithmName);

		pCurrentAlg->dwFlags = 0;
		pCurrentAlg->dwClass = NCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE;
		pCurrentAlg->dwAlgOperations = NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION | NCRYPT_SIGNATURE_OPERATION;

		pCurrentAlg->pszName = (LPWSTR)pbCurrent;
		RtlCopyMemory(pbCurrent,
				   BCRYPT_RSA_ALGORITHM,
				   sizeof(BCRYPT_RSA_ALGORITHM));
		pbCurrent += sizeof(BCRYPT_RSA_ALGORITHM);

		*pdwAlgCount = 1;
		*ppAlgList = (NCryptAlgorithmName *)pbOutput;

		fReturn = TRUE;

	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;

}

KspEnumNCryptKeyName* KspContainer::BuildEnumData(__in_opt LPCWSTR pszScope)
{
	DWORD dwError = 0;
	BOOL fEndTransaction = FALSE;
	DWORD cch = SCARD_AUTOALLOCATE;
	PWSTR pmszReaders = NULL;
	PWSTR szCurrentReader = NULL;
	DWORD dwProtocol = 0;
	CHAR szContainer[MAX_CONTAINER_NAME];
	KspEnumNCryptKeyName* returnValue = NULL;
	WCHAR szScopedReader[MAX_READER_NAME + 2];
	__try
	{
		returnValue = (KspEnumNCryptKeyName*) malloc(sizeof(KspEnumNCryptKeyName));
		if (!returnValue)
		{
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}
		ZeroMemory(returnValue, sizeof(KspEnumNCryptKeyName));
		dwError = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &m_hContext);
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR,L"SCardEstablishContext failed 0x%08X", dwError);
			__leave;
		}
		if (pszScope == NULL)
		{
			// identity a reader
			dwError = SCardListReaders(m_hContext,
							NULL,
							(LPWSTR)&pmszReaders,
							&cch );
			if (dwError || !pmszReaders)
			{
				Trace(TRACE_LEVEL_ERROR,L"SCardListReadersA failed 0x%08X", dwError);
				__leave;
			}
			szCurrentReader = pmszReaders;
		}
		else
		{
			if (wcsncmp(pszScope, L"\\\\.\\", 4) != 0)
			{
				Trace(TRACE_LEVEL_ERROR,L"Not a local scope %s 1", pszScope);
				dwError = ERROR_INVALID_PARAMETER;
				__leave;
			}
			size_t len = wcslen(pszScope);
			if (len <= 4 || pszScope[len-1] != '\\')
			{
				Trace(TRACE_LEVEL_ERROR,L"Not a local scope %s 2", pszScope);
				dwError = ERROR_INVALID_PARAMETER;
				__leave;
			}
			wcsncpy_s(szScopedReader, MAX_READER_NAME, pszScope + 4, len - 5);
			// extra 0 for chained string
			szScopedReader[len - 4] = 0;
			szCurrentReader = szScopedReader;
		}
		while('\0' != *szCurrentReader)
		{
			dwError = SCardConnect(m_hContext, szCurrentReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &m_hCard, &dwProtocol);
			if (dwError)
			{
				Trace(TRACE_LEVEL_INFO, L"reader %s is empty", szCurrentReader);
				szCurrentReader = szCurrentReader + wcslen(szCurrentReader) + 1;
				continue;
			}
			if (!StartTransaction())
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
				szCurrentReader = szCurrentReader + wcslen(szCurrentReader) + 1;
				SCardDisconnect(m_hCard, SCARD_LEAVE_CARD);
				m_hCard = NULL;
				continue;
			}
			fEndTransaction = TRUE;
			m_Card = CreateContext();
			if (!m_Card)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
				szCurrentReader = szCurrentReader + wcslen(szCurrentReader) + 1;
				SCardDisconnect(m_hCard, SCARD_LEAVE_CARD);
				m_hCard = NULL;
				continue;
			}
			DWORD dwMaxContainer = m_Card->GetMaxContainer();
			for(DWORD dwI = 0; dwI < dwMaxContainer; dwI++)
			{
				if (m_Card->GetContainerName(dwI, szContainer))
				{
					m_Card->GetKeySpec(dwI, &returnValue->names[returnValue->dwNumberOfNCryptKeyName].dwLegacyKeySpec);
					returnValue->names[returnValue->dwNumberOfNCryptKeyName].pszAlgid = BCRYPT_RSA_ALGORITHM;
					returnValue->names[returnValue->dwNumberOfNCryptKeyName].dwFlags = 0;
					returnValue->names[returnValue->dwNumberOfNCryptKeyName].pszName = returnValue->szContainerName[returnValue->dwNumberOfNCryptKeyName];
					MultiByteToWideChar(CP_ACP, 0, szContainer, -1, returnValue->szContainerName[returnValue->dwNumberOfNCryptKeyName], (int)(strlen(szContainer) + 1 ) * 2);
					returnValue->dwNumberOfNCryptKeyName++;
				}
			}
			delete m_Card;
			m_Card = NULL;
			SCardDisconnect(m_hCard, SCARD_LEAVE_CARD);
			m_hCard = NULL;
			szCurrentReader = szCurrentReader + wcslen(szCurrentReader) + 1;
		}
	}
	__finally
	{
		if (fEndTransaction)
			EndTransaction(0, FALSE);
		if (m_hCard)
		{
			SCardDisconnect(m_hCard, SCARD_LEAVE_CARD);
			m_hCard = NULL;
		}
		if (m_hContext && pmszReaders) 
			SCardFreeMemory( m_hContext, pmszReaders );
		if (m_hContext)
		{
			SCardReleaseContext(m_hContext);
			m_hContext = NULL;
		}
	}
	SetLastError(dwError);
	return returnValue;
}

_Success_(return) BOOL KspContainer::EnumKeys(
							__in_opt LPCWSTR pszScope,
							__deref_out NCryptKeyName **ppKeyName,
							__inout PVOID * ppEnumState,
							__in    DWORD   dwFlags)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	__try
	{
		Trace(TRACE_LEVEL_VERBOSE, L"Enter");
		if (!ppKeyName)
		{
			dwError = ERROR_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_ERROR, L"ppKeyName NULL");
			__leave;
		}
		if (!*ppEnumState)
		{
			*ppEnumState = KspContainer::BuildEnumData(pszScope);
			if (!*ppEnumState )
			{
				dwError = GetLastError();
				__leave;
			}
		}
		if (((KspEnumNCryptKeyName*)(*ppEnumState))->dwCurrentNCryptKeyName >= ((KspEnumNCryptKeyName*)(*ppEnumState))->dwNumberOfNCryptKeyName)
		{
			dwError = NTE_NO_MORE_ITEMS;
			Trace(TRACE_LEVEL_INFO, L"No more container because max reached");
			__leave;
		}
		NCryptKeyName* keyInfo = ((KspEnumNCryptKeyName*)(*ppEnumState))->names + ((KspEnumNCryptKeyName*)(*ppEnumState))->dwCurrentNCryptKeyName;
		Trace(TRACE_LEVEL_INFO, L"container: %s alg %s keyspec %d flag %d", keyInfo->pszName, keyInfo->pszAlgid, keyInfo->dwLegacyKeySpec, keyInfo->dwFlags);
		size_t keynamesize = (wcslen(keyInfo->pszName) + 1 ) * 2;
		size_t algsize = (wcslen(keyInfo->pszAlgid) + 1 ) * 2;
		size_t size = sizeof(NCryptKeyName) + keynamesize + algsize;
		*ppKeyName = (NCryptKeyName *) malloc(size);
		if (!*ppKeyName )
		{
			dwError = ERROR_OUTOFMEMORY;
			Trace(TRACE_LEVEL_ERROR, L"ERROR_OUTOFMEMORY");
			__leave;
		}
		RtlCopyMemory(*ppKeyName, keyInfo, sizeof(NCryptKeyName));
		(*ppKeyName)->pszName = (PWSTR) ((ULONG_PTR) (*ppKeyName) + sizeof(NCryptKeyName));
		(*ppKeyName)->pszAlgid = (PWSTR) ((ULONG_PTR) (*ppKeyName) + sizeof(NCryptKeyName) + keynamesize);
		RtlCopyMemory((*ppKeyName)->pszName, keyInfo->pszName, keynamesize);
		RtlCopyMemory((*ppKeyName)->pszAlgid, keyInfo->pszAlgid, algsize);
		// set iteration to next item
		((KspEnumNCryptKeyName*)(*ppEnumState))->dwCurrentNCryptKeyName++;
		fReturn = TRUE;
	}
	__finally
	{
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL KspKey::LoadPublicKey()
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	PBYTE pPubKey = NULL;
	DWORD dwSize = 0;
	BCRYPT_RSAKEY_BLOB* pBcryptPublicKey = NULL;
	__try
	{
		if (!m_Card->GetPublicKey(m_dwCardContainerId, &pPubKey, &dwSize))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"GetPublicKey failed 0x%08X", dwError);
			__leave;
		}

		m_dwLegacyKeySpec = (((BLOBHEADER*) pPubKey)->aiKeyAlg == CALG_RSA_KEYX ? AT_KEYEXCHANGE : AT_SIGNATURE);
		DWORD dwBcryptPublicKeySize = (DWORD) (sizeof(BCRYPT_RSAKEY_BLOB) + sizeof(DWORD) + ((RSAPUBLICKEYBLOB*) pPubKey)->rsapubkey.bitlen / 8);
		pBcryptPublicKey = (BCRYPT_RSAKEY_BLOB*) malloc(dwBcryptPublicKeySize);
		if (!pBcryptPublicKey)
		{
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}
		ZeroMemory(pBcryptPublicKey,dwBcryptPublicKeySize);
		pBcryptPublicKey->Magic = BCRYPT_RSAPUBLIC_MAGIC;
		pBcryptPublicKey->BitLength = ((RSAPUBLICKEYBLOB*) pPubKey)->rsapubkey.bitlen;
		pBcryptPublicKey->cbPublicExp = sizeof(DWORD);
		pBcryptPublicKey->cbModulus = ((RSAPUBLICKEYBLOB*) pPubKey)->rsapubkey.bitlen / 8;
		((PBYTE)pBcryptPublicKey)[sizeof(BCRYPT_RSAKEY_BLOB)] = ((RSAPUBLICKEYBLOB*) pPubKey)->rsapubkey.pubexp >> 24;
		((PBYTE)pBcryptPublicKey)[sizeof(BCRYPT_RSAKEY_BLOB) + 1] = (BYTE) ((((RSAPUBLICKEYBLOB*) pPubKey)->rsapubkey.pubexp & 0xFF0000) >> 16);
		((PBYTE)pBcryptPublicKey)[sizeof(BCRYPT_RSAKEY_BLOB) + 2] = (((RSAPUBLICKEYBLOB*) pPubKey)->rsapubkey.pubexp & 0xFF00) >> 8;
		((PBYTE)pBcryptPublicKey)[sizeof(BCRYPT_RSAKEY_BLOB) + 3] = (((RSAPUBLICKEYBLOB*) pPubKey)->rsapubkey.pubexp & 0xFF);
		for(DWORD dwI = 0; dwI < pBcryptPublicKey->cbModulus; dwI++)
		{
			((PBYTE)pBcryptPublicKey)[sizeof(BCRYPT_RSAKEY_BLOB) + 4 + dwI] = ((RSAPUBLICKEYBLOB*) pPubKey)->modulus[pBcryptPublicKey->cbModulus -1 - dwI];
		}
		
		dwError = BCryptOpenAlgorithmProvider(
													&m_hAlgProv,
													BCRYPT_RSA_ALGORITHM,
													NULL,
													0);
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR,L"BCryptOpenAlgorithmProvider failed 0x%08X", dwError);
			__leave;
		}
		dwError = BCryptImportKeyPair(m_hAlgProv,NULL,BCRYPT_RSAPUBLIC_BLOB,&m_key,(PUCHAR) pBcryptPublicKey, dwBcryptPublicKeySize,0);
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR,L"BCryptImportKeyPair failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pBcryptPublicKey)
			free(pBcryptPublicKey);
		if (pPubKey)
			free(pPubKey);
	}
	SetLastError(dwError);
	return fReturn;
}

KspKey* KspKey::LoadKey(KspContainer* kspcontainer, __in PCWSTR szReaderGiven, __in_opt PCWSTR szKeyName)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	KspKey* key = NULL;
	DWORD dwProtocol;
	BOOL fEndTransaction = FALSE;
	DWORD cch = SCARD_AUTOALLOCATE;
	PWSTR pmszReaders = NULL;
	PWSTR szCurrentReader = NULL;
	CHAR szContainer[MAX_CONTAINER_NAME];
	PSTR szContainerFromKeyName = NULL;
	__try
	{
		if (szKeyName)
		{
			WideCharToMultiByte(CP_ACP, 0, szKeyName, -1, szContainer, ARRAYSIZE(szContainer), NULL, NULL);
			szContainerFromKeyName = szContainer;
		}
		key = KspKey::Allocate(kspcontainer);
		if (!key)
		{
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}
		Trace(TRACE_LEVEL_INFO, L"Trying to load the container %s", szKeyName);
		dwError = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &key->m_hContext);
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR,L"SCardEstablishContext failed 0x%08X", dwError);
			__leave;
		}
		// reader name is submitted
		if (szReaderGiven)
		{
			wcscpy_s(key->m_szReader, MAX_READER_NAME, szReaderGiven);
			dwError = SCardConnect(key->m_hContext, key->m_szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &key->m_hCard, &dwProtocol);
			if (dwError)
			{
				Trace(TRACE_LEVEL_ERROR,L"SCardConnectA failed 0x%08X", dwError);
				__leave;
			}
			if (!key->StartTransaction())
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
				__leave;
			}
			fEndTransaction = TRUE;
			key->m_Card = key->CreateContext();
			if (!key->m_Card)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
				__leave;
			}
			if (!key->m_Card->LocateContainer(szContainerFromKeyName, &key->m_dwCardContainerId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"LocateContainer returned 0x%08X", dwError);
				__leave;
			}
			//OK
		}
		else
		{
			// identity a reader
			dwError = SCardListReaders(key->m_hContext,
                           NULL,
                           (LPWSTR)&pmszReaders,
                           &cch );
			if (dwError || !pmszReaders)
			{
				Trace(TRACE_LEVEL_ERROR,L"SCardListReadersA failed 0x%08X", dwError);
				__leave;
			}
			szCurrentReader = pmszReaders;
			while('\0' != *szCurrentReader)
			{
				dwError = SCardConnect(key->m_hContext, szCurrentReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &key->m_hCard, &dwProtocol);
				if (dwError)
				{
					Trace(TRACE_LEVEL_INFO, L"reader %S is empty", szCurrentReader);
					szCurrentReader = szCurrentReader + wcslen(szCurrentReader) + 1;
					continue;
				}
				if (!key->StartTransaction())
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
					szCurrentReader = szCurrentReader + wcslen(szCurrentReader) + 1;
					SCardDisconnect(key->m_hCard, SCARD_LEAVE_CARD);
					key->m_hCard = NULL;
					fEndTransaction = FALSE;
					continue;
				}
				fEndTransaction = TRUE;
				key->m_Card = key->CreateContext();
				if (!key->m_Card)
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
					szCurrentReader = szCurrentReader + wcslen(szCurrentReader) + 1;
					SCardEndTransaction(key->m_hCard, SCARD_LEAVE_CARD);
					SCardDisconnect(key->m_hCard, SCARD_LEAVE_CARD);
					key->m_hCard = NULL;
					fEndTransaction = FALSE;
					continue;
				}
				if (!key->m_Card->LocateContainer(szContainerFromKeyName, &key->m_dwCardContainerId))
				{
					Trace(TRACE_LEVEL_INFO, L"couldn't locate container in reader %S", szCurrentReader);
					szCurrentReader = szCurrentReader + wcslen(szCurrentReader) + 1;
					SCardEndTransaction(key->m_hCard, SCARD_LEAVE_CARD);
					delete key->m_Card;
					key->m_Card = NULL;
					SCardDisconnect(key->m_hCard, SCARD_LEAVE_CARD);
					key->m_hCard = NULL;
					fEndTransaction = FALSE;
					continue;
				} 
				// handle multiple smart card with the same container name ?
				wcscpy_s(key->m_szReader, MAX_READER_NAME, szCurrentReader);
				break;
			}
		}
		if (!szKeyName || szKeyName[0] == 0)
		{
			if (!key->m_Card->GetContainerName(key->m_dwCardContainerId, szContainer))
			{
				dwError = NTE_KEYSET_NOT_DEF;
				Trace(TRACE_LEVEL_ERROR,L"unable to load the container name");
				__leave;
			}
			size_t size = (strlen(szContainer) + 1);
			key->m_szKeyName = (PTSTR) malloc(size * sizeof(WCHAR));
			if (!key->m_szKeyName)
			{
				dwError = ERROR_OUTOFMEMORY;
				__leave;
			}
			MultiByteToWideChar(CP_ACP, 0, szContainer, -1, (PWSTR) key->m_szKeyName, (int) size);
		}
		else
		{
			size_t size = (wcslen(szKeyName) + 1) * sizeof(WCHAR);
			key->m_szKeyName = (PTSTR) malloc(size);
			if (!key->m_szKeyName)
			{
				dwError = ERROR_OUTOFMEMORY;
				__leave;
			}
			memcpy((PVOID) key->m_szKeyName, szKeyName, size);
		}
		if (!key->LoadPublicKey())
		{
			dwError = GetLastError();
			__leave;
		}
		key->m_isFinalized = TRUE;
		fReturn = TRUE;
	}
	__finally
	{
		if (fEndTransaction)
			SCardEndTransaction(key->m_hCard, SCARD_LEAVE_CARD);
		if (!fReturn && key)
		{
			delete key;
			key = NULL;
		}
	}
	SetLastError(dwError);
	return key;
}

KspKey* KspKey::CreateNonPersitedKey(KspContainer* kspcontainer, 
									 __in_opt LPCWSTR szKeyName, 
									 __in    DWORD   dwLegacyKeySpec,
									__in_opt BCRYPT_ALG_HANDLE hProv,
									__in_opt BCRYPT_KEY_HANDLE hKey)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	KspKey* key = NULL;
	__try
	{
		if (szKeyName == NULL || szKeyName[0] == 0)
		{
			dwError = ERROR_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_ERROR,L"Key name is empty");
			__leave;
		}
		key = KspKey::Allocate(kspcontainer);
		if (!key)
		{
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}
		key->m_dwLegacyKeySpec = dwLegacyKeySpec;
		key->m_dwBitLength = 2048;
		key->m_isFinalized = FALSE;
		size_t size = (wcslen(szKeyName) + 1) * sizeof(WCHAR);
		key->m_szKeyName = (PTSTR) malloc(size);
		if (!key->m_szKeyName)
		{
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}
		memcpy((PVOID) key->m_szKeyName, szKeyName, size);
		if (hProv && hKey)
		{
			Trace(TRACE_LEVEL_INFO,L"Initialized with key material");
			key->m_hAlgProv = hProv;
			key->m_key = hKey;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn && key)
		{
			delete key;
			key = NULL;
		}
	}
	SetLastError(dwError);
	return key;
}

BOOL KspContainer::GetUserStoreWithAllCard(__out HCERTSTORE* phStore)
{
	DWORD dwError = 0;
	BOOL fEndTransaction = FALSE;
	DWORD cch = SCARD_AUTOALLOCATE;
	PSTR pmszReaders = NULL;
	PSTR szCurrentReader = NULL;
	DWORD dwProtocol = 0;
	BOOL fReturn = FALSE;
	HCERTSTORE hStore = NULL;
	__try
	{
		hStore = CertOpenStore(CERT_STORE_PROV_MEMORY,0,0,0,NULL);
		if (!hStore)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CertOpenStore failed 0x%08X", dwError);
			__leave;
		}
		dwError = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &m_hContext);
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR,L"SCardEstablishContext failed 0x%08X", dwError);
			__leave;
		}
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
				szCurrentReader = szCurrentReader + strlen(szCurrentReader) + 1;
				SCardDisconnect(m_hCard, SCARD_LEAVE_CARD);
				m_hCard = NULL;
				continue;
			}
			fEndTransaction = TRUE;
			m_Card = CreateContext();
			if (!m_Card)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR,L"LoadContainer failed 0x%08X", dwError);
				szCurrentReader = szCurrentReader + strlen(szCurrentReader) + 1;
				SCardDisconnect(m_hCard, SCARD_LEAVE_CARD);
				m_hCard = NULL;
				continue;
			}
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
					PopulateUserStoreFromContainerName(hStore, TEXT(KSPNAME), szContainer, dwKeySpec, pbBuffer, dwSize);
				}
			}
			delete m_Card;
			m_Card = NULL;
			SCardDisconnect(m_hCard, SCARD_LEAVE_CARD);
			m_hCard = NULL;
			szCurrentReader = szCurrentReader + strlen(szCurrentReader) + 1;
		}
		*phStore = hStore;
		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn && hStore)
			CertCloseStore(hStore, 0);
		if (fEndTransaction)
			EndTransaction(0, FALSE);
		if (m_hCard)
		{
			SCardDisconnect(m_hCard, SCARD_LEAVE_CARD);
			m_hCard = NULL;
		}
		if (m_hContext && pmszReaders) 
			SCardFreeMemory( m_hContext, pmszReaders );
		if (m_hContext)
		{
			SCardReleaseContext(m_hContext);
			m_hContext = NULL;
		}
	}
	SetLastError(dwError);
	return fReturn;
}

KspKey::KspKey(KspContainer* kspcontainer)
{
	m_szKeyName = NULL;
	m_key = NULL;
	m_kspcontainer = kspcontainer;
	m_VerifyContext = FALSE;
	m_hAlgProv = NULL;
	m_key = NULL;
	m_dwBitLength = 0;
	m_dwCardContainerId = 0;
	m_dwBitLength = 0;
	m_isFinalized = FALSE;
	m_szReader[0] = 0;
}

KspKey::~KspKey()
{
	if (m_szKeyName)
		free((PVOID)m_szKeyName);
	if (m_key)
		BCryptDestroyKey(m_key);
	if (m_hAlgProv)
		BCryptCloseAlgorithmProvider(m_hAlgProv, 0);
}

_Success_(return) BOOL KspKey::GetKeyProperty(
__in    LPCWSTR pszProperty,
__out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
__in    DWORD   cbOutput,
__out   DWORD * pcbResult,
__in    DWORD   dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	DWORD cbResult = 0;
	__try
	{
		if (pcbResult == NULL)
		{
			dwError = NTE_INVALID_PARAMETER;
			__leave;
		}
		if((pszProperty == NULL)||
		  (wcslen(pszProperty) > NCRYPT_MAX_PROPERTY_NAME))
		{
			dwError = NTE_INVALID_PARAMETER;
			__leave;
		}
		if(wcscmp(pszProperty, NCRYPT_CERTIFICATE_PROPERTY) == 0)
		{
			*pcbResult = cbOutput;
			if (!LoadCertificate(pbOutput, pcbResult))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"LoadCertificate error 0x%08X", dwError);
				__leave;
			}
			fReturn = TRUE;
			__leave;
		}
		else if(wcscmp(pszProperty, NCRYPT_ALGORITHM_PROPERTY) == 0)
		{
			cbResult = sizeof(BCRYPT_RSA_ALGORITHM);
		}
		else if(wcscmp(pszProperty, NCRYPT_ALGORITHM_GROUP_PROPERTY) == 0)
		{
			cbResult = sizeof(NCRYPT_RSA_ALGORITHM_GROUP);
		}
		else if(wcscmp(pszProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0)
		{
			cbResult = sizeof(DWORD);
		}
		else if(wcscmp(pszProperty, NCRYPT_KEY_TYPE_PROPERTY) == 0)
		{
			cbResult = sizeof(DWORD);
		}
		else if(wcscmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0 ||
				wcscmp(pszProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0 ||
				wcscmp(pszProperty, NCRYPT_BLOCK_LENGTH_PROPERTY) == 0)
		{
			if (!m_isFinalized)
			{
				Trace(TRACE_LEVEL_ERROR, L"Key is not finalized");
				dwError = NTE_INVALID_HANDLE; // same error code returned than CNG
				__leave;
			}
			cbResult = sizeof(DWORD);
		}
		else if(wcscmp(pszProperty, NCRYPT_LENGTHS_PROPERTY) == 0)
		{
			cbResult = sizeof(NCRYPT_SUPPORTED_LENGTHS);
		}
		else if(wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0 ||
				wcscmp(pszProperty, NCRYPT_UNIQUE_NAME_PROPERTY) == 0)
		{
	        cbResult = (DWORD)(wcslen(m_szKeyName) + 1) * sizeof(WCHAR);
		}
		else
		{
			* pcbResult = 0;
			dwError = NTE_NOT_SUPPORTED;
			Trace(TRACE_LEVEL_ERROR, L"error property not suppored %s", pszProperty);
			__leave;
		}
		*pcbResult = cbResult;

		if(pbOutput == NULL)
		{
			fReturn = TRUE;
			__leave;
		}
		if(cbOutput < *pcbResult)
		{
			dwError = NTE_BUFFER_TOO_SMALL;
			Trace(TRACE_LEVEL_ERROR, L"buffer too small");
			__leave;
		}
		if(wcscmp(pszProperty, NCRYPT_ALGORITHM_PROPERTY) == 0)
		{
			CopyMemory(pbOutput, BCRYPT_RSA_ALGORITHM, sizeof(BCRYPT_RSA_ALGORITHM));
		}
		else if(wcscmp(pszProperty, NCRYPT_ALGORITHM_GROUP_PROPERTY) == 0)
		{
#pragma warning(suppress: 6386)
			CopyMemory(pbOutput, NCRYPT_RSA_ALGORITHM_GROUP, sizeof(NCRYPT_RSA_ALGORITHM_GROUP));
		}
		else if(wcscmp(pszProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0)
		{
			*(DWORD *)pbOutput = 0;
		}
		else if (wcscmp(pszProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0)
		{
			*(DWORD *)pbOutput = (m_dwLegacyKeySpec == AT_SIGNATURE ? NCRYPT_ALLOW_SIGNING_FLAG : NCRYPT_ALLOW_ALL_USAGES);
		}
		else if (wcscmp(pszProperty, NCRYPT_LENGTHS_PROPERTY) == 0)
		{
			((NCRYPT_SUPPORTED_LENGTHS*)pbOutput)->dwMinLength = 1024;
			((NCRYPT_SUPPORTED_LENGTHS*)pbOutput)->dwDefaultLength = 2048;
			((NCRYPT_SUPPORTED_LENGTHS*)pbOutput)->dwMaxLength = 3072;
			((NCRYPT_SUPPORTED_LENGTHS*)pbOutput)->dwIncrement = 1024;
		}
		else if(wcscmp(pszProperty, NCRYPT_BLOCK_LENGTH_PROPERTY) == 0 ||
				wcscmp(pszProperty, NCRYPT_KEY_TYPE_PROPERTY) == 0 || 
				wcscmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0)
		{
			dwError = BCryptGetProperty( m_key, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags);
			if (dwError)
			{
				Trace(TRACE_LEVEL_ERROR, L"BCryptGetProperty failed 0x%08X", dwError);
				__leave;
			}
		}
		else if(wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0 ||
			wcscmp(pszProperty, NCRYPT_UNIQUE_NAME_PROPERTY) == 0)
		{
	        CopyMemory(pbOutput, m_szKeyName, cbResult);
		}
		else
		{
			* pcbResult = 0;
			dwError = NTE_NOT_SUPPORTED;
			Trace(TRACE_LEVEL_ERROR, L"error property not suppored %s", pszProperty);
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

_Success_(return) BOOL KspKey::SetKeyProperty(
__in    LPCWSTR pszProperty,
__in_bcount(cbInput) PBYTE pbInput,
__in    DWORD   cbInput,
__in    DWORD   dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	__try
	{
		if((pszProperty == NULL)||
		  (wcslen(pszProperty) > NCRYPT_MAX_PROPERTY_NAME)||
		  (pbInput == NULL))
		{
			dwError = NTE_INVALID_PARAMETER;
			__leave;
		}
		if (wcscmp(pszProperty, NCRYPT_WINDOW_HANDLE_PROPERTY) == 0)
		{
			m_kspcontainer->m_hWnd = *((HWND*)pbInput);
		}
		else if (wcscmp(pszProperty, NCRYPT_CERTIFICATE_PROPERTY) == 0)
		{
			if (!m_isFinalized)
			{
				Trace(TRACE_LEVEL_ERROR, L"Key is not finalized");
				dwError = NTE_INVALID_HANDLE; // same error code returned than CNG
				__leave;
			}
			if (!SaveCertificate(pbInput, cbInput, m_dwLegacyKeySpec))
			{
				Trace(TRACE_LEVEL_ERROR, L"SaveCertificate failed 0x%08X", dwError);
				dwError = GetLastError();
				__leave;
			}
		}
		else if (wcscmp(pszProperty, NCRYPT_READER_PROPERTY) == 0)
		{
			if (m_isFinalized)
			{
				Trace(TRACE_LEVEL_ERROR, L"Key is finalized");
				dwError = NTE_INVALID_HANDLE; // same error code returned than CNG
				__leave;
			}
			wcscpy_s(m_szReader, MAX_READER_NAME, (PWSTR) pbInput);
		}
		else if (wcscmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0)
		{
			if (m_isFinalized)
			{
				Trace(TRACE_LEVEL_ERROR, L"Key is finalized");
				dwError = NTE_INVALID_HANDLE; // same error code returned than CNG
				__leave;
			}
			m_dwBitLength = *(PDWORD) (pbInput);
		}
		else
		{
			Trace(TRACE_LEVEL_ERROR, L"Invalid property %s", pszProperty);
			dwError = NTE_NOT_SUPPORTED;
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

_Success_(return) BOOL KspKey::ExportKey(
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	__try
	{
		if (!m_isFinalized)
		{
			Trace(TRACE_LEVEL_ERROR, L"Key is not finalized");
			dwError = NTE_INVALID_HANDLE; // same error code returned than CNG
			__leave;
		}
		dwError = BCryptExportKey(m_key, NULL, pszBlobType, pbOutput, cbOutput, pcbResult, dwFlags);
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR, L"BCryptExportKey failed 0x%08X", dwError);
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

_Success_(return) BOOL KspKey::Encrypt(
	__in_bcount(cbInput) PBYTE pbInput,
	__in    DWORD   cbInput,
	__in    VOID *pPaddingInfo,
	__out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
	__in    DWORD   cbOutput,
	__out   DWORD * pcbResult,
	__in    DWORD   dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
    __try
	{
		*pcbResult = 0;
		if(pbInput == NULL || cbInput == 0)
		{
			dwError = NTE_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_ERROR, L"no hash");
			__leave;
		}
		if(dwFlags & ~(NCRYPT_PAD_PKCS1_FLAG | NCRYPT_PAD_OAEP_FLAG | NCRYPT_NO_PADDING_FLAG | NCRYPT_SILENT_FLAG))
		{
			dwError = NTE_BAD_FLAGS;
			Trace(TRACE_LEVEL_ERROR, L"Invalid flag 0x%08X", dwFlags);
			__leave;
		}
		if (dwFlags & NCRYPT_PAD_PKCS1_FLAG)
		{
			if (pPaddingInfo)
			{
				dwError = NTE_INVALID_PARAMETER;
				Trace(TRACE_LEVEL_ERROR, L"pPaddingInfo present");
				__leave;
			}
		}
		else if (dwFlags & NCRYPT_PAD_OAEP_FLAG || dwFlags & NCRYPT_NO_PADDING_FLAG )
		{
			dwError = NTE_NOT_SUPPORTED;
			Trace(TRACE_LEVEL_ERROR, L"not supported");
			__leave;
		}
		if (m_dwLegacyKeySpec != AT_KEYEXCHANGE)
		{
			dwError = NTE_NOT_SUPPORTED;
			Trace(TRACE_LEVEL_ERROR, L"decryption not supported");
			__leave;
		}
		if (!m_isFinalized)
		{
			Trace(TRACE_LEVEL_ERROR, L"Key is not finalized");
			dwError = NTE_INVALID_HANDLE; // same error code returned than CNG
			__leave;
		}
		dwError = BCryptEncrypt(m_key, pbInput, cbInput, pPaddingInfo, NULL, 0, pbOutput, cbOutput, pcbResult, dwFlags);
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR, L"BCryptEncrypt failed 0x%08X", dwError);
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

_Success_(return) BOOL KspKey::Decrypt(
	__in_bcount(cbInput) PBYTE pbInput,
	__in    DWORD   cbInput,
	__in    VOID *pPaddingInfo,
	__out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
	__in    DWORD   cbOutput,
	__out   DWORD * pcbResult,
	__in    DWORD   dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	PCWSTR szAlgorithm = NULL;
	BOOL fEndTransaction = FALSE;
	BOOL fAuthenticated = FALSE;
	DWORD dwPinId = (DWORD) -1;
	PBYTE littleEndianBuffer = NULL;
	__try
	{
		*pcbResult = 0;
		if(pbInput == NULL || cbInput == 0)
		{
			dwError = NTE_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_ERROR, L"no hash");
			__leave;
		}
		if(dwFlags & ~(NCRYPT_PAD_PKCS1_FLAG | NCRYPT_PAD_OAEP_FLAG | NCRYPT_NO_PADDING_FLAG | NCRYPT_SILENT_FLAG))
		{
			dwError = NTE_BAD_FLAGS;
			Trace(TRACE_LEVEL_ERROR, L"Invalid flag 0x%08X", dwFlags);
			__leave;
		}
		if (dwFlags & NCRYPT_PAD_PKCS1_FLAG)
		{
			if (pPaddingInfo)
			{
				dwError = NTE_INVALID_PARAMETER;
				Trace(TRACE_LEVEL_ERROR, L"pPaddingInfo present");
				__leave;
			}
		}
		else if (dwFlags & NCRYPT_PAD_OAEP_FLAG || dwFlags & NCRYPT_NO_PADDING_FLAG )
		{
			dwError = NTE_NOT_SUPPORTED;
			Trace(TRACE_LEVEL_ERROR, L"not supported");
			__leave;
		}
		if (m_dwLegacyKeySpec != AT_KEYEXCHANGE)
		{
			dwError = NTE_NOT_SUPPORTED;
			Trace(TRACE_LEVEL_ERROR, L"decryption not supported");
			__leave;
		}
		if (!m_isFinalized)
		{
			Trace(TRACE_LEVEL_ERROR, L"Key is not finalized");
			dwError = NTE_INVALID_HANDLE; // same error code returned than CNG
			__leave;
		}
		m_AllowUI = !(dwFlags & NCRYPT_SILENT_FLAG);
		if (pbOutput == NULL)
		{
			// optimization
			ULONG dwSize = sizeof(DWORD);
			dwError = BCryptGetProperty(m_key, BCRYPT_SIGNATURE_LENGTH, (PBYTE) pcbResult, dwSize, &dwSize, 0);
			if (dwError)
			{
				Trace(TRACE_LEVEL_ERROR, L"BCryptGetProperty failed 0x%08X", dwError);
				__leave;
			}
			fReturn = TRUE;
			__leave;
		}
		littleEndianBuffer = (PBYTE) malloc(cbInput);
		if (!littleEndianBuffer)
		{
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}
		// re-revert the byte (signature stored in little endian for the interface)
		for(DWORD dwI = 0; dwI < cbInput; dwI++)
		{
			littleEndianBuffer[dwI] = pbInput[cbInput - 1 - dwI];
		}
		// get pin login and the logout
		if (!GetPIN(PIN_OPERATION_DECRYPT, &dwPinId))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetPIN failed 0x%08X", dwError);
			__leave;
		}
		if (!AskPinToUserIfNeeded(m_kspcontainer->m_hWnd, dwPinId))
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
		*pcbResult = cbOutput;
		if (!m_Card->Decrypt(m_dwCardContainerId, littleEndianBuffer, cbInput, pbOutput, pcbResult))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"SignData failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (littleEndianBuffer)
			free(littleEndianBuffer);
		if (fEndTransaction)
			EndTransaction(dwPinId, fAuthenticated);
	}
	SetLastError(dwError);
	return fReturn;
}

_Success_(return) BOOL KspKey::SignHash(
	__in_opt    VOID  *pPaddingInfo,
	__in_bcount(cbHashValue) PBYTE pbHashValue,
	__in    DWORD   cbHashValue,
	__out_bcount_part_opt(cbSignature, *pcbResult) PBYTE pbSignature,
	__in    DWORD   cbSignature,
	__out   DWORD * pcbResult,
	__in    DWORD   dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	PCWSTR szAlgorithm = NULL;
	BOOL fEndTransaction = FALSE;
	BOOL fAuthenticated = FALSE;
	DWORD dwPinId = (DWORD) -1;
	__try
	{
		*pcbResult = 0;
		if(pbHashValue == NULL || cbHashValue == 0)
		{
			dwError = NTE_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_ERROR, L"no hash");
			__leave;
		}
		if(dwFlags & ~(BCRYPT_PAD_PKCS1 | BCRYPT_PAD_PSS | NCRYPT_SILENT_FLAG))
		{
			dwError = NTE_BAD_FLAGS;
			Trace(TRACE_LEVEL_ERROR, L"Invalid flag");
			__leave;
		}
		if (dwFlags & BCRYPT_PAD_PKCS1)
		{
			if (!pPaddingInfo)
			{
				dwError = NTE_INVALID_PARAMETER;
				Trace(TRACE_LEVEL_ERROR, L"no pPaddingInfo");
				__leave;
			}
			BCRYPT_PKCS1_PADDING_INFO *pinf = (BCRYPT_PKCS1_PADDING_INFO*)pPaddingInfo;
			szAlgorithm = pinf->pszAlgId;
		}
		else if (dwFlags & BCRYPT_PAD_PSS)
		{
			if (!pPaddingInfo)
			{
				dwError = NTE_INVALID_PARAMETER;
				Trace(TRACE_LEVEL_ERROR, L"no pPaddingInfo");
				__leave;
			}
			dwError = NTE_NOT_SUPPORTED;
			Trace(TRACE_LEVEL_ERROR, L"not supported");
			__leave;
		}
		if (!m_isFinalized)
		{
			Trace(TRACE_LEVEL_ERROR, L"Key is not finalized");
			dwError = NTE_INVALID_HANDLE; // same error code returned than CNG
			__leave;
		}
		m_AllowUI = !(dwFlags & NCRYPT_SILENT_FLAG);
		if (pbSignature == NULL)
		{
			// optimization
			ULONG dwSize = sizeof(DWORD);
			dwError = BCryptGetProperty(m_key, BCRYPT_SIGNATURE_LENGTH, (PBYTE) pcbResult, dwSize, &dwSize, 0);
			if (dwError)
			{
				Trace(TRACE_LEVEL_ERROR, L"BCryptGetProperty failed 0x%08X", dwError);
				__leave;
			}
			fReturn = TRUE;
			__leave;
		}
		// get pin login and the logout
		if (!GetPIN(PIN_OPERATION_SIGN, &dwPinId))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetPIN failed 0x%08X", dwError);
			__leave;
		}
		if (!AskPinToUserIfNeeded(m_kspcontainer->m_hWnd, dwPinId))
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
		*pcbResult = cbSignature;
		if (!SignData(szAlgorithm, pbHashValue, cbHashValue, pbSignature, pcbResult))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"SignData failed 0x%08X", dwError);
			__leave;
		}
		// re-revert the byte (signature stored in little endian for the interface)
		for(DWORD dwI = 0; dwI < *pcbResult / 2; dwI++)
		{
			BYTE temp = pbSignature[dwI];
			pbSignature[dwI] = pbSignature[*pcbResult - 1 - dwI];
			pbSignature[*pcbResult - 1 - dwI] = temp;
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

_Success_(return) BOOL KspKey::VerifySignature(
__in_opt    VOID  *pPaddingInfo,
__in_bcount(cbHashValue) PBYTE pbHashValue,
__in    DWORD   cbHashValue,
 __in_bcount(cbSignature) PBYTE pbSignature,
__in    DWORD   cbSignature,
__in    DWORD   dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	__try
	{
		if (!m_isFinalized)
		{
			Trace(TRACE_LEVEL_ERROR, L"Key is not finalized");
			dwError = NTE_INVALID_HANDLE; // same error code returned than CNG
			__leave;
		}
		dwError = BCryptVerifySignature(m_key, pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignature, dwFlags);
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR, L"The signature verification failed 0x%08X", dwError);
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

_Success_(return) BOOL KspKey::DeleteKey(DWORD dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	DWORD dwPinId = 0;
	BOOL fEndTransaction = FALSE;
	BOOL fAuthenticated = FALSE;
	__try
	{
		if (!m_isFinalized)
		{
			Trace(TRACE_LEVEL_ERROR, L"Key is not finalized");
			dwError = NTE_INVALID_HANDLE; // same error code returned than CNG
			__leave;
		}
		m_AllowUI = !(dwFlags & NCRYPT_SILENT_FLAG);
		if (!GetPIN(PIN_OPERATION_DELETE, &dwPinId))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetPIN failed 0x%08X", dwError);
			__leave;
		}
		if (!AskPinToUserIfNeeded(m_kspcontainer->m_hWnd, dwPinId))
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
		Trace(TRACE_LEVEL_INFO, L"Freeing handle");
		m_kspcontainer->FreeKey((NCRYPT_KEY_HANDLE)this);
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

// tell if it is a OpenPGP card depending on the response on the applet selection
EXTERN_C BOOL WINAPI CheckForOpenPGPCardCheck(
  SCARDCONTEXT hSCardContext, // the card context passed in the parameter block
  SCARDHANDLE hCard,         // card handle
  PVOID pvUserData     // pointer to user data passed in the parameter block
)
{
	BYTE pbCmd[] = {0x00, 
		0xA4,
		0x04,
		0x00,
		0x06,
		0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
		0x00
	};
	BYTE recvbuf[256];
	DWORD recvlen = sizeof(recvbuf);
	DWORD dwReturn = SCardTransmit(hCard, 
									SCARD_PCI_T1, 
									pbCmd, 
									sizeof(pbCmd), 
									NULL, 
									recvbuf, 
									&recvlen);
	if ( dwReturn != SCARD_S_SUCCESS )
	{
		return FALSE;
	}
	if (recvlen < 2)
		return FALSE;
	if (recvbuf[recvlen -2] != 0x90 && recvbuf[recvlen -1] != 0x00)
		return FALSE;
	return TRUE;
}

EXTERN_C SCARDHANDLE WINAPI CheckForOpenPGPCardConnect(
  SCARDCONTEXT hSCardContext, // the card context passed in the parameter block
  PTSTR szReader,      // the name of the reader
  PTSTR mszCards,      // multiple string that contains
                 //    the possible card names in the reader
  PVOID pvUserData     // pointer to user data passed in parameter block
)
{
	SCARDHANDLE hCard = NULL;
	DWORD dwProtocol;
	DWORD dwError = SCardConnect(hSCardContext, szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &hCard, &dwProtocol);
	if (dwError)
	{
		Trace(TRACE_LEVEL_ERROR,L"Failed SCardConnect 0x%08X",dwError);
	}
	return hCard;
}

EXTERN_C void WINAPI CheckForOpenPGPCardDisconnect(
  SCARDCONTEXT hSCardContext, // the card context passed in the parameter block
  SCARDHANDLE hCard,         // card handle
  PVOID pvUserData     // pointer to user data passed in the parameter block
)
{
	SCardDisconnect(hCard, SCARD_LEAVE_CARD);
}

_Success_(return) BOOL KspKey::FinalizeKey(DWORD dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	DWORD dwPinId = 0;
	BOOL fEndTransaction = FALSE;
	BOOL fAuthenticated = FALSE;
	OPENCARDNAME_EX  dlgStruct = {0};
	OPENCARD_SEARCH_CRITERIA searchCriteria = {0};
	WCHAR szCardName[255];
	DWORD dwProtocol = 0;
	ALG_ID Algid = 0;
	CHAR szContainerNameTemp[MAX_CONTAINER_NAME * 2];
	__try
	{
		if (m_isFinalized)
		{
			Trace(TRACE_LEVEL_ERROR, L"Key is already finalized");
			dwError = NTE_INVALID_HANDLE; // same error code returned than CNG
			__leave;
		}
		if (dwFlags & NCRYPT_SILENT_FLAG)
		{
			Trace(TRACE_LEVEL_ERROR, L"Silent context");
			dwError = NTE_SILENT_CONTEXT;
			__leave;
		}
		Algid = (m_dwLegacyKeySpec == AT_KEYEXCHANGE ? CALG_RSA_KEYX : CALG_RSA_SIGN);
		m_AllowUI = !(dwFlags & NCRYPT_SILENT_FLAG);
		dwError = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &m_hContext);
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR,L"SCardEstablishContext failed 0x%08X", dwError);
			__leave;
		}
		if (m_szReader[0] != 0)
		{
			// reader inputed using NcrypSetProperty
		}
		else
		{	
			dlgStruct.dwStructSize = sizeof(dlgStruct);
			dlgStruct.hSCardContext = m_hContext;
			dlgStruct.hwndOwner = m_kspcontainer->m_hWnd;
			dlgStruct.dwFlags = SC_DLG_MINIMAL_UI;
			dlgStruct.lpstrRdr = m_szReader;
			dlgStruct.nMaxRdr = ARRAYSIZE(m_szReader);
			dlgStruct.lpstrCard = szCardName;
			dlgStruct.nMaxCard = ARRAYSIZE(szCardName);
			dlgStruct.pOpenCardSearchCriteria = &searchCriteria;
			searchCriteria.dwStructSize = sizeof(searchCriteria);
			searchCriteria.lpfnCheck = CheckForOpenPGPCardCheck;
			searchCriteria.lpfnConnect = CheckForOpenPGPCardConnect;
			searchCriteria.lpfnDisconnect = CheckForOpenPGPCardDisconnect;

			// Display the select card dialog box.
			dwError = SCardUIDlgSelectCard(&dlgStruct);
			if ( SCARD_S_SUCCESS != dwError )
			{
				Trace(TRACE_LEVEL_ERROR,L"Failed SCardUIDlgSelectCard 0x%08X",dwError);
				__leave;
			}
		}
		dwError = SCardConnect(m_hContext, m_szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &m_hCard, &dwProtocol);
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR,L"Failed SCardConnect 0x%08X",dwError);
			__leave;
		}
		if (!StartTransaction())
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"Failed SCardConnect 0x%08X",dwError);
			__leave;
		}
		fEndTransaction = TRUE;
		m_Card = CreateContext();
		if (!m_Card)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"CreateContext failed 0x%08X", dwError);
			__leave;
		}
		if (!EndTransaction(0, FALSE))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"EndTransaction failed 0x%08X", dwError);
			__leave;
		}
		fEndTransaction = FALSE;
		//if import ?
		if (m_key != NULL)
		{
			//TODO 
			__leave;
		}
		// else generate
		else
		{
			if (!m_Card->GetKeyIdForNewKey(Algid, m_kspcontainer->m_hWnd, &m_dwCardContainerId))
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
			if (!AskPinToUserIfNeeded(m_kspcontainer->m_hWnd, dwPinId))
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
			if (!m_Card->GenerateKey(Algid, m_dwCardContainerId, m_dwBitLength))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"GenerateKey failed 0x%08X", dwError);
				__leave;
			}
			Trace(TRACE_LEVEL_VERBOSE, L"before SetContainerName");
			WideCharToMultiByte(CP_ACP, 0, m_szKeyName, -1, szContainerNameTemp, ARRAYSIZE(szContainerNameTemp), NULL, NULL);
			if (!m_Card->SetContainerName(szContainerNameTemp, m_dwCardContainerId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"RegisterAlias failed 0x%08X", dwError);
				__leave;
			}
			Trace(TRACE_LEVEL_VERBOSE, L"before GetPublicKey");
			if (!LoadPublicKey())
			{
				dwError = GetLastError();
				__leave;
			}
			//TODO
			fReturn = TRUE;
		}
	}
	__finally
	{
		if (fEndTransaction)
			EndTransaction(dwPinId, fAuthenticated);
		if (!fReturn)
		{
			// clean the reader
			m_szReader[0] = 0;
		}
	}
	SetLastError(dwError);
	return fReturn;
}

KspKey* KspContainer::ImportKey(
		__in_opt NCRYPT_KEY_HANDLE hImportKey,
		__in    LPCWSTR pszBlobType,
		__in_opt NCryptBufferDesc *pParameterList,
		__in_bcount(cbData) PBYTE pbData,
		__in    DWORD   cbData,
		__in    DWORD   dwFlags)
{
	SetLastError(NTE_NOT_SUPPORTED);
	return NULL;
	KspKey* key = NULL;
	DWORD dwError = 0;
	ULONG i;
	PWSTR szKeyName = NULL;
	DWORD dwLegacyKeySpec = AT_KEYEXCHANGE;
	BCRYPT_ALG_HANDLE hRSAAlg = NULL;
	BCRYPT_KEY_HANDLE hTmpKey = NULL;
	__try
	{
		if (wcscmp(pszBlobType, BCRYPT_RSAPRIVATE_BLOB) != 0
			&& wcscmp(pszBlobType, BCRYPT_RSAFULLPRIVATE_BLOB) != 0
			&& wcscmp(pszBlobType, LEGACY_RSAPRIVATE_BLOB) != 0)
		{
		}
		if (!pParameterList)
		{
			Trace(TRACE_LEVEL_ERROR, L"error pParameterList empty");
			__leave;
		}
		if (pParameterList->ulVersion != NCRYPTBUFFER_VERSION)
		{
			Trace(TRACE_LEVEL_ERROR, L"error pParameterList incompatible version %d", pParameterList->ulVersion);
			__leave;
		}
		for( i = 0; i< pParameterList->cBuffers; i++)
		{
			if (pParameterList->pBuffers[i].BufferType == NCRYPTBUFFER_PKCS_KEY_NAME)
			{
				szKeyName = (PWSTR) pParameterList->pBuffers[i].pvBuffer;
			}
		}

		dwError = BCryptOpenAlgorithmProvider(&hRSAAlg,
													BCRYPT_RSAPRIVATE_BLOB,
													NULL,
													0);
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR, L"BCryptOpenAlgorithmProvider failed 0x%08X", dwError);
			__leave;
		}
		dwError = BCryptImportKeyPair(hRSAAlg,(BCRYPT_KEY_HANDLE) hImportKey,pszBlobType,&hTmpKey,pbData,cbData,0);
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR, L"BCryptImportKeyPair failed 0x%08X", dwError);
			__leave;
		}

		key = CreateNonPersistedKey(szKeyName, dwLegacyKeySpec, dwFlags, hRSAAlg, hTmpKey);
		if (!key)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"error LoadKey 0x%08X", dwError);
			__leave;
		}
		hRSAAlg = NULL;
		hTmpKey = NULL;
		if (!(dwFlags & NCRYPT_DO_NOT_FINALIZE_FLAG))
		{
			if (!key->FinalizeKey(dwFlags & NCRYPT_SILENT_FLAG))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"error FinalizeKey 0x%08X", dwError);
				FreeKey((NCRYPT_KEY_HANDLE) key);
				key = NULL;
				__leave;
			}
		}
	}
	__finally
	{
		if (hTmpKey)
			BCryptDestroyKey(hTmpKey);
		if (hRSAAlg)
			BCryptCloseAlgorithmProvider(hRSAAlg, 0);
	}
	SetLastError(dwError);
	return key;
	
	
	/*DWORD dwError = 0;
	BOOL fReturn = FALSE;
	BOOL fEndTransaction = FALSE;
	BOOL fAuthenticated = FALSE;
	DWORD dwPinId = 0;
	BCRYPT_ALG_HANDLE hRSAAlg = NULL;
	BCRYPT_KEY_HANDLE hTmpKey = NULL;
	DWORD dwSize = 0;
	PBYTE pbTempKey = NULL;
	KspKey* outKey = NULL;
	__try
	{
		if (!pbData)
		{
			dwError = ERROR_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_ERROR, L"pbData NULL");
			__leave;
		}

		if (wcscmp(pszBlobType, BCRYPT_RSAPRIVATE_BLOB) == 0)
		{
			if (cbData < sizeof(BCRYPT_RSAKEY_BLOB))
			{
				dwError  = NTE_BAD_DATA;
				Trace(TRACE_LEVEL_ERROR, L"cbDataLen %d < BLOB", cbData);
				__leave;
			}
			Trace(TRACE_LEVEL_VERBOSE, L"dwFlags %d", dwFlags);

			if (dwFlags & NCRYPT_DO_NOT_FINALIZE_FLAG)
			{
				dwError  = NTE_BAD_FLAGS;
				Trace(TRACE_LEVEL_ERROR, L"dwFlags 0x%08X exportable", dwFlags);
				__leave;
			}
			
			outKey = new KspKey(this);

			dwError = BCryptOpenAlgorithmProvider(&hRSAAlg,
													BCRYPT_RSAPRIVATE_BLOB,
													NULL,
													0);
			if (dwError)
			{
				printf("error BCryptOpenAlgorithmProvider 0x%08X\r\n", dwError);
				__leave;
			}
			dwError = BCryptImportKeyPair(hRSAAlg,(BCRYPT_KEY_HANDLE) hImportKey,BCRYPT_RSAPRIVATE_BLOB,&hTmpKey,pbData,cbData,0);
			if (dwError)
			{
				printf("error BCryptImportKeyPair 0x%08X\r\n", dwError);
				__leave;
			}
			dwError = BCryptExportKey(hTmpKey, NULL, LEGACY_RSAPRIVATE_BLOB, NULL, 0, &dwSize, NULL);
			if (dwError)
			{
				printf("error BCryptExportKey 0x%08X\r\n", dwError);
				__leave;
			}
			pbTempKey = (PBYTE) malloc(dwSize);
			if (!pbTempKey)
			{
				dwError = ERROR_OUTOFMEMORY;
				__leave;
			}
			dwError = BCryptExportKey(hTmpKey, NULL, LEGACY_RSAPRIVATE_BLOB, pbTempKey, dwSize, &dwSize, NULL);
			if (dwError)
			{
				printf("error BCryptExportKey 0x%08X\r\n", dwError);
				__leave;
			}
			if (!m_Card->GetKeyIdForNewKey(header->aiKeyAlg,&m_dwCardContainerId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"GetPIN failed 0x%08X", dwError);
				__leave;
			}
			if (!GetPIN(PIN_OPERATION_CREATE, &dwPinId))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"GetPIN failed 0x%08X", dwError);
				__leave;
			}
			if (!AskPinToUserIfNeeded(m_hWnd, dwPinId))
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
		
		m_keyHandles.push_back(handle);
		*phKey = (HCRYPTKEY) handle;
		fReturn = TRUE;
	}
	__finally
	{
		if (pbTempKey)
		{
			SecureZeroMemory(pbTempKey, dwSize);
			free(pbTempKey);
		}
		if (hTmpKey)
			BCryptDestroyKey(hTmpKey);
		if (hRSAAlg)
			BCryptCloseAlgorithmProvider(hRSAAlg,0);
		if (!fReturn)
		{
			if (hMyKey) CryptDestroyKey(hMyKey);
		}
		if (fEndTransaction)
			EndTransaction(dwPinId, fAuthenticated);
	}
	SetLastError(dwError);
	return fReturn;*/
	//TODO

	//if (NCRYPT_DO_NOT_FINALIZE_FLAG )


	return NULL;
}