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


NCRYPT_KEY_STORAGE_FUNCTION_TABLE KSPFunctionTable =
{
    NCRYPT_KEY_STORAGE_INTERFACE_VERSION,
    KSPOpenProvider,
    KSPOpenKey,
    KSPCreatePersistedKey,
    KSPGetProviderProperty,
    KSPGetKeyProperty,
    KSPSetProviderProperty,
    KSPSetKeyProperty,
    KSPFinalizeKey,
    KSPDeleteKey,
    KSPFreeProvider,
    KSPFreeKey,
    KSPFreeBuffer,
    KSPEncrypt,
    KSPDecrypt,
    KSPIsAlgSupported,
    KSPEnumAlgorithms,
    KSPEnumKeys,
    KSPImportKey,
    KSPExportKey,
    KSPSignHash,
    KSPVerifySignature,
    KSPPromptUser,
    KSPNotifyChangeKey,
    KSPSecretAgreement,
    KSPDeriveKey,
    KSPFreeSecret
};

///////////////////////////////////////////////////////////////////////////////
/******************************************************************************
* DESCRIPTION :     Get the  KSP key storage Interface function
*                   dispatch table
*
* INPUTS :
*            LPCWSTR pszProviderName        Name of the provider (unused)
*            DWORD   dwFlags                Flags (unused)
* OUTPUTS :
*            char    **ppFunctionTable      The key storage interface function
*                                           dispatch table
* RETURN :
*            ERROR_SUCCESS                  The function was successful.
*/
__checkReturn
NTSTATUS
WINAPI
GetKeyStorageInterface(
    __in   LPCWSTR  pszProviderName,
    __out  NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
    __in   DWORD    dwFlags)
{

    UNREFERENCED_PARAMETER(pszProviderName);
    UNREFERENCED_PARAMETER(dwFlags);
	Trace(TRACE_LEVEL_INFO, L"--> GetKeyStorageInterface");
    *ppFunctionTable = &KSPFunctionTable;
	Trace(TRACE_LEVEL_INFO, L"<-- GetKeyStorageInterface");
    return ERROR_SUCCESS;
}

/*******************************************************************
* DESCRIPTION :     Load and initialize the Sample KSP provider
*
* INPUTS :
*            LPCWSTR pszProviderName         Name of the provider
*            DWORD   dwFlags                 Flags (unused)
* OUTPUTS :
*            NCRYPT_PROV_HANDLE *phProvider  The provider handle
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
KSPOpenProvider(
    __out   NCRYPT_PROV_HANDLE *phProvider,
    __in    LPCWSTR pszProviderName,
    __in    DWORD   dwFlags)
{
	Trace(TRACE_LEVEL_INFO, L"--> KSPOpenProvider");
	if (wcscmp(pszProviderName, TEXT(KSPNAME)) != 0)
	{
		Trace(TRACE_LEVEL_ERROR, L"Invalid provider name %s", pszProviderName);
		Trace(TRACE_LEVEL_INFO, L"<-- KSPOpenProvider FALSE NTE_INVALID_PARAMETER");
		return NTE_INVALID_PARAMETER;
	}
	KspContainer* container = KspContainer::Create();
	if (container == NULL)
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPOpenProvider FALSE ERROR_OUTOFMEMORY");
		return ERROR_OUTOFMEMORY;
	}
	*phProvider = container->getProviderHandle();
	Trace(TRACE_LEVEL_INFO, L"<-- KSPOpenProvider TRUE Handle 0x%Ix", *phProvider);
    return ERROR_SUCCESS;
}

/******************************************************************************
* DESCRIPTION :     Release a handle to the sample KSP provider
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the sample KSP provider
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*/
SECURITY_STATUS
WINAPI
KSPFreeProvider(
    __in    NCRYPT_PROV_HANDLE hProvider)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> KSPFreeProvider");
	__try
	{
		KspContainer* container =KspContainer::GetContainerFromHandle(hProvider);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->Unload();
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"Unload failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPFreeProvider %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}

/******************************************************************************
* DESCRIPTION :     Open a key in the SAMPLE key storage provider
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the sample KSP provider
*            LPCWSTR pszKeyName              Name of the key
             DWORD  dwLegacyKeySpec          Flags for legacy key support (unused)
*            DWORD   dwFlags                 Flags (unused)
* OUTPUTS:
*            NCRYPT_KEY_HANDLE               A handle to the opened key
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
KSPOpenKey(
    __inout NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszKeyName,
    __in_opt DWORD  dwLegacyKeySpec,
    __in    DWORD   dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> KSPOpenKey");
	__try
	{
		KspContainer* container = KspContainer::GetContainerFromHandle(hProvider);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		KspKey* key = container->OpenKey(pszKeyName,dwLegacyKeySpec, dwFlags & NCRYPT_SILENT_FLAG);
		if (!key)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"OpenKey failed 0x%08X", dwError);
			__leave;
		}
		Trace(TRACE_LEVEL_VERBOSE, L"Key handle: 0x%p", key);
		*phKey = (NCRYPT_KEY_HANDLE) key;
		fReturn = TRUE;
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPOpenKey %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}

/******************************************************************************
* DESCRIPTION :     Create a new key and stored it into the user profile
*                   key storage area
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the sample KSP provider
*            LPCWSTR pszAlgId                Cryptographic algorithm to create the key
*            LPCWSTR pszKeyName              Name of the key
*            DWORD  dwLegacyKeySpec          Flags for legacy key support (unused)
*            DWORD   dwFlags                 0|NCRYPT_OVERWRITE_KEY_FLAG
* OUTPUTS:
*            NCRYPT_KEY_HANDLE               A handle to the opened key
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_EXISTS                      The key already exists.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*            NTE_NOT_SUPPORTED               The algorithm is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
KSPCreatePersistedKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszAlgId,
    __in_opt LPCWSTR pszKeyName,
    __in    DWORD   dwLegacyKeySpec,
    __in    DWORD   dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> KSPCreatePersistedKey %s %s %d %d", pszAlgId, pszKeyName, dwLegacyKeySpec, dwFlags);
	__try
	{
		KspContainer* container = KspContainer::GetContainerFromHandle(hProvider);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		KspKey* key = container->CreateNonPersistedKey(pszKeyName, dwLegacyKeySpec, dwFlags, NULL, NULL);
		if (!key)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CreateNonPersistedKey failed 0x%08X", dwError);
			__leave;
		}
		Trace(TRACE_LEVEL_VERBOSE, L"Key handle: 0x%p", key);
		*phKey = (NCRYPT_KEY_HANDLE) key;
		fReturn = TRUE;
    }
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPCreatePersistedKey %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}


/******************************************************************************
* DESCRIPTION :  Retrieves the value of a named property for a key storage
*                provider object.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the sample KSP provider
*            LPCWSTR pszProperty             Name of the property
*            DWORD   cbOutput                Size of the output buffer
*            DWORD   dwFlags                 Flags
* OUTPUTS:
*            PBYTE   pbOutput                Output buffer containing the value
*                                            of the property.  If pbOutput is NULL,
*                                            required buffer size will return in
*                                            *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_NOT_FOUND                   Cannot find such a property.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_NOT_SUPPORTED               The property is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
KSPGetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> KSPGetProviderProperty %s", pszProperty);
	__try
	{
		KspContainer* container = KspContainer::GetContainerFromHandle(hProvider);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		if (!container->GetProviderProperty(pszProperty,pbOutput, cbOutput, pcbResult, dwFlags))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetProviderProperty failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPGetProviderProperty %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}

/******************************************************************************
* DESCRIPTION :  Retrieves the value of a named property for a key storage
*                key object.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a sample KSP provider
*                                            object
*            NCRYPT_KEY_HANDLE hKey          A handle to a sample KSP key object
*            LPCWSTR pszProperty             Name of the property
*            DWORD   cbOutput                Size of the output buffer
*            DWORD   dwFlags                 Flags
* OUTPUTS:
*            PBYTE   pbOutput                Output buffer containing the value
*                                            of the property.  If pbOutput is NULL,
*                                            required buffer size will return in
*                                            *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_NOT_FOUND                   Cannot find such a property.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_NOT_SUPPORTED               The property is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
KSPGetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags)
{
    BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> KSPGetKeyProperty %s", pszProperty);
	__try
	{
		KspKey* key = KspContainer::GetKeyFromHandle(hProvider, hKey);
		if (!key)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKeyFromHandle failed 0x%08X", dwError);
			__leave;
		}
		if (!key->GetKeyProperty(pszProperty,pbOutput, cbOutput, pcbResult, dwFlags))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKeyProperty failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPGetKeyProperty %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}

/******************************************************************************
* DESCRIPTION :  Sets the value for a named property for a CNG key storage
*                provider object.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the sample KSP provider
*            LPCWSTR pszProperty             Name of the property
*            PBYTE   pbInput                 Input buffer containing the value
*                                            of the property
*            DWORD   cbOutput                Size of the input buffer
*            DWORD   dwFlags                 Flags
*
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NOT_SUPPORTED               The property is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
KSPSetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags)
{
    BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> KSPSetProviderProperty %s", pszProperty);
	__try
	{
		KspContainer* container = KspContainer::GetContainerFromHandle(hProvider);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		if (!container->SetProviderProperty(pszProperty,pbInput, cbInput, dwFlags))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"SetProviderProperty failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPSetProviderProperty %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}

/******************************************************************************
* DESCRIPTION :  Set the value of a named property for a key storage
*                key object.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a sample KSP provider
*                                            object
*            NCRYPT_KEY_HANDLE hKey          A handle to a sample KSP key object
*            LPCWSTR pszProperty             Name of the property
*            PBYTE   pbInput                 Input buffer containing the value
*                                            of the property
*            DWORD   cbOutput                Size of the input buffer
*            DWORD   dwFlags                 Flags
*
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle or a valid key handle
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NOT_SUPPORTED               The property is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
KSPSetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags)
{
    BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> KSPSetKeyProperty %s", pszProperty);
	__try
	{
		KspKey* key = KspContainer::GetKeyFromHandle(hProvider, hKey);
		if (!key)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKeyFromHandle failed 0x%08X", dwError);
			__leave;
		}
		if (!key->SetKeyProperty(pszProperty,pbInput, cbInput, dwFlags))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"SetKeyProperty failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPSetKeyProperty %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}

/******************************************************************************
* DESCRIPTION :     Completes a sample key storage key. The key cannot be used
*                   until this function has been called.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the sample KSP provider
*            NCRYPT_KEY_HANDLE hKey          A handle to a sample KSP key
*            DWORD   dwFlags                 Flags
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*            NTE_BAD_FLAGS                   The dwFlags parameter contains a
*                                            value that is not valid.
*/
SECURITY_STATUS
WINAPI
KSPFinalizeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags)
{
    BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> KSPFinalizeKey 0x%08X", dwFlags);
	__try
	{
		KspKey* key = KspContainer::GetKeyFromHandle(hProvider, hKey);
		if (!key)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKeyFromHandle failed 0x%08X", dwError);
			__leave;
		}
		if (!key->FinalizeKey(dwFlags))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"SetKeyProperty failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPFinalizeKey %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}

/******************************************************************************
* DESCRIPTION :     Deletes a CNG sample KSP key
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the sample KSP provider
*            NCRYPT_KEY_HANDLE hKey          Handle to a sample KSP key
*            DWORD   dwFlags                 Flags
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider or key handle.
*            NTE_BAD_FLAGS                   The dwFlags parameter contains a
*                                            value that is not valid.
*            NTE_INTERNAL_ERROR              Key file deletion failed.
*/
SECURITY_STATUS
WINAPI
KSPDeleteKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags)
{
    BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> KSPDeleteKey 0x%Ix", hKey);
	__try
	{
		KspKey* key = KspContainer::GetKeyFromHandle(hProvider, hKey);
		if (!key)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKeyFromHandle failed 0x%08X", dwError);
			__leave;
		}
		if (!key->DeleteKey(dwFlags))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"DeleteKey failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPDeleteKey %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}

/******************************************************************************
* DESCRIPTION :     Free a CNG sample KSP key object
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the sample KSP provider
*            NCRYPT_KEY_HANDLE hKey          A handle to a sample KSP key
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*/
SECURITY_STATUS
WINAPI
KSPFreeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey)
{
    BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> KSPFreeKey 0x%Ix", hKey);
	__try
	{
		KspContainer* container = KspContainer::GetContainerFromHandle(hProvider);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		if (!container->FreeKey(hKey))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"FreeKey failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPFreeKey %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}

/******************************************************************************
* DESCRIPTION :     free a CNG sample KSP memory buffer object
*
* INPUTS :
*            PVOID   pvInput                 The buffer to free.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*/
SECURITY_STATUS
WINAPI
KSPFreeBuffer(
    __deref PVOID   pvInput)
{
	Trace(TRACE_LEVEL_INFO, L"--> KSPFreeBuffer 0x%p", pvInput);
	if (pvInput!= NULL)
		free(pvInput);
    return ERROR_SUCCESS;
}

/******************************************************************************
* DESCRIPTION :  encrypts a block of data.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a sample KSP provider
*                                            object.
*            NCRYPT_KEY_HANDLE hKey          A handle to a sample KSP key object.
*            PBYTE   pbInput                 Plain text data to be encrypted.
*            DWORD   cbInput                 Size of the plain text data.
*            VOID    *pPaddingInfo           Padding information if padding sheme
*                                            is used.
*            DWORD   cbOutput                Size of the output buffer.
*            DWORD   dwFlags                 Flags
* OUTPUTS:
*            PBYTE   pbOutput                Output buffer containing encrypted
*                                            data.  If pbOutput is NULL,
*                                            required buffer size will return in
*                                            *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_BAD_KEY_STATE               The key identified by the hKey
*                                            parameter has not been finalized
*                                            or is incomplete.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
KSPEncrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
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
	Trace(TRACE_LEVEL_INFO, L"--> KSPEncrypt");
	__try
	{
		KspKey* key = KspContainer::GetKeyFromHandle(hProvider, hKey);
		if (!key)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKeyFromHandle failed 0x%08X", dwError);
			__leave;
		}
		if (!key->Encrypt(pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, pcbResult, dwFlags))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"Encrypt failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPEncrypt %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}

/******************************************************************************
* DESCRIPTION :  Decrypts a block of data.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a sample KSP provider
*                                            object.
*            NCRYPT_KEY_HANDLE hKey          A handle to a sample KSP key object.
*            PBYTE   pbInput                 Encrypted data blob.
*            DWORD   cbInput                 Size of the encrypted data blob.
*            VOID    *pPaddingInfo           Padding information if padding sheme
*                                            is used.
*            DWORD   cbOutput                Size of the output buffer.
*            DWORD   dwFlags                 Flags
* OUTPUTS:
*            PBYTE   pbOutput                Output buffer containing decrypted
*                                            data.  If pbOutput is NULL,
*                                            required buffer size will return in
*                                            *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_BAD_KEY_STATE               The key identified by the hKey
*                                            parameter has not been finalized
*                                            or is incomplete.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
KSPDecrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
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
	Trace(TRACE_LEVEL_INFO, L"--> KSPDecrypt");
	__try
	{
		KspKey* key = KspContainer::GetKeyFromHandle(hProvider, hKey);
		if (!key)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKeyFromHandle failed 0x%08X", dwError);
			__leave;
		}
		if (!key->Decrypt(pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, pcbResult, dwFlags))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"Encrypt failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPDecrypt %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}

/******************************************************************************
* DESCRIPTION :  Determines if a sample key storage provider supports a
*                specific cryptographic algorithm.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a sample KSP provider
*                                            object
*            LPCWSTR pszAlgId                Name of the cryptographic
*                                            Algorithm in question
*            DWORD   dwFlags                 Flags
* RETURN :
*            ERROR_SUCCESS                   The algorithm is supported.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               This algorithm is not supported.
*/
SECURITY_STATUS
WINAPI
KSPIsAlgSupported(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszAlgId,
    __in    DWORD   dwFlags)
{
    BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> KSPIsAlgSupported");
	__try
	{
		KspContainer* container = KspContainer::GetContainerFromHandle(hProvider);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		if (!container->IsAlgSupported(pszAlgId, dwFlags))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"IsAlgSupported failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPIsAlgSupported %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}

/******************************************************************************
* DESCRIPTION :  Obtains the names of the algorithms that are supported by
*                the sample key storage provider.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a sample KSP provider
*                                            object.
*            DWORD   dwAlgOperations         The crypto operations that are to
*                                            be enumerated.
*            DWORD   dwFlags                 Flags
*
* OUTPUTS:
*            DWORD * pdwAlgCount             Number of supported algorithms.
*            NCryptAlgorithmName **ppAlgList List of supported algorithms.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               The crypto operations are not supported.
*/
SECURITY_STATUS
WINAPI
KSPEnumAlgorithms(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    DWORD   dwAlgOperations, // this is the crypto operations that are to be enumerated
    __out   DWORD * pdwAlgCount,
    __deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
    __in    DWORD   dwFlags)
{
    BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> KSPEnumAlgorithms");
	__try
	{
		KspContainer* container = KspContainer::GetContainerFromHandle(hProvider);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		if (!container->EnumAlgorithms(dwAlgOperations, pdwAlgCount, ppAlgList, dwFlags))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"EnumAlgorithms failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPEnumAlgorithms %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}

/******************************************************************************
* DESCRIPTION :  Obtains the names of the keys that are stored by the provider.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a sample KSP provider
*                                            object
*            LPCWSTR pszScope                Unused
*            NCryptKeyName **ppKeyName       Name of the retrieved key
*            PVOID * ppEnumState             Enumeration state information
*            DWORD   dwFlags                 Flags
*
* OUTPUTS:
*            PVOID * ppEnumState             Enumeration state information that
*                                            is used in subsequent calls to
*                                            this function.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               NCRYPT_MACHINE_KEY_FLAG is not
*                                            supported.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
KSPEnumKeys(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt LPCWSTR pszScope,
    __deref_out NCryptKeyName **ppKeyName,
    __inout PVOID * ppEnumState,
    __in    DWORD   dwFlags)
{
    BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> KSPEnumKeys");
	__try
	{
		KspContainer* container = KspContainer::GetContainerFromHandle(hProvider);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		if (!container->EnumKeys(pszScope, ppKeyName, ppEnumState, dwFlags))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"EnumKeys failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPEnumKeys %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}

/******************************************************************************
* DESCRIPTION :  Imports a key into the sample KSP from a memory BLOB.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider     A handle to a sample KSP provider
*                                             object.
*            NCRYPT_KEY_HANDLE hImportKey     Unused
*            LPCWSTR pszBlobType              Type of the key blob.
*            NCryptBufferDesc *pParameterList Additional parameter information.
*            PBYTE   pbData                   Key blob.
*            DWORD   cbData                   Size of the key blob.
*            DWORD   dwFlags                  Flags
*
* OUTPUTS:
*            NCRYPT_KEY_HANDLE *phKey        Sample KSP key object imported
*                                            from the key blob.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               The type of the key blob is not
*                                            supported.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*            NTE_INTERNAL_ERROR              Decoding failed.
*/
SECURITY_STATUS
WINAPI
KSPImportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hImportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in_bcount(cbData) PBYTE pbData,
    __in    DWORD   cbData,
    __in    DWORD   dwFlags)
{
    BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> KSPImportKey");
	__try
	{
		KspContainer* container = KspContainer::GetContainerFromHandle(hProvider);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		KspKey* key = container->ImportKey(hImportKey,pszBlobType, pParameterList, pbData, cbData, dwFlags);
		if (!key)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"OpenKey failed 0x%08X", dwError);
			__leave;
		}
		Trace(TRACE_LEVEL_VERBOSE, L"Key handle: 0x%p", key);
		*phKey = (NCRYPT_KEY_HANDLE) key;
		fReturn = TRUE;
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPImportKey %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}

/******************************************************************************
* DESCRIPTION :  Exports a sample key storage key into a memory BLOB.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider     A handle to a sample KSP provider
*                                             object.
*            NCRYPT_KEY_HANDLE hKey           A handle to the sample KSP key
*                                             object to export.
*            NCRYPT_KEY_HANDLE hExportKey     Unused
*            LPCWSTR pszBlobType              Type of the key blob.
*            NCryptBufferDesc *pParameterList Additional parameter information.
*            DWORD   cbOutput                 Size of the key blob.
*            DWORD   dwFlags                  Flags
*
* OUTPUTS:
*            PBYTE pbOutput                  Key blob.
*            DWORD * pcbResult               Required size of the key blob.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               The type of the key blob is not
*                                            supported.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*            NTE_INTERNAL_ERROR              Encoding failed.
*/
SECURITY_STATUS
WINAPI
KSPExportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt NCRYPT_KEY_HANDLE hExportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags)
{
    BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> KSPExportKey");
	__try
	{
		KspKey* key = KspContainer::GetKeyFromHandle(hProvider, hKey);
		if (!key)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKeyFromHandle failed 0x%08X", dwError);
			__leave;
		}
		if (!key->ExportKey(pszBlobType, pParameterList, pbOutput, cbOutput, pcbResult, dwFlags))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"SignHash failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPExportKey %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}

/******************************************************************************
* DESCRIPTION :  creates a signature of a hash value.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a sample KSP provider
*                                            object
*            NCRYPT_KEY_HANDLE hKey          A handle to a sample KSP key object
*            VOID    *pPaddingInfo           Padding information is padding sheme
*                                            is used
*            PBYTE  pbHashValue              Hash to sign.
*            DWORD  cbHashValue              Size of the hash.
*            DWORD  cbSignature              Size of the signature
*            DWORD  dwFlags                  Flags
* OUTPUTS:
*            PBYTE  pbSignature              Output buffer containing signature.
*                                            If pbOutput is NULL, required buffer
*                                            size will return in *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_BAD_KEY_STATE               The key identified by the hKey
*                                            parameter has not been finalized
*                                            or is incomplete.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
KSPSignHash(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
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
	Trace(TRACE_LEVEL_INFO, L"--> KSPSignHash");
	__try
	{
		KspKey* key = KspContainer::GetKeyFromHandle(hProvider, hKey);
		if (!key)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKeyFromHandle failed 0x%08X", dwError);
			__leave;
		}
		if (!key->SignHash(pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignature, pcbResult, dwFlags))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"SignHash failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPSignHash %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}

/******************************************************************************
* DESCRIPTION :  Verifies that the specified signature matches the specified hash
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a sample KSP provider
*                                            object.
*            NCRYPT_KEY_HANDLE hKey          A handle to a sample KSP key object
*            VOID    *pPaddingInfo           Padding information is padding sheme
*                                            is used.
*            PBYTE  pbHashValue              Hash data
*            DWORD  cbHashValue              Size of the hash
*            PBYTE  pbSignature              Signature data
*            DWORD  cbSignaturee             Size of the signature
*            DWORD  dwFlags                  Flags
*
* RETURN :
*            ERROR_SUCCESS                   The signature is a valid signature.
*            NTE_BAD_KEY_STATE               The key identified by the hKey
*                                            parameter has not been finalized
*                                            or is incomplete.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
KSPVerifySignature(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __in_bcount(cbSignature) PBYTE pbSignature,
    __in    DWORD   cbSignature,
    __in    DWORD   dwFlags)
{
    BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> KSPVerifySignature");
	__try
	{
		KspKey* key = KspContainer::GetKeyFromHandle(hProvider, hKey);
		if (!key)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKeyFromHandle failed 0x%08X", dwError);
			__leave;
		}
		if (!key->VerifySignature(pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignature, dwFlags))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"VerifySignature failed 0x%08X", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- KSPVerifySignature %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	if (fReturn)
		return ERROR_SUCCESS;
	else
	{
		if (dwError == 0)
			dwError = ERROR_INTERNAL_ERROR;
		return dwError;
	}
}

SECURITY_STATUS
WINAPI
KSPPromptUser(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR  pszOperation,
    __in    DWORD   dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pszOperation);
    UNREFERENCED_PARAMETER(dwFlags);
	Trace(TRACE_LEVEL_ERROR, L"Not supported");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS
WINAPI
KSPNotifyChangeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout HANDLE *phEvent,
    __in    DWORD   dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(phEvent);
    UNREFERENCED_PARAMETER(dwFlags);
    Trace(TRACE_LEVEL_ERROR, L"Not supported");
    return NTE_NOT_SUPPORTED;
}


SECURITY_STATUS
WINAPI
KSPSecretAgreement(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hPrivKey,
    __in    NCRYPT_KEY_HANDLE hPubKey,
    __out   NCRYPT_SECRET_HANDLE *phAgreedSecret,
    __in    DWORD   dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hPrivKey);
    UNREFERENCED_PARAMETER(hPubKey);
    UNREFERENCED_PARAMETER(phAgreedSecret);
    UNREFERENCED_PARAMETER(dwFlags);
    Trace(TRACE_LEVEL_ERROR, L"Not supported");
    return NTE_NOT_SUPPORTED;
}


SECURITY_STATUS
WINAPI
KSPDeriveKey(
    __in        NCRYPT_PROV_HANDLE   hProvider,
    __in_opt    NCRYPT_SECRET_HANDLE hSharedSecret,
    __in        LPCWSTR              pwszKDF,
    __in_opt    NCryptBufferDesc     *pParameterList,
    __out_bcount_part_opt(cbDerivedKey, *pcbResult) PUCHAR pbDerivedKey,
    __in        DWORD                cbDerivedKey,
    __out       DWORD                *pcbResult,
    __in        ULONG                dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hSharedSecret);
    UNREFERENCED_PARAMETER(pwszKDF);
    UNREFERENCED_PARAMETER(pParameterList);
    UNREFERENCED_PARAMETER(pbDerivedKey);
    UNREFERENCED_PARAMETER(cbDerivedKey);
    UNREFERENCED_PARAMETER(pcbResult);
    UNREFERENCED_PARAMETER(dwFlags);
    Trace(TRACE_LEVEL_ERROR, L"Not supported");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS
WINAPI
KSPFreeSecret(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_SECRET_HANDLE hSharedSecret)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hSharedSecret);
    Trace(TRACE_LEVEL_ERROR, L"Not supported");
    return NTE_NOT_SUPPORTED;
}
