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

CRYPT_RETURN_HWND GetHWND;

/*
 -   CPAcquireContextW
 -
 *   Purpose:
 *                             The CPAcquireContextW function is used to acquire a context
 *                             handle to a cryptographic service provider (CSP). using
 *                             UNICODE strings.   This is an optional entry point for a CSP.
 *                             It is not used prior to Whistler.   There it is used if
 *                             exported by the CSP image, otherwise any string conversions
 *                             are done, and CPAcquireContext is called.
 *
 *
 *   Parameters:
 *                             __out phProv                 -   Handle to a CSP
 *                             __in   szContainer       -   Pointer to a string which is the
 *                                                                         identity of the logged on user
 *                             __in   dwFlags               -   Flags values
 *                             __in   pVTable               -   Pointer to table of function pointers
 *
 *   Returns:
 */

EXTERN_C BOOL WINAPI CPAcquireContext(
  __out HCRYPTPROV* phProv,
  __in PCSTR szSubmittedContainer,
  __in DWORD dwFlags,
  __inout PVTableProvStruc pVTable 
)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	BOOL fAllowUI =  TRUE;
	BOOL fMachineKeySet = FALSE;
	BOOL fVerifyContext = FALSE;
	PCSTR szReader = NULL;
	CHAR szBuffer[256];
	PCSTR szContainer = NULL;
	Trace(TRACE_LEVEL_INFO, L"--> CPAcquireContext flag 0x%08X", dwFlags);
	__try
	{
		// sanity checks
		if (  NULL  == phProv) 
		{
			Trace(TRACE_LEVEL_ERROR, L"phProv NULL");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		
		GetHWND = pVTable->FuncReturnhWnd;

		*phProv = (HCRYPTPROV)NULL;
	
		if ( dwFlags &  CRYPT_SILENT  )
		{
			Trace(TRACE_LEVEL_INFO, L"flag CRYPT_SILENT");
			fAllowUI =  FALSE ;
		}
		if ( dwFlags &  CRYPT_MACHINE_KEYSET  ) 
		{
			Trace(TRACE_LEVEL_INFO, L"flag CRYPT_MACHINE_KEYSET");
			fMachineKeySet =  TRUE ;
		}
		if ( dwFlags &  CRYPT_NEWKEYSET  ) 
		{
			Trace(TRACE_LEVEL_INFO, L"flag CRYPT_NEWKEYSET");
		}
		if ( dwFlags &  CRYPT_DELETEKEYSET  ) 
		{
			Trace(TRACE_LEVEL_INFO, L"flag CRYPT_DELETEKEYSET");
		}
		if ( dwFlags &  CRYPT_VERIFYCONTEXT  ) 
		{
			Trace(TRACE_LEVEL_INFO, L"flag CRYPT_VERIFYCONTEXT");
			fVerifyContext = TRUE;
		}
			

		// make sure what they are asking for is reasonable
		if ( ( dwFlags &  CRYPT_NEWKEYSET  ) && ( dwFlags &  CRYPT_DELETEKEYSET  ) ) {
			Trace(TRACE_LEVEL_ERROR, L"CRYPT_NEWKEYSET and CRYPT_DELETEKEYSET");
			dwError =  ERROR_NOT_SUPPORTED ;
			__leave;
		}
		/*if (  NULL  == szContainer && ( dwFlags &  CRYPT_DELETEKEYSET  ) ) {
			dwError =  ERROR_NOT_SUPPORTED ;
			Trace(TRACE_LEVEL_ERROR, L"szContainer NULL and CRYPT_DELETEKEYSET");
			__leave;
		}*/
	/*if (  NULL  != szContainer && !( dwFlags & CRYPT_NEWKEYSET ) 
					&& !ContainerFactory::isRegisteredContainer( szContainer, bMachineKeySet )) {
					SetLastError( static_cast<DWORD>(NTE_KEYSET_NOT_DEF) );
					return   FALSE;
	}*/

	
		if (!ExtractReaderAndContainerFromGeneralNameA(szSubmittedContainer, szBuffer, ARRAYSIZE(szBuffer), &szReader, &szContainer))
		{
			dwError = GetLastError();
			__leave;
		}

		// are they asking to delete the container?
		if ( dwFlags & CRYPT_DELETEKEYSET )
		{
			fReturn = CspContainer::Remove( szReader, szContainer, fAllowUI, fMachineKeySet );
			if (!fReturn)
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"Remove failed 0x%08X", dwError);
				__leave;
			}
			__leave;
		}

		// try to open the container
		CspContainer* container =  NULL;
		if ( dwFlags & CRYPT_NEWKEYSET ) 
		{
			container = CspContainer::Create( szReader, szContainer, fAllowUI, fMachineKeySet );
			if (  NULL  == container ) 
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"Create failed 0x%08X", dwError);
				__leave;
			} 
		}
		else
		{
			// verify context = no decrypt nor sign
			// verify the capability of the smart card is null container
			container = CspContainer::Load( szReader, szContainer, fAllowUI, fMachineKeySet, fVerifyContext);
			if (  NULL  == container ) 
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"Load failed 0x%08X", dwError);
				__leave;
			}
		}
			
		// pass back the container handle
		*phProv =  (HCRYPTPROV)container;
		fReturn = TRUE;
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPAcquireContext %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return   fReturn; 
}

/*
 -           CPReleaseContext
 -
 *           Purpose:
 *                             The CPReleaseContext function is used to release a
 *                             context created by CryptAcquireContext.
 *
 *         Parameters:
 *                             __in   phProv               -   Handle to a CSP
 *                             __in   dwFlags             -   Flags values
 *
 *   Returns:
 */

EXTERN_C BOOL WINAPI CPReleaseContext(
        __in     HCRYPTPROV  hProv,
        __in    DWORD  dwFlags )
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPReleaseContext");
	__try
	{
		// ownership check
		if (dwFlags)
		{
			dwError = NTE_BAD_FLAGS;
			Trace(TRACE_LEVEL_ERROR, L"NTE_BAD_FLAGS 0x%08X", dwFlags);
			__leave;
		}
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
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
		Trace(TRACE_LEVEL_INFO, L"<-- CPReleaseContext %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return   fReturn; 
} 

/*
 -   CPSetProvParam
 -
 *   Purpose:
 *                               Allows applications to customize various aspects of the
 *                               operations of a provider
 *
 *   Parameters:
 *                             __in           hProv     -   Handle to a CSP
 *                             __in           dwParam -   Parameter number
 *                             __in           pbData   -   Pointer to data
 *                             __in           dwFlags -   Flags values
 *
 *   Returns:
 */

EXTERN_C BOOL WINAPI CPSetProvParam(
        __in     HCRYPTPROV  hProv,
        __in    DWORD dwParam,
        __in     CONST  BYTE *pbData,
        __in    DWORD  dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPSetProvParam with dwParam = %d", dwParam);
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->SetProvParam(dwParam, pbData, dwFlags);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"SetProvParam failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPSetProvParam %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return   fReturn; 
}


/*
 -   CPGetProvParam
 -
 *   Purpose:
 *                               Allows applications to get various aspects of the
 *                               operations of a provider
 *
 *   Parameters:
 *                             __in           hProv           -   Handle to a CSP
 *                             __in           dwParam       -   Parameter number
 *                             __out         pbData         -   Pointer to data
 *                             __inout   pdwDataLen -   Length of parameter data
 *                             __in           dwFlags       -   Flags values
 *
 *   Returns:
 */

EXTERN_C BOOL WINAPI CPGetProvParam(
        __in     HCRYPTPROV  hProv,
        __in    DWORD dwParam,
        __out  LPBYTE  pbData,
        __inout  LPDWORD pcbDataLen,
        __in    DWORD  dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPGetProvParam with dwParam = %d", dwParam);
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->GetProvParam(dwParam, pbData, pcbDataLen, dwFlags);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetProvParam failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPGetProvParam %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}

/*
 -   CPGenRandom
 -
 *   Purpose:
 *                               Used to fill a buffer with random bytes
 *
 *
 *   Parameters:
 *                             __in   hProv                 -   Handle to the user identifcation
 *                             __in   dwLen                 -   Number of bytes of random data requested
 *                             __inout pbBuffer     -   Pointer to the buffer where the random
 *                                                                       bytes are to be placed
 *
 *   Returns:
 */

EXTERN_C BOOL WINAPI CPGenRandom(
        __in     HCRYPTPROV  hProv,
        __in    DWORD cbLen,
        __out  LPBYTE pbBuffer)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPGenRandom");
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->GenRandom(cbLen, pbBuffer);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GenRandom failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPGenRandom %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}

/*
 -   CPCreateHash
 -
 *   Purpose:
 *                               initate the hashing of a stream of data
 *
 *
 *   Parameters:
 *                             __in   hUID       -   Handle to the user identifcation
 *                             __in   Algid     -   Algorithm identifier of the hash algorithm
 *                                                           to be used
 *                             __in   hKey     -     Optional handle to a key
 *                             __in   dwFlags -   Flags values
 *                             __out pHash     -   Handle to hash object
 *
 *   Returns:
 */

EXTERN_C BOOL WINAPI CPCreateHash(
        __in     HCRYPTPROV  hProv,
        __in     ALG_ID  Algid,
        __in     HCRYPTKEY   hKey,
        __in     DWORD  dwFlags,
        __out     HCRYPTHASH  *phHash)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPCreateHash");
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->CreateHash(Algid, hKey, dwFlags, phHash);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"CreateHash failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPCreateHash %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}

/*
 -   CPHashData
 -
 *   Purpose:
 *                               Compute the cryptograghic hash on a stream of data
 *
 *
 *   Parameters:
 *                             __in   hProv         -   Handle to the user identifcation
 *                             __in   hHash         -   Handle to hash object
 *                             __in   pbData       -   Pointer to data to be hashed
 *                             __in   dwDataLen -   Length of the data to be hashed
 *                             __in   dwFlags     -   Flags values
 *
 *   Returns:
 */

EXTERN_C   BOOL   WINAPI
CPHashData(
        __in     HCRYPTPROV  hProv,
        __in     HCRYPTHASH  hHash,
        __in     CONST  BYTE *pbData,
        __in    DWORD cbDataLen,
        __in    DWORD  dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPHashData");
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->HashData(hHash, pbData, cbDataLen, dwFlags);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"HashData failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPHashData %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}


/*
 -   CPHashSessionKey
 -
 *   Purpose:
 *                               Compute the cryptograghic hash on a key object.
 *
 *
 *   Parameters:
 *                             __in   hProv         -   Handle to the user identifcation
 *                             __in   hHash         -   Handle to hash object
 *                             __in   hKey           -   Handle to a key object
 *                             __in   dwFlags     -   Flags values
 *
 *   Returns:
 *                             CRYPT_FAILED
 *                             CRYPT_SUCCEED
 */

EXTERN_C   BOOL   WINAPI
CPHashSessionKey(
        __in     HCRYPTPROV  hProv,
        __in     HCRYPTHASH  hHash,
        __in     HCRYPTKEY   hKey,
        __in    DWORD  dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPHashSessionKey");
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->HashSessionKey(hHash, hKey, dwFlags);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"HashSessionKey failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPHashSessionKey %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}


/*
 -   CPSignHash
 -
 *   Purpose:
 *                               Create a digital signature from a hash
 *
 *
 *   Parameters:
 *                             __in   hProv               -   Handle to the user identifcation
 *                             __in   hHash               -   Handle to hash object
 *                             __in   dwKeySpec       -   Key pair to that is used to sign with
 *                             __in   sDescription -   Description of data to be signed
 *                             __in   dwFlags           -   Flags values
 *                             __out pbSignature   -   Pointer to signature data
 *                             __inout dwHashLen -   Pointer to the len of the signature data
 *
 *   Returns:
 */

EXTERN_C   BOOL   WINAPI
CPSignHash(
        __in     HCRYPTPROV  hProv,
        __in     HCRYPTHASH  hHash,
        __in    DWORD  dwKeySpec,
        __in    LPCWSTR szDescription,
        __in    DWORD  dwFlags,
        __out  LPBYTE pbSignature,
        __inout  LPDWORD pcbSigLen)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPSignHash");
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->SignHash(hHash, dwKeySpec, szDescription, dwFlags, pbSignature, pcbSigLen);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"SignHash failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPSignHash %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}


/*
 -   CPDestroyHash
 -
 *   Purpose:
 *                               Destroy the hash object
 *
 *
 *   Parameters:
 *                             __in   hProv         -   Handle to the user identifcation
 *                             __in   hHash         -   Handle to hash object
 *
 *   Returns:
 */

EXTERN_C   BOOL   WINAPI
CPDestroyHash(
        __in     HCRYPTPROV  hProv,
        __in     HCRYPTHASH  hHash)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPDestroyHash");
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->DestroyHash(hHash);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"DestroyHash failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPDestroyHash %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}

/*
 -   CPSetHashParam
 -
 *   Purpose:
 *                               Allows applications to customize various aspects of the
 *                               operations of a hash
 *
 *   Parameters:
 *                             __in           hProv     -   Handle to a CSP
 *                             __in           hHash     -   Handle to a hash
 *                             __in           dwParam -   Parameter number
 *                             __in           pbData   -   Pointer to data
 *                             __in           dwFlags -   Flags values
 *
 *   Returns:
 */

EXTERN_C   BOOL   WINAPI
CPSetHashParam(
        __in     HCRYPTPROV  hProv,
        __in     HCRYPTHASH  hHash,
        __in    DWORD dwParam,
        __in     CONST  BYTE *pbData,
        __in    DWORD  dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPSetHashParam with dwParam = %d", dwParam);
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->SetHashParam(hHash, dwParam, pbData, dwFlags);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"SetHashParam failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPSetHashParam %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}


/*
 -   CPGetHashParam
 -
 *   Purpose:
 *                               Allows applications to get various aspects of the
 *                               operations of a hash
 *
 *   Parameters:
 *                             __in           hProv           -   Handle to a CSP
 *                             __in           hHash           -   Handle to a hash
 *                             __in           dwParam       -   Parameter number
 *                             __out         pbData         -   Pointer to data
 *                             __in           pdwDataLen -   Length of parameter data
 *                             __in           dwFlags       -   Flags values
 *
 *   Returns:
 */

EXTERN_C   BOOL   WINAPI
CPGetHashParam(
        __in     HCRYPTPROV  hProv,
        __in     HCRYPTHASH  hHash,
        __in    DWORD dwParam,
        __out  LPBYTE  pbData,
        __inout  LPDWORD pcbDataLen,
        __in    DWORD  dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPGetHashParam with dwParam = %d", dwParam);
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->GetHashParam(hHash, dwParam, pbData, pcbDataLen, dwFlags);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetHashParam failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPGetHashParam %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}

/*
 -   CPGenKey
 -
 *   Purpose:
 *                               Generate cryptographic keys
 *
 *
 *   Parameters:
 *                             __in           hProv     -   Handle to a CSP
 *                             __in           Algid     -   Algorithm identifier
 *                             __in           dwFlags -   Flags values
 *                             __out         phKey     -   Handle to a generated key
 *
 *   Returns:
 */

EXTERN_C BOOL WINAPI CPGenKey(
        __in     HCRYPTPROV  hProv,
        __in     ALG_ID  Algid,
        __in    DWORD  dwFlags,
        __out   HCRYPTKEY  *phKey)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPGenKey");
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->GenKey(Algid, dwFlags, phKey);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GenKey failed 0x%08X", dwError);
			__leave;
		}
		Trace(TRACE_LEVEL_VERBOSE, L"Gen hKey 0x%Ix", *phKey);
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPGenKey %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}


/*
 -   CPDeriveKey
 -
 *   Purpose:
 *                               Derive cryptographic keys from base data
 *
 *
 *   Parameters:
 *                             __in           hProv           -   Handle to a CSP
 *                             __in           Algid           -   Algorithm identifier
 *                             __in           hBaseData -     Handle to base data
 *                             __in           dwFlags       -   Flags values
 *                             __out         phKey           -   Handle to a generated key
 *
 *   Returns:
 */

EXTERN_C   BOOL   WINAPI
CPDeriveKey(
        __in     HCRYPTPROV  hProv,
        __in     ALG_ID  Algid,
        __in     HCRYPTHASH  hHash,
        __in    DWORD  dwFlags,
        __out   HCRYPTKEY  *phKey)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPDeriveKey");
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->DeriveKey(Algid, hHash, dwFlags, phKey);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"DeriveKey failed 0x%08X", dwError);
			__leave;
		}
		Trace(TRACE_LEVEL_VERBOSE, L"Derive hKey 0x%Ix", *phKey);
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPDeriveKey %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}


/*
 -   CPDestroyKey
 -
 *   Purpose:
 *                               Destroys the cryptographic key that is being referenced
 *                               with the hKey parameter
 *
 *
 *   Parameters:
 *                             __in           hProv   -   Handle to a CSP
 *                             __in           hKey     -   Handle to a key
 *
 *   Returns:
 */

EXTERN_C   BOOL   WINAPI
CPDestroyKey(
        __in     HCRYPTPROV  hProv,
        __in     HCRYPTKEY   hKey)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPDestroyKey");
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->DestroyKey(hKey);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"DestroyKey failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPDestroyKey %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}



/*
 -   CPSetKeyParam
 -
 *   Purpose:
 *                               Allows applications to customize various aspects of the
 *                               operations of a key
 *
 *   Parameters:
 *                             __in           hProv     -   Handle to a CSP
 *                             __in           hKey       -   Handle to a key
 *                             __in           dwParam -   Parameter number
 *                             __in           pbData   -   Pointer to data
 *                             __in           dwFlags -   Flags values
 *
 *   Returns:
 */

EXTERN_C   BOOL   WINAPI
CPSetKeyParam(
        __in     HCRYPTPROV  hProv,
        __in     HCRYPTKEY   hKey,
        __in    DWORD dwParam,
        __in     CONST  BYTE *pbData,
        __in    DWORD  dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPSetKeyParam with dwParam = %d", dwParam);
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->SetKeyParam(hKey, dwParam, pbData, dwFlags);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"SetKeyParam failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPSetKeyParam %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}


/*
 -   CPGetKeyParam
 -
 *   Purpose:
 *                               Allows applications to get various aspects of the
 *                               operations of a key
 *
 *   Parameters:
 *                             __in           hProv           -   Handle to a CSP
 *                             __in           hKey             -   Handle to a key
 *                             __in           dwParam       -   Parameter number
 *                             __out         pbData         -   Pointer to data
 *                             __in           pdwDataLen -   Length of parameter data
 *                             __in           dwFlags       -   Flags values
 *
 *   Returns:
 */

EXTERN_C   BOOL   WINAPI
CPGetKeyParam(
        __in     HCRYPTPROV  hProv,
        __in     HCRYPTKEY   hKey,
        __in    DWORD dwParam,
        __out  LPBYTE  pbData,
        __inout  LPDWORD pcbDataLen,
        __in    DWORD  dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPGetKeyParam with dwParam = %d", dwParam);
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->GetKeyParam(hKey, dwParam, pbData, pcbDataLen, dwFlags);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetKeyParam failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPGetKeyParam %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}







/*
 -   CPExportKey
 -
 *   Purpose:
 *                               Export cryptographic keys out of a CSP in a secure manner
 *
 *
 *   Parameters:
 *                             __in   hProv                 - Handle to the CSP user
 *                             __in   hKey                   - Handle to the key to export
 *                             __in   hPubKey             - Handle to exchange public key value of
 *                                                                     the destination user
 *                             __in   dwBlobType       - Type of key blob to be exported
 *                             __in   dwFlags             - Flags values
 *                             __out pbData               -         Key blob data
 *                             __inout pdwDataLen - Length of key blob in bytes
 *
 *   Returns:
 */

EXTERN_C   BOOL   WINAPI
CPExportKey(
        __in     HCRYPTPROV  hProv,
        __in     HCRYPTKEY   hKey,
        __in     HCRYPTKEY  hPubKey,
        __in    DWORD dwBlobType,
        __in    DWORD  dwFlags,
        __out  LPBYTE  pbData,
        __inout  LPDWORD pcbDataLen)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPExportKey");
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->ExportKey(hKey, hPubKey, dwBlobType, dwFlags, pbData, pcbDataLen);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"ExportKey failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPExportKey %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}

/*
 -   CPImportKey
 -
 *   Purpose:
 *                               Import cryptographic keys
 *
 *
 *   Parameters:
 *                             __in   hProv         -   Handle to the CSP user
 *                             __in   pbData       -   Key blob data
 *                             __in   dwDataLen -   Length of the key blob data
 *                             __in   hPubKey     -   Handle to the exchange public key value of
 *                                                               the destination user
 *                             __in   dwFlags     -   Flags values
 *                             __out phKey         -   Pointer to the handle to the key which was
 *                                                               Imported
 *
 *   Returns:
 */

EXTERN_C   BOOL   WINAPI
CPImportKey(
        __in     HCRYPTPROV  hProv,
        __in     CONST  BYTE *pbData,
        __in    DWORD cbDataLen,
        __in     HCRYPTKEY  hPubKey,
        __in    DWORD  dwFlags,
        __out   HCRYPTKEY  *phKey)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPImportKey");
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->ImportKey(pbData, cbDataLen, hPubKey, dwFlags, phKey);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"ImportKey failed 0x%08X", dwError);
			__leave;
		}
		Trace(TRACE_LEVEL_VERBOSE, L"Import hKey 0x%Ix", *phKey);
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPImportKey %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}

/*
 -   CPEncrypt
 -
 *   Purpose:
 *                               Encrypt data
 *
 *
 *   Parameters:
 *                             __in   hProv                 -   Handle to the CSP user
 *                             __in   hKey                   -   Handle to the key
 *                             __in   hHash                 -   Optional handle to a hash
 *                             __in   Final                 -   Boolean indicating if this is the final
 *                                                                       block of plaintext
 *                             __in   dwFlags             -   Flags values
 *                             __inout pbData         -   Data to be encrypted
 *                             __inout pdwDataLen -   Pointer to the length of the data to be
 *                                                                       encrypted
 *                             __in dwBufLen             -   Size of Data buffer
 *
 *   Returns:
 */

EXTERN_C   BOOL   WINAPI
CPEncrypt(
        __in     HCRYPTPROV  hProv,
        __in     HCRYPTKEY   hKey,
        __in     HCRYPTHASH  hHash,
        __in     BOOL  fFinal,
        __in    DWORD  dwFlags,
        __inout  LPBYTE  pbData,
        __inout  LPDWORD pcbDataLen,
        __in    DWORD cbBufLen)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPEncrypt");
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->Encrypt(hKey, hHash, fFinal, dwFlags, pbData, pcbDataLen, cbBufLen);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"Encrypt failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPEncrypt %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}

/*
 -   CPDecrypt
 -
 *   Purpose:
 *                               Decrypt data
 *
 *
 *   Parameters:
 *                             __in   hProv                 -   Handle to the CSP user
 *                             __in   hKey                   -   Handle to the key
 *                             __in   hHash                 -   Optional handle to a hash
 *                             __in   Final                 -   Boolean indicating if this is the final
 *                                                                       block of ciphertext
 *                             __in   dwFlags             -   Flags values
 *                             __inout pbData         -   Data to be decrypted
 *                             __inout pdwDataLen -   Pointer to the length of the data to be
 *                                                                       decrypted
 *
 *   Returns:
 */

EXTERN_C   BOOL   WINAPI
CPDecrypt(
        __in     HCRYPTPROV  hProv,
        __in     HCRYPTKEY   hKey,
        __in     HCRYPTHASH  hHash,
        __in     BOOL  fFinal,
        __in    DWORD  dwFlags,
        __inout  LPBYTE  pbData,
        __inout  LPDWORD pcbDataLen)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPDecrypt");
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->Decrypt(hKey, hHash, fFinal, dwFlags, pbData, pcbDataLen);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"Decrypt failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPDecrypt %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}






/*
 -   CPVerifySignature
 -
 *   Purpose:
 *                               Used to verify a signature against a hash object
 *
 *
 *   Parameters:
 *                             __in   hProv               -   Handle to the user identifcation
 *                             __in   hHash               -   Handle to hash object
 *                             __in   pbSignture     -   Pointer to signature data
 *                             __in   dwSigLen         -   Length of the signature data
 *                             __in   hPubKey           -   Handle to the public key for verifying
 *                                                                     the signature
 *                             __in   sDescription -   String describing the signed data
 *                             __in   dwFlags           -   Flags values
 *
 *   Returns:
 */

EXTERN_C   BOOL   WINAPI
CPVerifySignature(
        __in     HCRYPTPROV  hProv,
        __in     HCRYPTHASH  hHash,
        __in     CONST  BYTE *pbSignature,
        __in    DWORD cbSigLen,
        __in     HCRYPTKEY  hPubKey,
        __in    LPCWSTR szDescription,
        __in    DWORD  dwFlags)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPVerifySignature");
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->VerifySignature(hHash, pbSignature, cbSigLen, hPubKey, szDescription, dwFlags);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"VerifySignature failed 0x%08X", dwError);
			__leave;
		}
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPVerifySignature %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}


/*
 -   CPGetUserKey
 -
 *   Purpose:
 *                               Gets a handle to a permanent user key
 *
 *
 *   Parameters:
 *                             __in   hProv           -   Handle to the user identifcation
 *                             __in   dwKeySpec   -   Specification of the key to retrieve
 *                             __out phUserKey   -   Pointer to key handle of retrieved key
 *
 *   Returns:
 */

EXTERN_C   BOOL   WINAPI
CPGetUserKey(
        __in     HCRYPTPROV  hProv,
        __in    DWORD  dwKeySpec,
        __out   HCRYPTKEY  *phUserKey)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	Trace(TRACE_LEVEL_INFO, L"--> CPGetUserKey %s", (dwKeySpec == AT_SIGNATURE ? L"AT_SIGNATURE" : (dwKeySpec == AT_KEYEXCHANGE ? L"AT_KEYECHANGE": L"ERROR")));
	__try
	{
		// ownership check
		CspContainer* container =  CspContainer::GetContainerFromHandle(hProv);
		if (!container)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetContainerFromHandle failed 0x%08X", dwError);
			__leave;
		}
		fReturn = container->GetUserKey(dwKeySpec, phUserKey);
		if (!fReturn)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetUserKey failed 0x%08X", dwError);
			__leave;
		}
		Trace(TRACE_LEVEL_VERBOSE, L"GetUserKey hKey 0x%Ix", *phUserKey);
	}
	__finally
	{
		Trace(TRACE_LEVEL_INFO, L"<-- CPGetUserKey %s 0x%08X", (fReturn?L"TRUE":L"FALSE"), dwError);
	}
	SetLastError(dwError);
	return fReturn;
}