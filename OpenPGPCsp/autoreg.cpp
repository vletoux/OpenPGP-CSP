/*++

Copyright (C) Microsoft Corporation, 1998 - 1999

Module Name:

    autoreg

Abstract:

    This module provides autoregistration capabilities to a CSP.  It allows
    regsvr32 to call the DLL directly to add and remove Registry settings.

Author:

    Doug Barlow (dbarlow) 3/11/1998

Environment:

    Win32

Notes:

    Look for "?vendor?" tags and edit appropriately.

--*/

#include "stdafx.h"

static HMODULE
GetInstanceHandle(
    void);

#ifdef SCARD_CSP
static const TCHAR
    l_szCardName[]
        = TEXT("OpenPGP Card");
static const GUID   // Optional
    l_guidPrimaryProv
    //?vendor? Add your Primary Provider GUID here 
        = { /* 00000000-0000-0000-0000-000000000000 */
            0x00000000,
            0x0000,
            0x0000,
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
          };
static const BYTE
    l_rgbATR[]     = { 0x3B,0xDA,0x18,0xFF,0x81,0xB1,0xFE,0x75,0x1F,0x03,0x00,0x31,0xC5,0x73,0xC0,0x01,0x40,0x00,0x90,0x00,0x0C },
    l_rgbATRMask[] = { 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff };
#endif

static const TCHAR
    l_szProviderName[]
        = TEXT(CSPNAME);
static const TCHAR
    l_szKSPProviderName[]
        = TEXT(KSPNAME);
static const DWORD
    l_dwCspType
        = PROV_RSA_FULL;


/*++

DllUnregisterServer:

    This service removes the registry entries associated with this CSP.

Arguments:

    None

Return Value:

    Status code as an HRESULT.

Author:

    Doug Barlow (dbarlow) 3/11/1998

--*/

STDAPI
UnRegisterCsp(
    void)
{
    LONG nStatus;
    DWORD dwDisp;
    HRESULT hReturnStatus = NO_ERROR;
    HKEY hProviders = NULL;
#ifdef SCARD_CSP
    SCARDCONTEXT hCtx = NULL;
#endif

#ifdef _AFXDLL
    AFX_MANAGE_STATE(AfxGetStaticModuleState());
#endif


    //
    // Delete the Registry key for this CSP.
    //

    nStatus = RegCreateKeyEx(
                    HKEY_LOCAL_MACHINE,
                    TEXT("SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider"),
                    0,
                    TEXT(""),
                    REG_OPTION_NON_VOLATILE,
                    KEY_ALL_ACCESS,
                    NULL,
                    &hProviders,
                    &dwDisp);
    if (ERROR_SUCCESS == nStatus)
    {
        RegDeleteKey(hProviders, l_szProviderName);
        RegCloseKey(hProviders);
        hProviders = NULL;
    }


#ifdef SCARD_CSP
    //
    // Forget the card type.
    //

    hCtx = NULL;
    SCardEstablishContext(SCARD_SCOPE_SYSTEM, 0, 0, &hCtx);
    SCardForgetCardType(hCtx, l_szCardName);
    if (NULL != hCtx)
    {
        SCardReleaseContext(hCtx);
        hCtx = NULL;
    }
#endif


    //
    // ?vendor?
    // Delete vendor specific registry entries.
    //



    //
    // All done!
    //

    return hReturnStatus;
}


/*++

DllRegisterServer:

    This function installs the proper registry entries to enable this CSP.

Arguments:

    None

Return Value:

    Status code as an HRESULT.

Author:

    Doug Barlow (dbarlow) 3/11/1998

--*/

STDAPI
RegisterCsp(
    void)
{
    TCHAR szModulePath[MAX_PATH];
    LPTSTR szFileName, szFileExt;
    HINSTANCE hThisDll;
    DWORD dwStatus;
    LONG nStatus;
	DWORD dwDisp;
    HRESULT hReturnStatus = NO_ERROR;
    HKEY hProviders = NULL;
    HKEY hMyCsp = NULL;
    HKEY hCalais = NULL;
    HKEY hVendor = NULL;
    BOOL fSignatureFound = FALSE;
    HANDLE hSigFile = INVALID_HANDLE_VALUE;
#ifdef SCARD_CSP
    DWORD dwIndex;
    BOOL fCardIntroduced = FALSE;
    SCARDCONTEXT hCtx = NULL;
#endif

#ifdef _AFXDLL
    AFX_MANAGE_STATE(AfxGetStaticModuleState());
#endif

    //
    // Figure out the file name and path.
    //

    hThisDll = GetInstanceHandle();
    if (NULL == hThisDll)
    {
        hReturnStatus = HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE);
        goto ErrorExit;
    }

    dwStatus = GetModuleFileName(
                    hThisDll,
                    szModulePath,
                    sizeof(szModulePath) / sizeof(TCHAR));
    if (0 == dwStatus)
    {
        hReturnStatus = HRESULT_FROM_WIN32(GetLastError());
        goto ErrorExit;
    }

    szFileName = _tcsrchr(szModulePath, TEXT('\\'));
    if (NULL == szFileName)
        szFileName = szModulePath;
    else
        szFileName += 1;
    szFileExt = _tcsrchr(szFileName, TEXT('.'));
    if (NULL == szFileExt)
    {
        hReturnStatus = HRESULT_FROM_WIN32(ERROR_INVALID_NAME);
        goto ErrorExit;
    }
    else
        szFileExt += 1;


    //
    // Create the Registry key for this CSP.
    //

    nStatus = RegCreateKeyEx(
                    HKEY_LOCAL_MACHINE,
                    TEXT("SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider"),
                    0,
                    TEXT(""),
                    REG_OPTION_NON_VOLATILE,
                    KEY_ALL_ACCESS,
                    NULL,
                    &hProviders,
                    &dwDisp);
    if (ERROR_SUCCESS != nStatus)
    {
        hReturnStatus = HRESULT_FROM_WIN32(nStatus);
        goto ErrorExit;
    }
    nStatus = RegCreateKeyEx(
                    hProviders,
                    l_szProviderName,
                    0,
                    TEXT(""),
                    REG_OPTION_NON_VOLATILE,
                    KEY_ALL_ACCESS,
                    NULL,
                    &hMyCsp,
                    &dwDisp);
    if (ERROR_SUCCESS != nStatus)
    {
        hReturnStatus = HRESULT_FROM_WIN32(nStatus);
        goto ErrorExit;
    }
    nStatus = RegCloseKey(hProviders);
    hProviders = NULL;
    if (ERROR_SUCCESS != nStatus)
    {
        hReturnStatus = HRESULT_FROM_WIN32(nStatus);
        goto ErrorExit;
    }


    //
    // Install the trivial registry values.
    //

    nStatus = RegSetValueEx(
                    hMyCsp,
                    TEXT("Image Path"),
                    0,
                    REG_SZ,
                    (LPBYTE)szModulePath,
                    ((DWORD)_tcslen(szModulePath) + 1) * sizeof(TCHAR));
    if (ERROR_SUCCESS != nStatus)
    {
        hReturnStatus = HRESULT_FROM_WIN32(nStatus);
        goto ErrorExit;
    }

    nStatus = RegSetValueEx(
                    hMyCsp,
                    TEXT("Type"),
                    0,
                    REG_DWORD,
                    (LPBYTE)&l_dwCspType,
                    sizeof(DWORD));
    if (ERROR_SUCCESS != nStatus)
    {
        hReturnStatus = HRESULT_FROM_WIN32(nStatus);
        goto ErrorExit;
    }

    nStatus = RegCloseKey(hMyCsp);
    hMyCsp = NULL;
    if (ERROR_SUCCESS != nStatus)
    {
        hReturnStatus = HRESULT_FROM_WIN32(nStatus);
        goto ErrorExit;
    }


#ifdef SCARD_CSP
    //
    // Introduce the vendor card.  Try various techniques until one works.
    //

    for (dwIndex = 0; !fCardIntroduced; dwIndex += 1)
    {
        switch (dwIndex)
        {
        case 0:
            {

                dwStatus = SCardIntroduceCardType(
                                NULL,
                                l_szCardName,
                                NULL,
                                NULL,
                                0,
                                l_rgbATR,
                                l_rgbATRMask,
                                sizeof(l_rgbATR));
                if ((ERROR_SUCCESS != dwStatus)
                    && (ERROR_ALREADY_EXISTS != dwStatus))
                    continue;
                dwStatus = SCardSetCardTypeProviderName(
                                NULL,
                                l_szCardName,
                                SCARD_PROVIDER_CSP,
                                l_szProviderName);
                if (ERROR_SUCCESS != dwStatus)
                {
                    if (0 == (dwStatus & 0xffff0000))
                        hReturnStatus = HRESULT_FROM_WIN32(dwStatus);
                    else
                        hReturnStatus = (HRESULT)dwStatus;
                    goto ErrorExit;
                }
				dwStatus = SCardSetCardTypeProviderName(
                                NULL,
                                l_szCardName,
                                SCARD_PROVIDER_KSP,
                                l_szKSPProviderName);
                if (ERROR_SUCCESS != dwStatus)
                {
                    if (0 == (dwStatus & 0xffff0000))
                        hReturnStatus = HRESULT_FROM_WIN32(dwStatus);
                    else
                        hReturnStatus = (HRESULT)dwStatus;
                    goto ErrorExit;
                }
                fCardIntroduced = TRUE;
                break;
            }

        case 1:
            dwStatus = SCardEstablishContext(SCARD_SCOPE_SYSTEM, 0, 0, &hCtx);
            if (ERROR_SUCCESS != dwStatus)
                continue;
            dwStatus = SCardIntroduceCardType(
                            hCtx,
                            l_szCardName,
                            NULL,
                            NULL,
                            0,
                            l_rgbATR,
                            l_rgbATRMask,
                            sizeof(l_rgbATR));
            if ((ERROR_SUCCESS != dwStatus)
                && (ERROR_ALREADY_EXISTS != dwStatus))
            {
                if (0 == (dwStatus & 0xffff0000))
                    hReturnStatus = HRESULT_FROM_WIN32(dwStatus);
                else
                    hReturnStatus = (HRESULT)dwStatus;
                goto ErrorExit;
            }
            dwStatus = SCardReleaseContext(hCtx);
            hCtx = NULL;
            if (ERROR_SUCCESS != dwStatus)
            {
                if (0 == (dwStatus & 0xffff0000))
                    hReturnStatus = HRESULT_FROM_WIN32(dwStatus);
                else
                    hReturnStatus = (HRESULT)dwStatus;
                goto ErrorExit;
            }
            nStatus = RegCreateKeyEx(
                            HKEY_LOCAL_MACHINE,
                            TEXT("SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards"),
                            0,
                            TEXT(""),
                            REG_OPTION_NON_VOLATILE,
                            KEY_ALL_ACCESS,
                            NULL,
                            &hCalais,
                            &dwDisp);
            if (ERROR_SUCCESS != nStatus)
            {
                hReturnStatus = HRESULT_FROM_WIN32(nStatus);
                goto ErrorExit;
            }
            nStatus = RegCreateKeyEx(
                            hCalais,
                            l_szCardName,
                            0,
                            TEXT(""),
                            REG_OPTION_NON_VOLATILE,
                            KEY_ALL_ACCESS,
                            NULL,
                            &hVendor,
                            &dwDisp);
            if (ERROR_SUCCESS != nStatus)
            {
                hReturnStatus = HRESULT_FROM_WIN32(nStatus);
                goto ErrorExit;
            }
            nStatus = RegCloseKey(hCalais);
            hCalais = NULL;
            if (ERROR_SUCCESS != nStatus)
            {
                hReturnStatus = HRESULT_FROM_WIN32(nStatus);
                goto ErrorExit;
            }
            nStatus = RegSetValueEx(
                            hVendor,
                            TEXT("Crypto Provider"),
                            0,
                            REG_SZ,
                            (LPBYTE)l_szProviderName,
                            (DWORD)((_tcslen(l_szProviderName) + 1) * sizeof(TCHAR)));
            if (ERROR_SUCCESS != nStatus)
            {
                hReturnStatus = HRESULT_FROM_WIN32(nStatus);
                goto ErrorExit;
            }

			nStatus = RegSetValueEx(
                            hVendor,
                            TEXT("Crypto Provider"),
                            0,
                            REG_SZ,
                            (LPBYTE)l_szProviderName,
                            (DWORD)((_tcslen(l_szProviderName) + 1) * sizeof(TCHAR)));
            if (ERROR_SUCCESS != nStatus)
            {
                hReturnStatus = HRESULT_FROM_WIN32(nStatus);
                goto ErrorExit;
            }

            nStatus = RegCloseKey(hVendor);
            hVendor = NULL;
            if (ERROR_SUCCESS != nStatus)
            {
                hReturnStatus = HRESULT_FROM_WIN32(nStatus);
                goto ErrorExit;
            }

            fCardIntroduced = TRUE;
            break;

        case 2:
            nStatus = RegCreateKeyEx(
                            HKEY_LOCAL_MACHINE,
                            TEXT("SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards"),
                            0,
                            TEXT(""),
                            REG_OPTION_NON_VOLATILE,
                            KEY_ALL_ACCESS,
                            NULL,
                            &hCalais,
                            &dwDisp);
            if (ERROR_SUCCESS != nStatus)
                continue;
            nStatus = RegCreateKeyEx(
                            hCalais,
                            l_szCardName,
                            0,
                            TEXT(""),
                            REG_OPTION_NON_VOLATILE,
                            KEY_ALL_ACCESS,
                            NULL,
                            &hVendor,
                            &dwDisp);
            if (ERROR_SUCCESS != nStatus)
            {
                hReturnStatus = HRESULT_FROM_WIN32(nStatus);
                goto ErrorExit;
            }
            nStatus = RegCloseKey(hCalais);
            hCalais = NULL;
            if (ERROR_SUCCESS != nStatus)
            {
                hReturnStatus = HRESULT_FROM_WIN32(nStatus);
                goto ErrorExit;
            }
            nStatus = RegSetValueEx(
                            hVendor,
                            TEXT("Primary Provider"),
                            0,
                            REG_BINARY,
                            (LPCBYTE)&l_guidPrimaryProv,
                            sizeof(l_guidPrimaryProv));
            if (ERROR_SUCCESS != nStatus)
            {
                hReturnStatus = HRESULT_FROM_WIN32(nStatus);
                goto ErrorExit;
            }
            nStatus = RegSetValueEx(
                            hVendor,
                            TEXT("ATR"),
                            0,
                            REG_BINARY,
                            l_rgbATR,
                            sizeof(l_rgbATR));
            if (ERROR_SUCCESS != nStatus)
            {
                hReturnStatus = HRESULT_FROM_WIN32(nStatus);
                goto ErrorExit;
            }
            nStatus = RegSetValueEx(
                            hVendor,
                            TEXT("ATRMask"),
                            0,
                            REG_BINARY,
                            l_rgbATRMask,
                            sizeof(l_rgbATRMask));
            if (ERROR_SUCCESS != nStatus)
            {
                hReturnStatus = HRESULT_FROM_WIN32(nStatus);
                goto ErrorExit;
            }
            nStatus = RegSetValueEx(
                            hVendor,
                            TEXT("Crypto Provider"),
                            0,
                            REG_SZ,
                            (LPBYTE)l_szProviderName,
                            (DWORD)((_tcslen(l_szProviderName) + 1) * sizeof(TCHAR)));
            if (ERROR_SUCCESS != nStatus)
            {
                hReturnStatus = HRESULT_FROM_WIN32(nStatus);
                goto ErrorExit;
            }
            nStatus = RegCloseKey(hVendor);
            hVendor = NULL;
            if (ERROR_SUCCESS != nStatus)
            {
                hReturnStatus = HRESULT_FROM_WIN32(nStatus);
                goto ErrorExit;
            }
            fCardIntroduced = TRUE;
            break;

        default:
            hReturnStatus = ERROR_ACCESS_DENIED;
            goto ErrorExit;
        }
    }
#endif


    //
    // ?vendor?
    // Add any additional initialization required here.
    //



    //
    // All done!
    //

    return hReturnStatus;


    //
    // An error was detected.  Clean up any outstanding resources and
    // return the error.
    //

    ErrorExit:
#ifdef SCARD_CSP
    if (NULL != hCtx)
        SCardReleaseContext(hCtx);
    if (NULL != hCalais)
        RegCloseKey(hCalais);
#endif
    if (NULL != hVendor)
        RegCloseKey(hVendor);
    if (INVALID_HANDLE_VALUE != hSigFile)
        CloseHandle(hSigFile);
    if (NULL != hMyCsp)
        RegCloseKey(hMyCsp);
    if (NULL != hProviders)
        RegCloseKey(hProviders);
    UnRegisterCsp();
    return hReturnStatus;
}


/*++

GetInstanceHandle:

    This routine is CSP dependant.  It returns the DLL instance handle.  This
    is typically provided by the DllMain routine and stored in a global
    location.

Arguments:

    None

Return Value:

    The DLL Instance handle provided to the DLL when DllMain was called.

Author:

    Doug Barlow (dbarlow) 3/11/1998

--*/

extern HINSTANCE g_hInst;

static HINSTANCE
GetInstanceHandle(
    void)
{
#ifdef _AFXDLL
    return AfxGetInstanceHandle();
#else
    return g_hInst;
#endif
}


//
// An array of algorithm names, all belonging to the
// same algorithm class...
//
PWSTR AlgorithmNames[1] = {
    NCRYPT_KEY_STORAGE_ALGORITHM
};

//
// Definition of ONE class of algorithms supported
// by the provider...
//
CRYPT_INTERFACE_REG AlgorithmClass = {
    NCRYPT_KEY_STORAGE_INTERFACE,       // ncrypt key storage interface
    CRYPT_LOCAL,                        // Scope: local system only
    1,                                  // One algorithm in the class
    AlgorithmNames                      // The name(s) of the algorithm(s) in the class
};

//
// An array of ALL the algorithm classes supported
// by the provider...
//
PCRYPT_INTERFACE_REG AlgorithmClasses[1] = {
    &AlgorithmClass
};

//
// Definition of the provider's user-mode binary...
//
CRYPT_IMAGE_REG SampleKspImage = {
    L"OpenPGPCsp.dll",                   // File name of the sample KSP binary
	1,                                  // Number of algorithm classes the binary supports
    AlgorithmClasses                    // List of all algorithm classes available
};

//
// Definition of the overall provider...
//
CRYPT_PROVIDER_REG KSPProvider = {
    0,
    NULL,
    &SampleKspImage,  // Image that provides user-mode support
    NULL              // Image that provides kernel-mode support (*MUST* be NULL)
};
///////////////////////////////////////////////////////////////////////////////

HRESULT
RegisterKsp(
    void
    )
{
    NTSTATUS ntStatus = 0;

    //
    // Make CNG aware that our provider
    // exists...
    //
	ntStatus = BCryptRegisterProvider(
                    TEXT(KSPNAME),
                    CRYPT_OVERWRITE,                          // Flags: fail if provider is already registered
                    &KSPProvider
                    );
    if (!BCRYPT_SUCCESS(ntStatus))
    {
        wprintf(L"BCryptRegisterProvider failed with error code 0x%08x\n", ntStatus);
    }

    //
    // Add the algorithm name to the priority list of the
    // symmetric cipher algorithm class. (This makes it
    // visible to BCryptResolveProviders.)
    //
#pragma warning(suppress: 6387)
    ntStatus = BCryptAddContextFunction(
                    CRYPT_LOCAL,                    // Scope: local machine only
                    NULL,                           // Application context: default
                    NCRYPT_KEY_STORAGE_INTERFACE,   // Algorithm class
                    NCRYPT_KEY_STORAGE_ALGORITHM,   // Algorithm name
                    CRYPT_PRIORITY_BOTTOM           // Lowest priority
                    );
    if ( !BCRYPT_SUCCESS(ntStatus))
    {
        wprintf(L"BCryptAddContextFunction failed with error code 0x%08x\n", ntStatus);
    }

    //
    // Identify our new provider as someone who exposes
    // an implementation of the new algorithm.
    //
#pragma warning(suppress: 6387)
    ntStatus = BCryptAddContextFunctionProvider(
                    CRYPT_LOCAL,                    // Scope: local machine only
                    NULL,                           // Application context: default
                    NCRYPT_KEY_STORAGE_INTERFACE,   // Algorithm class
                    NCRYPT_KEY_STORAGE_ALGORITHM,   // Algorithm name
                    TEXT(KSPNAME),        // Provider name
                    CRYPT_PRIORITY_BOTTOM           // Lowest priority
                    );
    if ( !BCRYPT_SUCCESS(ntStatus))
    {
        wprintf(L"BCryptAddContextFunctionProvider failed with error code 0x%08x\n", ntStatus);
    }
	return HRESULT_FROM_NT(ntStatus);
}
///////////////////////////////////////////////////////////////////////////////

HRESULT
UnRegisterKsp()
{
    NTSTATUS ntStatus = 0;

    //
    // Tell CNG that this provider no longer supports
    // this algorithm.
    //
#pragma warning(suppress: 6387)
    ntStatus = BCryptRemoveContextFunctionProvider(
                    CRYPT_LOCAL,                    // Scope: local machine only
                    NULL,                           // Application context: default
                    NCRYPT_KEY_STORAGE_INTERFACE,   // Algorithm class
                    NCRYPT_KEY_STORAGE_ALGORITHM,   // Algorithm name
                    TEXT(KSPNAME)         // Provider
                    );
    if (!BCRYPT_SUCCESS(ntStatus))
    {
        wprintf(L"BCryptRemoveContextFunctionProvider failed with error code 0x%08x\n", ntStatus);
    }


    //
    // Tell CNG to forget about our provider component.
    //
    ntStatus = BCryptUnregisterProvider(TEXT(KSPNAME));
    if (!BCRYPT_SUCCESS(ntStatus))
    {
        wprintf(L"BCryptUnregisterProvider failed with error code 0x%08x\n", ntStatus);
    }
	return HRESULT_FROM_NT(ntStatus);
}
///////////////////////////////////////////////////////////////////////////////




/*++

DllUnregisterServer:

    This service removes the registry entries associated with this CSP.

Arguments:

    None

Return Value:

    Status code as an HRESULT.

Author:

    Doug Barlow (dbarlow) 3/11/1998

--*/

STDAPI
DllUnregisterServer(
    void)
{
	HRESULT hr = UnRegisterCsp();
	if (FAILED(hr))
	{
		return hr;
	}
	hr = UnRegisterKsp();
	return hr;
}


/*++

DllRegisterServer:

    This function installs the proper registry entries to enable this CSP.

Arguments:

    None

Return Value:

    Status code as an HRESULT.

Author:

    Doug Barlow (dbarlow) 3/11/1998

--*/

STDAPI
DllRegisterServer(
    void)
{
	HRESULT hr = RegisterCsp();
	if (FAILED(hr))
	{
		return hr;
	}
	hr = RegisterKsp();
	return hr;
}