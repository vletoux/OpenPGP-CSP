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


#include "global.h"



INT_PTR CALLBACK	P12Proc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

VOID ImportACertificate(HWND hWnd)
{
	DialogBox(GetModuleHandle(NULL),MAKEINTRESOURCE(IDD_P12IMPORT),hWnd,P12Proc);
	if (!CryptSetProvParam(NULL, PP_CLIENT_HWND, (PBYTE) &hWnd, sizeof(HWND)))
	{
		Trace(TRACE_LEVEL_INFORMATION, L"PP_CLIENT_HWND failed 0x%08X");
	} 
}

BOOL SelectFile(HWND hWnd)
{
	// select file to open
	TCHAR szSpecContainer[256] = TEXT("");
	TCHAR szSpecAll[256] = TEXT("");
	OPENFILENAME ofn;
	TCHAR szFile[MAX_PATH], szFilter[256];
	_stprintf_s(szFilter, 256, TEXT("%s%c*.pfx;*.p12%c%s%c*.*%c"),szSpecContainer,0,0,szSpecAll,0,0);
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hWnd;
	ofn.lpstrFile = szFile;
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrFilter = szFilter;
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	if (GetOpenFileName(&ofn)==TRUE) 
	{
		SetWindowText(GetDlgItem(hWnd,IDC_P12FILENAME),szFile);
		return TRUE;
	}
	return FALSE;
}

// see http://msdn.microsoft.com/en-us/library/windows/desktop/aa387401%28v=vs.85%29.aspx
typedef struct _RSAPRIVATEKEY {
	BLOBHEADER blobheader;
	RSAPUBKEY rsapubkey;
#ifdef _DEBUG
#define BITLEN_TO_CHECK 2048
	BYTE modulus[BITLEN_TO_CHECK/8];
	BYTE prime1[BITLEN_TO_CHECK/16];
	BYTE prime2[BITLEN_TO_CHECK/16];
	BYTE exponent1[BITLEN_TO_CHECK/16];
	BYTE exponent2[BITLEN_TO_CHECK/16];
	BYTE coefficient[BITLEN_TO_CHECK/16];
	BYTE privateExponent[BITLEN_TO_CHECK/8];
#endif
} RSAPRIVKEY, *PRSAPRIVKEY;

BOOL CheckRSAKeyLength(PTSTR szContainerName, PTSTR szProviderName, RSAPRIVKEY* pbData)
{
	BOOL fReturn = FALSE;
	HCRYPTPROV hProv = NULL;
	DWORD dwError = 0;
	DWORD dwFlags = CRYPT_FIRST;
	PROV_ENUMALGS_EX alg;
	DWORD dwSize;
	__try
	{
		if (pbData->blobheader.bType != PRIVATEKEYBLOB)
		{
			dwError = ERROR_INVALID_PARAMETER;
			Trace(TRACE_LEVEL_WARNING,L"ERROR_INVALID_PARAMETER");
			__leave;
		}
		if (! CryptAcquireContext(&hProv,szContainerName, szProviderName, PROV_RSA_FULL,CRYPT_VERIFYCONTEXT))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
			__leave;
		}
		dwSize = sizeof(PROV_ENUMALGS_EX);
		while (CryptGetProvParam(hProv,
				PP_ENUMALGS_EX,
				(LPBYTE) &alg,
				&dwSize,
				dwFlags)
			)
		{
			if (alg.aiAlgid == pbData->blobheader.aiKeyAlg)
			{
				if (pbData->rsapubkey.bitlen >= alg.dwMinLen && pbData->rsapubkey.bitlen <= alg.dwMaxLen)
				{
					fReturn = TRUE;
				}
				else
				{
					dwError = (DWORD) NTE_BAD_LEN;
					Trace(TRACE_LEVEL_WARNING,L"Invalid bitlen should be %d < %d < %d",alg.dwMinLen,pbData->rsapubkey.bitlen, alg.dwMaxLen);
				}
				__leave;
			}
			dwSize = sizeof(PROV_ENUMALGS_EX);
			dwFlags = 0;
		}
		Trace(TRACE_LEVEL_VERBOSE,L"no alg data found");
		fReturn = TRUE;
	}
	__finally
	{
		if (hProv)
			CryptReleaseContext(hProv, 0);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL ImportFileToSmartCard(HWND hWnd, PTSTR szFileName, PTSTR szPassword, PTSTR szReaderName, PTSTR szCardname)
{
	BOOL fReturn = FALSE;
	CRYPT_DATA_BLOB DataBlob = {0};
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HCERTSTORE hCS = NULL;
	DWORD dwRead = 0;
	TCHAR szProviderName[1024];
	DWORD dwProviderNameLen = ARRAYSIZE(szProviderName);
	PWSTR szContainerName = NULL;
	HCRYPTPROV hCardProv = NULL, hProv = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	BOOL fFreeProv = FALSE;
	DWORD dwKeySpec = AT_KEYEXCHANGE;
	HCRYPTKEY hKey = NULL, hCardKey = NULL;
	PRSAPRIVKEY pbData = NULL;
	DWORD dwSize = 0;
	DWORD dwError = 0;
	BOOL fSetBackMSBaseSCCryptoFlagImport = FALSE;
	__try
	{
		Trace(TRACE_LEVEL_VERBOSE,L"Importing %s", szFileName);
		if (!CryptSetProvParam(NULL, PP_CLIENT_HWND, (PBYTE) &hWnd, sizeof(HWND)))
		{
			Trace(TRACE_LEVEL_INFORMATION, L"PP_CLIENT_HWND failed 0x%08X");
		} 
		hFile = CreateFile(szFileName,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_WARNING,L"CreateFile 0x%08x",dwError);
			__leave;
		}
		DataBlob.cbData = GetFileSize(hFile,NULL);
		if (!DataBlob.cbData)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_WARNING,L"GetFileSize 0x%08x",dwError);
			__leave;
		}
		DataBlob.pbData = (PBYTE) malloc(DataBlob.cbData);
		if (!DataBlob.pbData)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_WARNING,L"EIDAlloc 0x%08x",dwError);
			__leave;
		}
		if (!ReadFile(hFile, DataBlob.pbData, DataBlob.cbData, &dwRead, NULL))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_WARNING,L"ReadFile 0x%08x",dwError);
			__leave;
		}
		hCS = PFXImportCertStore(&DataBlob, szPassword, CRYPT_EXPORTABLE | CRYPT_USER_KEYSET );
		if(!hCS)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_WARNING,L"PFXImportCertStore 0x%08x",dwError);
			__leave;
		}
		// provider name
		if (!SchGetProviderNameFromCardName(szCardname, szProviderName, &dwProviderNameLen))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_WARNING,L"SchGetProviderNameFromCardName 0x%08x",dwError);
			__leave;
		}
		// container name from card name
		szContainerName = (LPTSTR) malloc((DWORD)(_tcslen(szReaderName) + 6) * sizeof(TCHAR));
		if (!szContainerName)
		{
			//dwError = GetLastError();
			dwError = GetLastError();
			Trace(TRACE_LEVEL_WARNING,L"EIDAlloc 0x%08x",dwError);
			__leave;
		}
		_stprintf_s(szContainerName,(_tcslen(szReaderName) + 6), _T("\\\\.\\%s\\"), szReaderName);
		pCertContext = CertEnumCertificatesInStore(hCS, NULL);
		while( pCertContext )
		{
			dwSize = 0;
			// this check allows to find which certificate has a private key
			if (CertGetCertificateContextProperty(pCertContext,CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize))
			{	
				if (! CryptAcquireCertificatePrivateKey(pCertContext, 0, NULL, &hProv, &dwKeySpec, &fFreeProv))
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_WARNING,L"CryptAcquireCertificatePrivateKey 0x%08x",dwError);
					__leave;
				}
				if (_tcscmp(szProviderName,MS_SCARD_PROV) == 0)
				{
					// check if MS Base crypto allow the import. If not, enable it
					HKEY hRegKey;
					DWORD dwKeyData = 0;
					dwSize = sizeof(DWORD);
					dwError = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Base Smart Card Crypto Provider"),NULL, KEY_READ|KEY_QUERY_VALUE|KEY_WRITE, &hRegKey);
					if (! dwError)
					{
						if (dwKeySpec == AT_SIGNATURE)
						{
							RegQueryValueEx(hRegKey,TEXT("AllowPrivateSignatureKeyImport"),NULL, NULL,(PBYTE)&dwKeyData,&dwSize);
							Trace(TRACE_LEVEL_INFORMATION, L"AllowPrivateSignatureKeyImport = %d", dwKeyData);
						}
						else
						{
							RegQueryValueEx(hRegKey,TEXT("AllowPrivateExchangeKeyImport"),NULL, NULL,(PBYTE)&dwKeyData,&dwSize);
							Trace(TRACE_LEVEL_INFORMATION, L"AllowPrivateExchangeKeyImport = %d", dwKeyData);
						}
						if (!dwKeyData)
						{
							Trace(TRACE_LEVEL_INFORMATION, L"Try to change the policy");
							fSetBackMSBaseSCCryptoFlagImport = TRUE;
							dwKeyData = 1;
							dwSize = sizeof(DWORD);
							if (dwKeySpec == AT_SIGNATURE)
							{
								dwError = RegSetValueEx(hRegKey,TEXT("AllowPrivateSignatureKeyImport"),NULL, REG_DWORD,(PBYTE)&dwKeyData,dwSize);
							}
							else
							{
								dwError = RegSetValueEx(hRegKey,TEXT("AllowPrivateExchangeKeyImport"),NULL, REG_DWORD,(PBYTE)&dwKeyData,dwSize);
							}
							if (dwError)
							{
								Trace(TRACE_LEVEL_WARNING,L"RegSetValueEx 0x%08x (not running as admin ?)",dwError);
							}
						}
						RegCloseKey(hRegKey);
					}
					else
					{
						Trace(TRACE_LEVEL_WARNING,L"RegOpenKeyEx 0x%08x",dwError);
						dwError = ERROR_ACCESS_DENIED;
						__leave;
					}

				}
				if (!CryptGetUserKey(hProv, dwKeySpec, &hKey))
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_WARNING,L"CryptGetUserKey 0x%08x",dwError);
					__leave;
				}
				dwSize = 0;
				if (!CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, NULL, &dwSize))
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_WARNING,L"CryptExportKey 0x%08x",dwError);
					__leave;
				}
				pbData = (PRSAPRIVKEY) malloc(dwSize);
				if (!pbData)
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_WARNING,L"EIDAlloc 0x%08x",dwError);
					__leave;
				}
				memset(pbData, 0, dwSize);
				if (!CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, (PBYTE) pbData, &dwSize))
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_WARNING,L"CryptExportKey 0x%08x",dwError);
					__leave;
				}
				// check key length
				if (!CheckRSAKeyLength(szContainerName, szProviderName, pbData))
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_WARNING,L"CheckRSAKeyLength 0x%08x",dwError);
					__leave;
				}
				if (! CryptAcquireContext(&hCardProv,szContainerName, szProviderName, PROV_RSA_FULL,CRYPT_NEWKEYSET))
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
					__leave;
				}
				if (!CryptImportKey(hCardProv, (PBYTE) pbData, dwSize, NULL, 0, &hCardKey))
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_WARNING,L"CryptImportKey 0x%08x",dwError);
					if (dwError == NTE_BAD_TYPE)
					{
						Trace(TRACE_LEVEL_WARNING,L"Check that the import policy on base smart card CSP has been disabled (not admin ?)");
					}
					__leave;
				}
				if (!CryptSetKeyParam(hCardKey, KP_CERTIFICATE, pCertContext->pbCertEncoded, 0))
				{
					dwError = GetLastError();
					Trace(TRACE_LEVEL_WARNING,L"CryptSetKeyParam 0x%08x",dwError);
					__leave;
				}
				Trace(TRACE_LEVEL_WARNING,L"OK");
				fReturn = TRUE;
				__leave;
			}
			pCertContext = CertEnumCertificatesInStore(hCS, pCertContext);
		}
		Trace(TRACE_LEVEL_WARNING,L"not found");
	}
	__finally
	{
		if (hCardKey)
			CryptDestroyKey(hCardKey);
		if (pbData)
			free(pbData);
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv && fFreeProv)
			CryptReleaseContext(hProv, 0);
		if (pCertContext)
			CertFreeCertificateContext(pCertContext);
		if (hCardProv)
			CryptReleaseContext(hCardProv, 0);
		if (szContainerName) 
			free(szContainerName);			
		if (hCS)
			CertCloseStore(hCS, 0);
		if (DataBlob.pbData)
			free(DataBlob.pbData);
		if (hFile != INVALID_HANDLE_VALUE)
			CloseHandle(hFile);
		if (fSetBackMSBaseSCCryptoFlagImport)
		{
			HKEY hRegKey;
			DWORD dwKeyData = 0;
			dwSize = sizeof(DWORD);
			if (!RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Base Smart Card Crypto Provider"),0,KEY_READ|KEY_QUERY_VALUE|KEY_WRITE, &hRegKey))
			{
				if (dwKeySpec == AT_SIGNATURE)
				{
					RegSetValueEx(hRegKey,TEXT("AllowPrivateSignatureKeyImport"),NULL, REG_DWORD,(PBYTE)&dwKeyData,dwSize);
				}
				else
				{
					RegSetValueEx(hRegKey,TEXT("AllowPrivateExchangeKeyImport"),NULL, REG_DWORD,(PBYTE)&dwKeyData,dwSize);
				}
				RegCloseKey(hRegKey);
			}
		}
	}
	SetLastError(dwError);
	return fReturn;
}

INT_PTR CALLBACK	P12Proc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	int wmId;
	int wmEvent;
	switch(message)
	{
		case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		// Analyse les sélections de menu :
		switch (wmId)
		{	
			case IDC_SELECTP12FILE:
				SelectFile(hWnd);
				break;
			case IDCANCEL:
				EndDialog(hWnd,FALSE);
				break;
			case IDOK:
				Trace(TRACE_LEVEL_WARNING,L"IDC_03IMPORT");
				TCHAR szFileName[1024] = TEXT("");
				TCHAR szPassword[1024] = TEXT("");
				GetWindowText(GetDlgItem(hWnd,IDC_P12FILENAME),szFileName,ARRAYSIZE(szFileName));
				GetWindowText(GetDlgItem(hWnd,IDC_IMPORTPASSWORD),szPassword,ARRAYSIZE(szPassword));
				if (!ImportFileToSmartCard(hWnd, szFileName, szPassword, szReader, szCard))
				{
					DWORD dwError = GetLastError();
					if (dwError != SCARD_W_CANCELLED_BY_USER)
						MessageBoxWin32Ex(dwError,hWnd);
					return FALSE;
				}
				else
				{
					EndDialog(hWnd,TRUE);
				}
		}
		break;
	}
	return FALSE;
}