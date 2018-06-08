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

PTSTR szDialogReader;
PBYTE pbDialogATR;
DWORD dwDialogATRSize;

BOOL IsElevated()
{
	BOOL fReturn = FALSE;
	HANDLE hToken	= NULL;

	if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &hToken ) )
	{
		return FALSE;
	}

	TOKEN_ELEVATION te = { 0 };
	DWORD dwReturnLength = 0;

	if ( GetTokenInformation(
				hToken,
				TokenElevation,
				&te,
				sizeof( te ),
				&dwReturnLength ) )
	{
	
		fReturn = te.TokenIsElevated ? TRUE : FALSE; 
	}

	CloseHandle(hToken);

	return fReturn;
}


BOOL IsAdmin()
{
	BOOL fReturn = FALSE;
	PSID AdministratorsGroup = NULL;
	__try
	{
		SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
		if (!AllocateAndInitializeSid(&NtAuthority,	2,
						SECURITY_BUILTIN_DOMAIN_RID,
						DOMAIN_ALIAS_RID_ADMINS,
						0, 0, 0, 0, 0, 0,
						&AdministratorsGroup))
		{
			Trace(TRACE_LEVEL_ERROR, L"AllocateAndInitializeSid 0x%08X", GetLastError());
			__leave;
		}
		if (!CheckTokenMembership( NULL, AdministratorsGroup, &fReturn)) 
		{
			Trace(TRACE_LEVEL_ERROR, L"CheckTokenMembership 0x%08X", GetLastError());
			__leave;
		}
		if (fReturn)
		{
			Trace(TRACE_LEVEL_VERBOSE, L"is an admin");
		}
		else
		{
			Trace(TRACE_LEVEL_VERBOSE, L"is NOT an admin");
		}
	}
	__finally
	{
		if (AdministratorsGroup) FreeSid(AdministratorsGroup); 
	}
	return fReturn;
}

#define CSP_NAME TEXT("OpenPGP CSP")
BOOL RegisterThisTag(PBYTE pbATR, DWORD dwAtrSize, PTSTR szName, PTSTR szCalaisDatabaseRoot)
{
	LONG lStatus = 0;
	HKEY hCalais = NULL;
	HKEY hTag = NULL;
	BOOL fReturn = FALSE;
	BYTE pbAtrMask[256];
	__try
	{
		lStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE, szCalaisDatabaseRoot ,0, KEY_ALL_ACCESS,&hCalais);
		if (lStatus)
		{
			Trace(TRACE_LEVEL_ERROR, L"RegOpenKeyEx failed 0x%08X", lStatus);
			__leave;
		}
		lStatus = RegCreateKeyEx(hCalais,szName,NULL,0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,NULL, &hTag,NULL);
		if (lStatus)
		{
			Trace(TRACE_LEVEL_ERROR, L"RegCreateKeyEx failed 0x%08X", lStatus);
			__leave;
		}

		lStatus = RegSetValueEx( hTag,TEXT("Crypto Provider"),0, REG_SZ, (PBYTE)CSP_NAME,sizeof(CSP_NAME));
		if (lStatus)
		{
			Trace(TRACE_LEVEL_ERROR, L"RegSetValueEx failed 0x%08X", lStatus);
			__leave;
		}
		lStatus = RegSetValueEx( hTag,TEXT("ATR"),0, REG_BINARY, pbATR,dwAtrSize);
		if (lStatus)
		{
			Trace(TRACE_LEVEL_ERROR, L"RegSetValueEx failed 0x%08X", lStatus);
			__leave;
		}
		memset(pbAtrMask, 0xFF, min(dwAtrSize, sizeof(pbAtrMask)));
		lStatus = RegSetValueEx( hTag,TEXT("ATRMask"),0, REG_BINARY, pbAtrMask,dwAtrSize);
		if (lStatus)
		{
			Trace(TRACE_LEVEL_ERROR, L"RegSetValueEx failed 0x%08X", lStatus);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hTag) RegCloseKey(hTag);
		if (hCalais) RegCloseKey(hCalais);
	}
	SetLastError(lStatus);
	return fReturn;
}

BOOL RegisterThisTag(PBYTE pbATR, DWORD dwAtrSize, PTSTR szName)
{
	if (!RegisterThisTag(pbATR, dwAtrSize, szName, TEXT("SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards")))
	{
		DWORD dwError = GetLastError();
		Trace(TRACE_LEVEL_ERROR, L"RegisterThisTag with root 1");
		SetLastError(dwError);
		return FALSE;
	}
#ifdef _M_X64
	if (!RegisterThisTag(pbATR, dwAtrSize, szName, TEXT("SOFTWARE\\Wow6432Node\\Microsoft\\Cryptography\\Calais\\SmartCards")))
	{
		DWORD dwError = GetLastError();
		Trace(TRACE_LEVEL_ERROR, L"RegisterThisTag with root 2");
		SetLastError(dwError);
		return FALSE;
	}
#endif
	return TRUE;
}

BOOL DialogRegisterTheTag(HWND hWnd, PTSTR szTagName)
{
	BOOL fDirect = FALSE;
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	__try
	{
		if (fWindowsXPCompatible)
		{
			fDirect = IsAdmin();
		}
		else
		{
			fDirect = IsElevated();
		}
		if (fDirect)
		{
			if (!RegisterThisTag(pbDialogATR, dwDialogATRSize, szTagName))
			{
				dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"RegisterThisTag failed 0x%08X", dwError);
				__leave;
			}
			fReturn = TRUE;
			__leave;
		}

		TCHAR szATR[256];
		for (DWORD i = 0; i < ARRAYSIZE(szATR)/2-1 && i < dwDialogATRSize; i++)
		{
			_stprintf_s(szATR+i*2,ARRAYSIZE(szATR) - 2*i,TEXT("%02X"), pbDialogATR[i]);
		}
		// elevate
		SHELLEXECUTEINFO shExecInfo = {0};
		TCHAR szName[MAX_PATH] = TEXT("");
		TCHAR szParameter[1024] = TEXT("");
		_stprintf_s(szParameter,ARRAYSIZE(szParameter),TEXT("/ADDTAG %s \"%s\""), szATR, szTagName);

		GetModuleFileName(GetModuleHandle(NULL),szName, ARRAYSIZE(szName));
		shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);

		shExecInfo.lpVerb = TEXT("runas");
		shExecInfo.lpFile = szName;
		shExecInfo.lpParameters = szParameter;
		shExecInfo.nShow = SW_NORMAL;
		shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
		shExecInfo.hwnd = hWnd;

		if (!ShellExecuteEx(&shExecInfo))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"ShellExecuteEx failed 0x%08x", dwError);
			__leave;
		}
		if (!WaitForSingleObject(shExecInfo.hProcess, INFINITE) == WAIT_OBJECT_0)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"WaitForSingleObject failed 0x%08x", dwError);
			__leave;
		}
		if (!GetExitCodeProcess(shExecInfo.hProcess, &dwError))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"GetExitCodeProcess failed 0x%08x", dwError);
			__leave;
		}
		if (dwError)
		{
			Trace(TRACE_LEVEL_ERROR,L"Register the tag failed 0x%08x", dwError);
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

INT_PTR CALLBACK WndProcAddTag(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	int wmId, wmEvent;
	switch(message)
	{
		case WM_INITDIALOG:
			Trace(TRACE_LEVEL_VERBOSE,L"WM_INITDIALOG");
			{
				SetWindowText(GetDlgItem(hWnd, IDC_READER), szDialogReader);
				TCHAR szATR[256];
				for (DWORD i = 0; i < ARRAYSIZE(szATR)/3-1 && i < dwDialogATRSize; i++)
				{
					_stprintf_s(szATR+i*3,ARRAYSIZE(szATR) - 3*i,TEXT("%02X "), pbDialogATR[i]);
				}
				SetWindowText(GetDlgItem(hWnd, IDC_ATR), szATR);
				SetWindowText(GetDlgItem(hWnd, IDC_TAGNAME), TEXT("OpenPGP Card Default tag name"));
				SendDlgItemMessage(hWnd,IDOK, BCM_SETSHIELD, 0, (LPARAM)TRUE);
			}
			break;
		case WM_CLOSE:
			Trace(TRACE_LEVEL_VERBOSE,L"WM_CLOSE");
			EndDialog(hWnd, IDCANCEL);
			return TRUE;
		case WM_COMMAND:
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			// Analyse les sélections de menu :
			switch (wmId)
			{
			case IDOK:
				{
					TCHAR szName[256];
					GetWindowText(GetDlgItem(hWnd, IDC_TAGNAME), szName, ARRAYSIZE(szName));
					if (DialogRegisterTheTag(hWnd, szName))
					{
						_tcscpy_s(szReader,dwReaderSize, szDialogReader);
						_tcscpy_s(szCard, dwCardSize, szName);
						EndDialog(hWnd, IDOK);
					}
					else
					{
						MessageBoxWin32Ex(GetLastError(), hWnd);
					}
				}
				break;
			case IDCANCEL:
				Trace(TRACE_LEVEL_VERBOSE,L"IDCANCEL");
				EndDialog(hWnd, IDCANCEL);
				break;
			}
			break;
	}
	return FALSE;
}



BOOL ProposeToRegisterTheCard(HWND hWnd, PTSTR szInputReader, __in_bcount(dwAtrSize) PBYTE pbAtr, DWORD dwAtrSize)
{
	pbDialogATR = pbAtr;
	dwDialogATRSize = dwAtrSize;
	szDialogReader = szInputReader;
	return DialogBox(hInst, MAKEINTRESOURCE(IDD_ADDTAG),hWnd, WndProcAddTag) == IDOK;
}

BOOL CheckIfTheCardCanBeUsedButIsNotRegistered(HWND hWnd, PTSTR szInputReader, SCARDCONTEXT hSC)
{
	BOOL fShouldTheWizardContinue = FALSE;
	LONG lReturn = 0;
	SCARDHANDLE hCard = NULL;
	DWORD dwProtocol;
	LPTSTR szTempReader = NULL;
	DWORD dwTempReaderSize = SCARD_AUTOALLOCATE;
	PBYTE pbAtr = NULL;
	DWORD dwAtrSize = SCARD_AUTOALLOCATE;
	LPTSTR szCards = NULL;
	DWORD dwzCardsSize = SCARD_AUTOALLOCATE;
	BYTE pbCmd[] = {0x00, 
				    0xA4,
					0x04,
					0x00,
					0x06,
					0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
					0x00
					};
	BYTE  SW1, SW2;
	BYTE pbBuffer[256];
	DWORD dwBufferSize = ARRAYSIZE(pbBuffer);
	__try
	{
		lReturn = SCardConnect(hSC, szInputReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &hCard, &dwProtocol);
		if ( SCARD_S_SUCCESS != lReturn )
		{
			Trace(TRACE_LEVEL_ERROR,L"Failed SCardConnect 0x%08X",lReturn);
			__leave;
		}
		// get the ATR
		lReturn = SCardStatus(hCard, (PTSTR) &szTempReader, &dwTempReaderSize, NULL, NULL, (PBYTE)&pbAtr, &dwAtrSize);
		if ( SCARD_S_SUCCESS != lReturn )
		{
			Trace(TRACE_LEVEL_ERROR,L"Failed SCardStatus 0x%08X",lReturn);
			__leave;
		}
		if (!pbAtr)
		{
			Trace(TRACE_LEVEL_ERROR, L"pbAtr null");
			lReturn = ERROR_INTERNAL_ERROR;
			__leave;
		}
		// get the name
		lReturn = SCardListCards(hSC, pbAtr, NULL, 0, (PTSTR) &szCards, &dwzCardsSize);
		if ( SCARD_S_SUCCESS != lReturn )
		{
			Trace(TRACE_LEVEL_ERROR,L"Failed SCardListCards 0x%08X",lReturn);
			__leave;
		}
		if (!szCards)
		{
			Trace(TRACE_LEVEL_ERROR, L"szCards null");
			lReturn = ERROR_INTERNAL_ERROR;
			__leave;
		}
		if (szCards[0] != 0)
		{
			__leave;
		}
		// unknown card
		lReturn = SCardBeginTransaction(hCard);
		if ( lReturn != SCARD_S_SUCCESS )
		{
			Trace(TRACE_LEVEL_ERROR, L"SCardBeginTransaction failed 0x%08X", lReturn);
			__leave;
		}
		lReturn = SCardTransmit(hCard, 
									(dwProtocol == SCARD_PROTOCOL_T1 ? SCARD_PCI_T1 :  SCARD_PCI_T0), 
									pbCmd, 
									ARRAYSIZE(pbCmd), 
									NULL, 
									pbBuffer, 
									&dwBufferSize);
		SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
		if ( lReturn != SCARD_S_SUCCESS )
		{
			Trace(TRACE_LEVEL_ERROR, L"SCardTransmit failed 0x%08X", lReturn);
			__leave;
		}
		SW1 = pbBuffer[dwBufferSize-2];
		SW2 = pbBuffer[dwBufferSize-1];
		if (SW1 != 0x90 || SW2 != 0)
		{
			__leave;
		}
		// found an unknown smart card which has an ID
		fShouldTheWizardContinue = ProposeToRegisterTheCard(hWnd, szInputReader, pbAtr, dwAtrSize);
	}
	__finally
	{
		if (hCard != NULL)
			SCardDisconnect(hCard, SCARD_LEAVE_CARD);
		if (pbAtr)
			SCardFreeMemory(hSC, pbAtr);
		if (szCards)
			SCardFreeMemory(hSC, szCards);
	}
	return fShouldTheWizardContinue;
}

BOOL CheckIfACardCanBeUsedButIsNotRegistered(HWND hWnd)
{
	LONG             lReturn = 0;
	SCARDCONTEXT     hSC = NULL;
	PTSTR szReaders = NULL;
	BOOL fShouldTheWizardContinue = FALSE;
	__try
	{
		// Establish a context.
		// It will be assigned to the structure's hSCardContext field.
		lReturn = SCardEstablishContext(SCARD_SCOPE_USER,
										NULL,
										NULL,
										&hSC );
		if ( SCARD_S_SUCCESS != lReturn )
		{
			Trace(TRACE_LEVEL_ERROR,L"Failed SCardReleaseContext 0x%08X",lReturn);
			__leave;
		}
		DWORD dwReaderCount = SCARD_AUTOALLOCATE;
		lReturn = SCardListReaders(hSC, NULL,  (LPTSTR)&szReaders, &dwReaderCount);
		if ( SCARD_S_SUCCESS != lReturn )
		{
			Trace(TRACE_LEVEL_ERROR,L"Failed SCardListReaders 0x%08X",lReturn);
			__leave;
		}
		if (!szReaders)
		{
			Trace(TRACE_LEVEL_ERROR, L"szReaders NULL");
			lReturn = ERROR_INTERNAL_ERROR;
			__leave;
		}
		// foreach reader, try to know if there is a smart card
		PTSTR szCurrentReader = szReaders;
		while(szCurrentReader[0] != 0)
		{
			if (CheckIfTheCardCanBeUsedButIsNotRegistered(hWnd, szCurrentReader, hSC))
			{
				fShouldTheWizardContinue = TRUE;
				__leave;
			}
			// for the next loop
			szCurrentReader = szCurrentReader + _tcslen(szCurrentReader) + 1;
		}
	}
	__finally
	{
		if (szReaders)
			SCardFreeMemory(hSC, szReaders);
		if (hSC)
			SCardReleaseContext(hSC);
	}
	return fShouldTheWizardContinue;
}