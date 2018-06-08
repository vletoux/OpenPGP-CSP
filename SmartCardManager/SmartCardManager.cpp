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

#pragma comment(lib,"Comctl32")
#ifdef UNICODE
#if defined _M_IX86
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_IA64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='ia64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif
#endif

WCHAR szReader[256];
DWORD dwReaderSize = ARRAYSIZE(szReader);
WCHAR szCard[256];
DWORD dwCardSize = ARRAYSIZE(szCard);
WCHAR szProvider[256];
DWORD dwProviderSize = ARRAYSIZE(szProvider);

HINSTANCE hInst = 0;
BOOL fWindowsXPCompatible = FALSE;

VOID CenterWindow(HWND hWnd)
{
	RECT rc;
    if (!GetWindowRect(hWnd, &rc)) return;

    const int width  = rc.right  - rc.left;
    const int height = rc.bottom - rc.top;

    MoveWindow(hWnd,
        (GetSystemMetrics(SM_CXSCREEN) - width)  / 2,
        (GetSystemMetrics(SM_CYSCREEN) - height) / 2,
        width, height, true);
}

/**
 *  Display a messagebox giving an error code
 */
void MessageBoxWin32Ex2(DWORD status, HWND hWnd, LPCSTR szFile, DWORD dwLine) {
	LPTSTR Error = NULL;
	TCHAR szMessage[1024];
	TCHAR szTitle[1024];
	_stprintf_s(szTitle,ARRAYSIZE(szTitle),TEXT("%hs(%d)"),szFile, dwLine);
		// system error message
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,status,0,(LPTSTR)&Error,0,NULL);
	_stprintf_s(szMessage,ARRAYSIZE(szMessage),TEXT("0x%08X - %s"),status,Error);
	if (status != ERROR_CANCELLED)
	{
		MessageBox(hWnd,szMessage, szTitle ,MB_ICONASTERISK);
	}
	LocalFree(Error);
}

VOID CreateToolTip(HWND hWnd, int toolID, int resourceMessage)
{
	HWND hwndTip = CreateWindowEx(NULL, TOOLTIPS_CLASS, NULL,
								WS_POPUP | TTS_ALWAYSTIP | TTS_BALLOON,
								CW_USEDEFAULT, CW_USEDEFAULT,
								CW_USEDEFAULT, CW_USEDEFAULT,
								hWnd, NULL,
								hInst, NULL);
	if (!hwndTip) return;

	TOOLINFO toolInfo = {0};
	toolInfo.cbSize = sizeof(toolInfo);
	toolInfo.hwnd = hWnd;
	toolInfo.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
	toolInfo.uId = (UINT_PTR) GetDlgItem(hWnd, toolID);
	toolInfo.lpszText = MAKEINTRESOURCE(resourceMessage);
	SendMessage(hwndTip, TTM_ADDTOOL, 0, (LPARAM) &toolInfo);
}

BOOL IsCurrentUserBelongToADomain()
{
	BOOL fReturn = FALSE;
	HANDLE hToken	= NULL;
	PTOKEN_USER  ptiUser  = NULL;
	DWORD dwError = 0;
	__try
	{
		if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &hToken ) )
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"OpenProcessToken failed 0x%08X",dwError);
			__leave;
		}
		
		DWORD        cbti     = 0;
		// Obtain the size of the user information in the token.
		if (GetTokenInformation(hToken, TokenUser, NULL, 0, &cbti)) {

			// Call should have failed due to zero-length buffer.
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetTokenInformation failed 0x%08X", dwError);
			__leave;
   
		} else {

			// Call should have failed due to zero-length buffer.
			dwError = GetLastError();
			if (dwError != ERROR_INSUFFICIENT_BUFFER)
			{
				Trace(TRACE_LEVEL_ERROR, L"GetTokenInformation failed 0x%08X", dwError);
				__leave;
			}
		}

		// Allocate buffer for user information in the token.
		ptiUser = (PTOKEN_USER) HeapAlloc(GetProcessHeap(), 0, cbti);
		if (!ptiUser)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"HeapAlloc failed 0x%08X", dwError);
			__leave;
		}

		// Retrieve the user information from the token.
		if (!GetTokenInformation(hToken, TokenUser, ptiUser, cbti, &cbti))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetTokenInformation failed 0x%08X", dwError);
			__leave;
		}

		TCHAR szUser[255];
		DWORD cchUser = ARRAYSIZE(szUser);
		TCHAR szDomain[255];
		DWORD cchDomain = ARRAYSIZE(szDomain);
		SID_NAME_USE snu;
		if (!LookupAccountSid(NULL, ptiUser->User.Sid, szUser, &cchUser, 
            szDomain, &cchDomain, &snu))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"LookupAccountSid failed 0x%08X", dwError);
			__leave;
		}
		TCHAR szComputerName[255];
		DWORD cchComputerName = ARRAYSIZE(szComputerName);
		if (!GetComputerName(szComputerName,&cchComputerName))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR, L"GetComputerName failed 0x%08X", dwError);
			__leave;
		}
		if (_tcsicmp(szComputerName,szDomain) != 0)
		{
			Trace(TRACE_LEVEL_INFORMATION, L"User belong to a domain");
			fReturn = TRUE;
		}
		else
		{
			Trace(TRACE_LEVEL_INFORMATION, L"User doesn't belong to a domain");
		}
	}
	__finally
	{
		if (hToken)
			CloseHandle(hToken);
		if (ptiUser)
			HeapFree(GetProcessHeap(), 0, ptiUser);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL AskForCard(HWND hWnd, LPWSTR szInputReader, DWORD ReaderLength,LPWSTR szInputCard,DWORD CardLength)
{
	SCARDCONTEXT     hSC = NULL;
	OPENCARDNAME_EX  dlgStruct;
	OPENCARD_SEARCH_CRITERIA searchCriteria;
	LONG             lReturn = 0;
	BOOL			 fReturn = FALSE;
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

		// Initialize the structure.
		memset(&dlgStruct, 0, sizeof(dlgStruct));
		memset(&searchCriteria, 0, sizeof(searchCriteria));
		
		dlgStruct.dwStructSize = sizeof(dlgStruct);
		dlgStruct.hSCardContext = hSC;
		dlgStruct.hwndOwner = hWnd;
		dlgStruct.dwFlags = SC_DLG_MINIMAL_UI;
		dlgStruct.lpstrRdr = szInputReader;
		dlgStruct.nMaxRdr = ReaderLength;
		dlgStruct.lpstrCard = szInputCard;
		dlgStruct.nMaxCard = CardLength;
		dlgStruct.pOpenCardSearchCriteria = &searchCriteria;
		searchCriteria.dwStructSize = sizeof(searchCriteria);
		//searchCriteria.lpstrCardNames = szSmartCard;
		//searchCriteria.nMaxCardNames = ARRAYSIZE(szSmartCard);

		// Display the select card dialog box.
		lReturn = SCardUIDlgSelectCard(&dlgStruct);
		if ( SCARD_S_SUCCESS != lReturn )
		{
			Trace(TRACE_LEVEL_ERROR,L"Failed SCardUIDlgSelectCard 0x%08X",lReturn);
			szInputReader[0]=0;
			szInputCard[0]=0;
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hSC)
			SCardReleaseContext(hSC);
	}
	// Free the context.
	// lReturn is of type LONG.
	// hSC was set by an earlier call to SCardEstablishContext.
	SetLastError(lReturn);
	return fReturn;
}

VOID AddCertificate(PBYTE pbData, DWORD dwSize, int itemNum, HWND hWnd)
{
	LVITEM lvI;
	ZeroMemory(&lvI, sizeof(lvI));
	PCCERT_CONTEXT pCertContext = NULL;
	BOOL fOK = FALSE;
	DWORD dwResult;
	TCHAR szSubject[256];
	__try
	{
		pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pbData, dwSize);
		if (!pCertContext)
		{
			Trace(TRACE_LEVEL_ERROR, L"CertCreateCertificateContext 0x%08x",GetLastError());
			__leave;
		}
		dwResult = CertGetNameString(pCertContext,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,NULL,szSubject,ARRAYSIZE(szSubject));
		if (!dwResult) 
		{
			Trace(TRACE_LEVEL_ERROR, L"CertNameToStr subject 0x%08x",GetLastError());
			__leave;
		}
		fOK = TRUE;
		lvI.iItem = itemNum;
		lvI.mask = LVIF_TEXT| LVIF_IMAGE | LVIF_PARAM;
		lvI.pszText = szSubject;
		lvI.iImage = 1;
		lvI.lParam = (LPARAM) pCertContext;
		pCertContext = NULL;
		ListView_InsertItem(GetDlgItem(hWnd, IDC_LISTCERTIFICATES), &lvI);
	}
	__finally
	{
		if (pCertContext) CertFreeCertificateContext(pCertContext);
		if (!fOK)
		{
			lvI.iItem = itemNum;
			lvI.mask = LVIF_TEXT| LVIF_IMAGE ;
			lvI.iImage = 0;
			lvI.pszText = TEXT("Error while reading the certificate");
			ListView_InsertItem(GetDlgItem(hWnd, IDC_LISTCERTIFICATES), &lvI);
		}
	}
}

BOOL GetProvider(__inout_ecount(256) PTSTR szInputProvider, __in PTSTR szInputCard)
{
	BOOL fReturn = FALSE;
	SCARDCONTEXT hSCardContext = NULL;
	LONG lCardStatus = 0;
	DWORD dwProviderNameLen = 256;
	__try
	{
		lCardStatus = SCardEstablishContext(SCARD_SCOPE_USER,NULL,NULL,&hSCardContext);
		if (SCARD_S_SUCCESS != lCardStatus)
		{
			Trace(TRACE_LEVEL_ERROR,L"SCardEstablishContext 0x%08x",lCardStatus);
			__leave;
		}
	
		lCardStatus = SCardGetCardTypeProviderName(hSCardContext,
											szInputCard,
											SCARD_PROVIDER_CSP,
											szInputProvider,
											&dwProviderNameLen);
		if (SCARD_S_SUCCESS != lCardStatus)
		{
			Trace(TRACE_LEVEL_ERROR,L"SCardGetCardTypeProviderName 0x%08x",lCardStatus);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hSCardContext) SCardReleaseContext(hSCardContext);
	}
	SetLastError(lCardStatus);
	return fReturn;
}

VOID RefreshContainer(HWND hWnd)
{
	BOOL fReturn;
	HCRYPTPROV hProv = NULL;
	HCRYPTPROV hProvCurrent = NULL;
	HCRYPTKEY hKey = NULL;
	CHAR szCharContainerName[256];
	TCHAR szContainerName[256];
	DWORD dwContainerNameLen = ARRAYSIZE(szContainerName);
	DWORD pKeySpecs[2] = {AT_KEYEXCHANGE,AT_SIGNATURE};
	DWORD dwError;
	LVITEM lvI;
	int itemNum = 0;
	__try
	{
		ListView_DeleteAllItems(GetDlgItem(hWnd, IDC_LISTCERTIFICATES));
		_stprintf_s(szContainerName,ARRAYSIZE(szContainerName), _T("\\\\.\\%s\\"), szReader);
		fReturn = CryptAcquireContext(&hProv,
					szContainerName,
					szProvider,
					PROV_RSA_FULL,
					CRYPT_SILENT);
		if (!fReturn)
		{
			dwError =  GetLastError();
			if (NTE_BAD_KEYSET == dwError)
			{
				ZeroMemory(&lvI, sizeof(lvI));
				lvI.mask = LVIF_TEXT | LVIF_IMAGE;
				lvI.iImage = 2;
				lvI.pszText = TEXT("The smart card is empty");
				ListView_InsertItem(GetDlgItem(hWnd, IDC_LISTCERTIFICATES), &lvI);
				__leave;
			}
			else
			{
				Trace(TRACE_LEVEL_ERROR,L"CryptAcquireContext 1 0x%08x",dwError);
				TCHAR szBuffer[100];
				_stprintf_s(szBuffer, TEXT("Error 0x%08X"), dwError);
				ZeroMemory(&lvI, sizeof(lvI));
				lvI.mask = LVIF_TEXT | LVIF_IMAGE;
				lvI.iImage = 0;
				lvI.pszText = szBuffer;
				ListView_InsertItem(GetDlgItem(hWnd, IDC_LISTCERTIFICATES), &lvI);
				__leave;
			}
		}
		DWORD dwFlags = CRYPT_FIRST;
		/* Enumerate all the containers */

		while (CryptGetProvParam(hProv,
					PP_ENUMCONTAINERS,
					(PBYTE) szCharContainerName,
					&dwContainerNameLen,
					dwFlags)
				)
		{
			// convert the container name to unicode
#ifdef UNICODE
			MultiByteToWideChar(CP_ACP, 0, szCharContainerName, (int)strlen(szCharContainerName)+1, szContainerName, ARRAYSIZE(szContainerName));
#else
			strcpy_s(szContainerName,ARRAYSIZE(szContainerName),szCharContainerName);
#endif
			// create a CContainer item
			if (CryptAcquireContext(&hProvCurrent,
				szContainerName,
				szProvider,
				PROV_RSA_FULL,
				CRYPT_SILENT))
			{
				BOOL fHashKey = FALSE;
				for (DWORD i = 0; i < ARRAYSIZE(pKeySpecs); i++)
				{
					if (CryptGetUserKey(hProvCurrent,
							pKeySpecs[i],
							&hKey) )
					{
						fHashKey = TRUE;
						BYTE Data[4096];
						DWORD DataSize = 4096;
						if (CryptGetKeyParam(hKey,
								KP_CERTIFICATE,
								Data,
								&DataSize,
								0))
						{
							// certificate
							AddCertificate(Data, DataSize, itemNum, hWnd);
						}
						else
						{
							// no certificate
							ZeroMemory(&lvI, sizeof(lvI));
							lvI.iItem = itemNum;
							lvI.iSubItem = 0;
							lvI.mask = LVIF_TEXT | LVIF_IMAGE;
							lvI.iImage = 0;
							lvI.pszText = TEXT("Container without a certificate");
							ListView_InsertItem(GetDlgItem(hWnd, IDC_LISTCERTIFICATES), &lvI);
						}
						// colmun 1 : container name
						ZeroMemory(&lvI, sizeof(lvI));
						lvI.iItem = itemNum;
						lvI.mask = LVIF_TEXT;
						lvI.iSubItem = 1;
						lvI.pszText = szContainerName;
						ListView_SetItem(GetDlgItem(hWnd, IDC_LISTCERTIFICATES), &lvI);
						// column 2 : keyspec
						ZeroMemory(&lvI, sizeof(lvI));
						lvI.iItem = itemNum;
						lvI.mask = LVIF_TEXT;
						lvI.iSubItem = 2;
						lvI.pszText = (pKeySpecs[i] == AT_KEYEXCHANGE ? L"1":L"2");
						ListView_SetItem(GetDlgItem(hWnd, IDC_LISTCERTIFICATES), &lvI);
						// next loop
						itemNum++;
						CryptDestroyKey(hKey);
						hKey = NULL;
					}
				}
				if (!fHashKey)
				{
					// no certificate
					ZeroMemory(&lvI, sizeof(lvI));
					lvI.iItem = itemNum;
					lvI.iSubItem = 0;
					lvI.mask = LVIF_TEXT | LVIF_IMAGE;
					lvI.iImage = 0;
					lvI.pszText = TEXT("Container without a key");
					ListView_InsertItem(GetDlgItem(hWnd, IDC_LISTCERTIFICATES), &lvI);
					// colmun 1 : container name
					ZeroMemory(&lvI, sizeof(lvI));
					lvI.iItem = itemNum;
					lvI.mask = LVIF_TEXT;
					lvI.iSubItem = 1;
					lvI.pszText = szContainerName;
					ListView_SetItem(GetDlgItem(hWnd, IDC_LISTCERTIFICATES), &lvI);
				}
			}
			CryptReleaseContext(hProvCurrent, 0);
			hProvCurrent = NULL;
			dwFlags = CRYPT_NEXT;
			dwContainerNameLen = ARRAYSIZE(szContainerName);
		}
	}
	__finally
	{
		if (hProv) CryptReleaseContext(hProv, 0);
		if (hProvCurrent) CryptReleaseContext(hProvCurrent,0);
		if (hKey) CryptDestroyKey(hKey);
	}
	ListView_Update(GetDlgItem(hWnd, IDC_LISTCERTIFICATES), 0);
}

VOID ViewCertificate(HWND hWnd, int iSelected)
{
	// get container name
	TCHAR szContainerName[256] = TEXT("");
	TCHAR szKeySpec[3] = TEXT("");
	LVITEM lvI;
	ZeroMemory(&lvI, sizeof(lvI));
	PCCERT_CONTEXT pCertContext = NULL;
	CRYPTUI_VIEWCERTIFICATE_STRUCT certViewInfo;
	BOOL fPropertiesChanged = FALSE;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	__try
	{
		ListView_GetItemText(GetDlgItem(hWnd, IDC_LISTCERTIFICATES),iSelected,1,szContainerName,ARRAYSIZE(szContainerName));
		ListView_GetItemText(GetDlgItem(hWnd, IDC_LISTCERTIFICATES),iSelected,2,szKeySpec,ARRAYSIZE(szKeySpec));
	
		if (!CryptAcquireContext(&hProv,
				szContainerName,
				szProvider,
				PROV_RSA_FULL,
				CRYPT_SILENT))
		{
			Trace(TRACE_LEVEL_ERROR, L"CryptAcquireContext 0x%08x",GetLastError());
			__leave;
		}
		if (!CryptGetUserKey(hProv,
							(_tcscmp(szKeySpec,L"1") == 0 ? AT_KEYEXCHANGE: AT_SIGNATURE),
							&hKey) )
		{
			Trace(TRACE_LEVEL_ERROR, L"CryptGetUserKey 0x%08x",GetLastError());
			__leave;
		}
		BYTE Data[4096];
		DWORD DataSize = 4096;
		if (!CryptGetKeyParam(hKey,
				KP_CERTIFICATE,
				Data,
				&DataSize,
				0))
		{
			Trace(TRACE_LEVEL_ERROR, L"CryptGetKeyParam 0x%08x",GetLastError());
			__leave;
		}
		pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, Data, DataSize);
		if (!pCertContext)
		{
			Trace(TRACE_LEVEL_ERROR, L"CertCreateCertificateContext 0x%08x",GetLastError());
			__leave;
		}
		ZeroMemory(&certViewInfo,sizeof(certViewInfo));
		certViewInfo.dwSize = sizeof(CRYPTUI_VIEWCERTIFICATE_STRUCT);
		certViewInfo.hwndParent = hWnd;
		certViewInfo.szTitle = TEXT("Info");
		certViewInfo.pCertContext = pCertContext;
		CryptUIDlgViewCertificate(&certViewInfo,&fPropertiesChanged);
	}
	__finally
	{
		if (hKey) CryptDestroyKey(hKey);
		if (hProv) CryptReleaseContext(hProv, 0);
		if (pCertContext) CertFreeCertificateContext(pCertContext);
	}
}


VOID Refresh(HWND hWnd)
{
	if (!AskForCard(hWnd, szReader, dwReaderSize, szCard, dwCardSize))
	{
		DWORD dwError = GetLastError();
		if ( dwError != SCARD_W_CANCELLED_BY_USER)
		{
			MessageBoxWin32Ex(dwError,hWnd);
			EndDialog(hWnd,0);
			return;
		}
		if (!CheckIfACardCanBeUsedButIsNotRegistered(hWnd))
		{
			EndDialog(hWnd,0);
			return;
		}
		
	}
	if (!GetProvider(szProvider, szCard))
	{
		DWORD dwError = GetLastError();
		Trace(TRACE_LEVEL_ERROR,L"GetProvider 0x%08x",dwError);
		return;
	}
	RefreshContainer(hWnd);
}

VOID IntializeListView(HWND hWndListView)
{
	LVCOLUMN lvc;
	//ListView_SetExtendedListViewStyle(hWndListView, LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT);
	//ListView_SetView(hWndListView,LV_VIEW_DETAILS);
	// list view columns
	ZeroMemory(&lvc, sizeof(lvc));
	lvc.mask = LVCF_TEXT;
	lvc.pszText = TEXT("Certificates");
	ListView_InsertColumn(hWndListView, 0, &lvc);
	ZeroMemory(&lvc, sizeof(lvc));
	ListView_InsertColumn(hWndListView, 1, &lvc);
	ZeroMemory(&lvc, sizeof(lvc));
	ListView_InsertColumn(hWndListView, 2, &lvc);
	ListView_SetColumnWidth(hWndListView, 0, LVSCW_AUTOSIZE_USEHEADER);
	// list view icons
	HICON hiconItem;     // icon for list-view items 
    HIMAGELIST hLarge;   // image list for icon view 
    HIMAGELIST hSmall;   // image list for other views 

    // Create the full-sized icon image lists. 

	hLarge = ImageList_Create(GetSystemMetrics(SM_CXICON), 
                              GetSystemMetrics(SM_CYICON), 
                               ILC_COLORDDB | ILC_MASK, 3, 3); 

    hSmall = ImageList_Create(GetSystemMetrics(SM_CXSMICON), 
                              GetSystemMetrics(SM_CYSMICON), 
                               ILC_COLORDDB | ILC_MASK, 3, 3); 
	
    ImageList_SetBkColor(hLarge, GetSysColor(COLOR_WINDOW));
	ImageList_SetBkColor(hSmall, GetSysColor(COLOR_WINDOW));
	// 0 = error icon
#pragma warning(push)
#pragma warning(disable:4302)
	hiconItem = LoadIcon(NULL,MAKEINTRESOURCE( IDI_ERROR));
#pragma warning(pop)
	ImageList_AddIcon(hLarge, hiconItem); 
	ImageList_AddIcon(hSmall, hiconItem); 
	DestroyIcon(hiconItem); 

	// 1 = certificate icon
	HMODULE hDll = LoadLibrary(TEXT("certmgr.dll") );
	if (hDll)
	{
		//Check if hIcon is valid
		HICON hIcon = LoadIcon(hDll, MAKEINTRESOURCE(218));
		ImageList_AddIcon(hLarge, hIcon ); 
		ImageList_AddIcon(hSmall, hIcon ); 	
		DestroyIcon(hIcon ); 
		FreeLibrary(hDll);
	}
#pragma warning(push)
#pragma warning(disable:4302)
	hiconItem = LoadIcon(NULL, MAKEINTRESOURCE(IDI_INFORMATION));
#pragma warning(pop)

	ImageList_AddIcon(hLarge, hiconItem); 
	ImageList_AddIcon(hSmall, hiconItem); 
	DestroyIcon(hiconItem); 
	ListView_SetImageList(hWndListView, hLarge, LVSIL_NORMAL); 
    ListView_SetImageList(hWndListView, hSmall, LVSIL_SMALL); 
}

VOID Initialize(HWND hWnd)
{
	CenterWindow(hWnd);		
	IntializeListView(GetDlgItem(hWnd, IDC_LISTCERTIFICATES));
	CreateToolTip(hWnd, IDC_GENERATE, IDS_TOOLTIP_GENERATE);
	CreateToolTip(hWnd, IDC_IMPORT, IDS_TOOLTIP_IMPORT);
	CreateToolTip(hWnd, IDC_REQUEST, IDS_TOOLTIP_REQUEST);
	CreateToolTip(hWnd, IDC_DELETE, IDS_TOOLTIP_DELETE);
	CreateToolTip(hWnd, IDC_REFRESH, IDS_TOOLTIP_REFRESH);
	if (!CryptSetProvParam(NULL, PP_CLIENT_HWND, (PBYTE) &hWnd, sizeof(HWND)))
	{
		Trace(TRACE_LEVEL_INFORMATION, L"PP_CLIENT_HWND failed 0x%08X");
	} 
}

VOID DeleteItems(HWND hWnd)
{
	HWND hWndList = GetDlgItem(hWnd, IDC_LISTCERTIFICATES);
	for (int i = ListView_GetItemCount(hWndList)-1; i >= 0; i--)
	{
		DWORD state = ListView_GetItemState(hWndList,i,(DWORD)(-1));
		if (state & LVIS_SELECTED)
		{
			// deleting item i
			// get container name
			TCHAR szContainerName[256] = TEXT("");
			ListView_GetItemText(hWndList,i,1,szContainerName,ARRAYSIZE(szContainerName));
			if (_tcscmp(szContainerName,TEXT("")) != 0)
			{
				HCRYPTPROV hProv = NULL;
				if (!CryptAcquireContext(&hProv,
						szContainerName,
						szProvider,
						PROV_RSA_FULL,
						CRYPT_DELETEKEYSET))
				{
					DWORD dwError = GetLastError();
					if (dwError != SCARD_W_CANCELLED_BY_USER)
					{
						MessageBoxWin32Ex(dwError,hWnd);
					}
				}
			}
		}
	}
}

VOID TriggerChangePIN(HWND hWnd)
{
	TCHAR szContainerName[256];
	HCRYPTPROV hProv = NULL;
	_stprintf_s(szContainerName,ARRAYSIZE(szContainerName), _T("\\\\.\\%s\\"), szReader);
	
	if (! CryptAcquireContext(&hProv,
					szContainerName,
					szProvider,
					PROV_RSA_FULL,
					0))
	{
		MessageBoxWin32Ex(GetLastError(), hWnd);
		return;
	}
	DWORD dwSize = 0;
	if (CryptGetProvParam(hProv, PP_CHANGE_PASSWORD, NULL, &dwSize, NULL))
	{
		MessageBoxWin32Ex(0, hWnd);
	}
	else
	{
		MessageBoxWin32Ex(GetLastError(), hWnd);
	}
	CryptReleaseContext(hProv, 0);
}

INT_PTR CALLBACK AdvancedWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	int wmId, wmEvent;
	switch(message)
	{
	case WM_INITDIALOG:
		if (!CryptSetProvParam(NULL, PP_CLIENT_HWND, (PBYTE) &hWnd, sizeof(HWND)))
		{
			Trace(TRACE_LEVEL_INFORMATION, L"PP_CLIENT_HWND failed 0x%08X");
		} 
		break;
	case WM_CLOSE:
			Trace(TRACE_LEVEL_VERBOSE,L"WM_CLOSE");
			EndDialog(hWnd, IDOK);
			return TRUE;
		case WM_COMMAND:
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			// Analyse les sélections de menu :
			switch (wmId)
			{
			/*case IDOK:
				EndDialog(hWnd, IDOK);
				break;
			case IDCANCEL:
				Trace(TRACE_LEVEL_VERBOSE,L"IDCANCEL");
				EndDialog(hWnd, IDCANCEL);
				break;*/
			case IDC_CHANGEPIN:
				TriggerChangePIN(hWnd);
				break;
			}
			break;
	}
	return FALSE;
}


INT_PTR CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	LPNMHDR pHeader;
	switch(message)
	{
		case WM_INITDIALOG:
			Trace(TRACE_LEVEL_VERBOSE,L"WM_INITDIALOG");
			Initialize(hWnd);
			Refresh(hWnd);
			if (!IsCurrentUserBelongToADomain())
			{
				EnableWindow(GetDlgItem(hWnd, IDC_REQUEST),FALSE);
			}
			{
				HICON hIcon = LoadIcon(hInst, MAKEINTRESOURCE(IDI_LOGO));
				if (hIcon)
				{
					SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM) hIcon);
					SendMessage(hWnd, WM_SETICON, ICON_BIG, (LPARAM) hIcon);
				}
			}
			break;
		case WM_CLOSE:
			Trace(TRACE_LEVEL_VERBOSE,L"WM_CLOSE");
			 EndDialog(hWnd, IDOK);
			return TRUE;
		case WM_COMMAND:
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			// Analyse les sélections de menu :
			switch (wmId)
			{
			case IDOK:
				EndDialog(hWnd, IDOK);
				break;
			case IDCANCEL:
				Trace(TRACE_LEVEL_VERBOSE,L"IDCANCEL");
				EndDialog(hWnd, IDCANCEL);
				break;
			case IDC_GENERATE:
				{
					TCHAR szUser[256+1] = TEXT("CN=");;
					DWORD dwSize = ARRAYSIZE(szUser)-3;
					GetUserName(szUser+3, &dwSize);
					DWORD ret = MessageBox(hWnd, TEXT("Do you want to be able to decrypt data ?\r\nPress Yes to select decryption & signature and No to select only signature"), TEXT("Type of key"), MB_YESNOCANCEL);
					if (ret == IDCANCEL)
						break;
					if (CreateSelfSignCertificate(szReader, szUser, ret == IDYES))
					{
						Refresh(hWnd);
					}
					else
					{
						if (GetLastError() != SCARD_W_CANCELLED_BY_USER)
						{
							MessageBoxWin32Ex(GetLastError(),hWnd);
						}
					}
				}
				break;
			case IDC_IMPORT:
				ImportACertificate(hWnd);
				Refresh(hWnd);
				break;
			case IDC_REQUEST:
				{
					HRESULT hr = Enroll(hWnd);
					Refresh(hWnd);
					if (FAILED(hr))
					{
						if (hr == E_ACCESSDENIED)
						{
							MessageBox(hWnd, TEXT("Access was denied when trying to issue a certificate.\r\n\r\nLook at the \"Active Directory Certificate Services\" logs for more information"),TEXT("Access denied"), MB_ICONERROR);
						}
						else if (hr == E_UNEXPECTED)
						{
							MessageBox(hWnd, TEXT("The certificate couldn't be issued immediatly. You may adjust \"Active Directory Certificate Services\" parameters to fix this issue."),TEXT("Access denied"), MB_ICONERROR);
						}
						else
						{
							MessageBoxWin32Ex(hr,hWnd);
						}
					}
				}
				break;
			case IDC_DELETE:
				DeleteItems(hWnd);
				Refresh(hWnd);
				break;
			case IDC_REFRESH:
				Refresh(hWnd);
				break;
			}
			break;
		case WM_NOTIFY:
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			// Analyse les sélections de menu :
			switch (wmId)
			{
			case IDC_LISTCERTIFICATES:
				pHeader = (LPNMHDR) lParam;
				switch(pHeader->code)
				{
				case NM_DBLCLK:
					{
						if (((LPNMITEMACTIVATE)lParam)->iItem >= 0)
						{
							ViewCertificate(hWnd, ((LPNMITEMACTIVATE)lParam)->iItem);
						}
					}
					break;
				}
				break;
			case IDC_ADVANCED:
				pHeader = (LPNMHDR) lParam;
				switch(pHeader->code)
				{
					case NM_CLICK:
					case NM_RETURN:
						{
							Trace(TRACE_LEVEL_VERBOSE,L"advanced");
							DialogBox(hInst, MAKEINTRESOURCE(IDD_ADVANCED), hWnd, AdvancedWndProc);
							if (!CryptSetProvParam(NULL, PP_CLIENT_HWND, (PBYTE) &hWnd, sizeof(HWND)))
							{
								Trace(TRACE_LEVEL_INFORMATION, L"PP_CLIENT_HWND failed 0x%08X");
							}
						}
						break;
				}
				break;
			}
			break;
	}
	return FALSE;
}

BOOL Is_Vista_or_Later () ;

 #define xtod(c) ((c>='0' && c<='9') ? c-'0' : ((c>='A' && c<='F') ? \
                c-'A'+10 : ((c>='a' && c<='f') ? c-'a'+10 : 0)))

int APIENTRY _tWinMain(__in HINSTANCE hInstance,
                     __in_opt HINSTANCE hPrevInstance,
                     __in LPTSTR    lpCmdLine,
                     __in int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	UNREFERENCED_PARAMETER(nCmdShow);

	TracingRegister();
	Trace(TRACE_LEVEL_VERBOSE,L"Start");
	// verify important else no windows will be showed on windows XP
	INITCOMMONCONTROLSEX iccx;
	iccx.dwSize=sizeof(INITCOMMONCONTROLSEX);
	iccx.dwICC=ICC_STANDARD_CLASSES | ICC_TAB_CLASSES;
	InitCommonControlsEx(&iccx);
	hInst = hInstance;
	
	int iNumArgs;
	LPWSTR *pszCommandLine =  CommandLineToArgvW(lpCmdLine,&iNumArgs);
	for (int i = 0;i< iNumArgs; i++)
	{
		if (_tcscmp(pszCommandLine[i],TEXT("/ADDTAG")) == 0)
		{
			Trace(TRACE_LEVEL_INFORMATION, L"/ADDTAG");
			if (i+2 >= iNumArgs)
			{
				Trace(TRACE_LEVEL_ERROR,L"missing argument");
				return ERROR_INVALID_PARAMETER;
			}
			BYTE pbAtr[256];
			DWORD dwAtrSize = 0;
			PTSTR sz = pszCommandLine[i+1];
			if (_tcsclen(sz) % 2 != 0)
			{
				Trace(TRACE_LEVEL_ERROR,L"ATR %s invalid", sz);
				return ERROR_INVALID_PARAMETER;
			}
			dwAtrSize =  (DWORD) _tcslen(sz) /2;
			for (DWORD j = 0; j < dwAtrSize; j++)
			{
				pbAtr[j] = (BYTE)((xtod(sz[j*2]) << 4) + xtod(sz[j*2 +1 ]));
			}
			Trace(TRACE_LEVEL_INFORMATION, L"creating key for %s", pszCommandLine[i+2]);
			if (!RegisterThisTag(pbAtr, dwAtrSize, pszCommandLine[i+2]))
			{
				DWORD dwError = GetLastError();
				Trace(TRACE_LEVEL_ERROR, L"RegisterThisTag failed 0x%08X", dwError);
				return dwError;
			}
			return 0;
		}
	}

	fWindowsXPCompatible =  !Is_Vista_or_Later();
	Trace(TRACE_LEVEL_VERBOSE, L"XP compatibility is %s", (fWindowsXPCompatible?L"ON":L"OFF"));
	

	DialogBox (hInstance, MAKEINTRESOURCE(IDD_MAIN),NULL, WndProc);
	Trace(TRACE_LEVEL_VERBOSE,L"End");
	TracingUnRegister();
    return 0;

}