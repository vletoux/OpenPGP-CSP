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


ChangePINDialog::ChangePINDialog()
{
	strcpy_s(_szBeforePin,ARRAYSIZE(_szBeforePin), "");
	strcpy_s(_szAfterPin,ARRAYSIZE(_szAfterPin), "");
}

ChangePINDialog::~ChangePINDialog()
{
	SecureZeroMemory(_szBeforePin, sizeof(_szBeforePin));
	SecureZeroMemory(_szAfterPin, sizeof(_szAfterPin));
}

INT_PTR ChangePINDialog::Show()
{
	HWND hWndParent = NULL;
	GetHWND(&hWndParent);
	return DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_CHANGEPIN), hWndParent, _dialogProc, (LPARAM)this);
}

INT_PTR CALLBACK ChangePINDialog::_dialogProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (WM_INITDIALOG == msg) {
        ((ChangePINDialog*)lp)->_hwnd = hwnd;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, lp);
    }
	ChangePINDialog* dlg = (ChangePINDialog*)GetWindowLongPtr(hwnd, GWLP_USERDATA);

    // WM_SETFONT is coming in before WM_INITDIALOG
    // in which case GWLP_USERDATA won't be set yet.
	if (dlg) {
		return dlg->DialogProc(msg, wp, lp);
	}
    return FALSE;
}


INT_PTR ChangePINDialog::DialogProc(UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) 
	{
	case WM_INITDIALOG:
		{
			InitDialog();
		}
		break;
	case WM_CLOSE:
		Trace(TRACE_LEVEL_VERBOSE,L"WM_CLOSE");
		EndDialog(_hwnd, IDCANCEL);
		return TRUE;
	case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDOK:
                    Enter();
					break;
                case IDCANCEL:
                    EndDialog(_hwnd, IDCANCEL);
                    break;
            }
            return TRUE;
        }
    }
	return FALSE;
}

void ChangePINDialog::CenterWindow() 
{
    RECT rc;
    if (!GetWindowRect(_hwnd, &rc)) return;

    const int width  = rc.right  - rc.left;
    const int height = rc.bottom - rc.top;

    MoveWindow(_hwnd,
        (GetSystemMetrics(SM_CXSCREEN) - width)  / 2,
        (GetSystemMetrics(SM_CYSCREEN) - height) / 2,
        width, height, true);
}


VOID ChangePINDialog::InitDialog()
{
	CenterWindow();
	// focus to PIN
	SendMessage(_hwnd, WM_NEXTDLGCTL, (WPARAM)GetDlgItem(this->_hwnd,IDC_VERIFY), TRUE);
}


BOOL ChangePINDialog::Enter()
{
	DWORD dwError = 0, dwRemaingPinAttempt = 0;
	PCCERT_CONTEXT pCertContext = NULL;
	BOOL fReturn = FALSE;
	BOOL fLogonSuccess = FALSE;
	DWORD dwSize = 0;
	CHAR szPIN2[MAX_PIN_SIZE];
	__try
	{
		GetWindowTextA(GetDlgItem(_hwnd,IDC_PIN), _szAfterPin, ARRAYSIZE(_szAfterPin));
		GetWindowTextA(GetDlgItem(_hwnd,IDC_PINCONFIRM), szPIN2, ARRAYSIZE(szPIN2));
		if (strcmp(szPIN2, _szAfterPin) != 0)
		{
			MessageBox(_hwnd, TEXT("The two PINs don't match"), TEXT("Error"), MB_ICONSTOP);
			fReturn = FALSE;
			__leave;
		}
		GetWindowTextA(GetDlgItem(_hwnd,IDC_VERIFY), _szBeforePin, ARRAYSIZE(_szBeforePin));
		fReturn = TRUE;
		EndDialog(_hwnd, IDOK);
	}
	__finally
	{
		
	}
	return fReturn;
}

VOID ChangePINDialog::GetBeforePIN(__out_ecount(MAX_PIN_SIZE) PSTR szPin)
{
	strcpy_s(szPin, MAX_PIN_SIZE, _szBeforePin);
}

VOID ChangePINDialog::GetAfterPIN(__out_ecount(MAX_PIN_SIZE) PSTR szPin)
{
	strcpy_s(szPin, MAX_PIN_SIZE, _szAfterPin);
}