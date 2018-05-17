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


PINDialog::PINDialog(PWSTR szPinPrompt, DWORD dwResourceId) :_szPinPrompt(szPinPrompt), _dwResourceId(dwResourceId)
{
	strcpy_s(_szPin,ARRAYSIZE(_szPin), "");
}

PINDialog::~PINDialog()
{
	SecureZeroMemory(_szPin, sizeof(_szPin));
}

INT_PTR PINDialog::Show()
{
    HWND hWndParent = NULL;
	GetHWND(&hWndParent);
	return DialogBoxParam(g_hInst, MAKEINTRESOURCE(_dwResourceId), hWndParent, _dialogProc, (LPARAM)this);
}

INT_PTR CALLBACK PINDialog::_dialogProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (WM_INITDIALOG == msg) {
        ((PINDialog*)lp)->_hwnd = hwnd;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, lp);
    }
	PINDialog* dlg = (PINDialog*)GetWindowLongPtr(hwnd, GWLP_USERDATA);

    // WM_SETFONT is coming in before WM_INITDIALOG
    // in which case GWLP_USERDATA won't be set yet.
	if (dlg) {
		return dlg->DialogProc(msg, wp, lp);
	}
    return FALSE;
}


INT_PTR PINDialog::DialogProc(UINT msg, WPARAM wParam, LPARAM lParam)
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

void PINDialog::CenterWindow() 
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


VOID PINDialog::InitDialog()
{
	CenterWindow();
	if (_szPinPrompt)
	{
		SetWindowText(GetDlgItem(_hwnd,IDC_PIN_PROMPT), _szPinPrompt);
	}
	// focus to PIN
	SendMessage(_hwnd, WM_NEXTDLGCTL, (WPARAM)GetDlgItem(this->_hwnd,IDC_PIN), TRUE);
	SetWindowPos(_hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
}


BOOL PINDialog::Enter()
{
	DWORD dwError = 0, dwRemaingPinAttempt = 0;
	PCCERT_CONTEXT pCertContext = NULL;
	BOOL fReturn = FALSE;
	BOOL fLogonSuccess = FALSE;
	DWORD dwSize = 0;
	__try
	{
		GetWindowTextA(GetDlgItem(_hwnd,IDC_PIN), _szPin, ARRAYSIZE(_szPin));
		fReturn = TRUE;
		EndDialog(_hwnd, IDOK);
	}
	__finally
	{
		
	}
	return fReturn;
}

VOID PINDialog::GetPIN(__out_ecount(MAX_PIN_SIZE) PSTR szPin)
{
	strcpy_s(szPin, MAX_PIN_SIZE, _szPin);
}