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


SelectOpenPGPv3KeyDialog::SelectOpenPGPv3KeyDialog(__in ALG_ID Algid, BOOL fSupportMse)
{
	m_Algid  = Algid;
	m_fSupportMse = fSupportMse;
}

SelectOpenPGPv3KeyDialog::~SelectOpenPGPv3KeyDialog()
{

}

INT_PTR SelectOpenPGPv3KeyDialog::Show()
{
	HWND hWndParent = NULL;
	GetHWND(&hWndParent);
	return DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_SELECTOPENPGPV3KEY), hWndParent, _dialogProc, (LPARAM)this);
}

INT_PTR CALLBACK SelectOpenPGPv3KeyDialog::_dialogProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (WM_INITDIALOG == msg) {
        ((SelectOpenPGPv3KeyDialog*)lp)->_hwnd = hwnd;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, lp);
    }
	SelectOpenPGPv3KeyDialog* dlg = (SelectOpenPGPv3KeyDialog*)GetWindowLongPtr(hwnd, GWLP_USERDATA);

    // WM_SETFONT is coming in before WM_INITDIALOG
    // in which case GWLP_USERDATA won't be set yet.
	if (dlg) {
		return dlg->DialogProc(msg, wp, lp);
	}
    return FALSE;
}


INT_PTR SelectOpenPGPv3KeyDialog::DialogProc(UINT msg, WPARAM wParam, LPARAM lParam)
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
				case IDC_SIGNATURE:
					m_dwKeyId = OPENPGP_KEY_SIGNATURE;
					EndDialog(_hwnd, IDOK);
					break;
				case IDC_ENCRYPTION:
					m_dwKeyId = OPENPGP_KEY_CONFIDENTIALITY;
					EndDialog(_hwnd, IDOK);
					break;
				case IDC_AUTHENTICATION:
					m_dwKeyId = OPENPGP_KEY_AUTHENTICATION;
					EndDialog(_hwnd, IDOK);
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

void SelectOpenPGPv3KeyDialog::CenterWindow() 
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


VOID SelectOpenPGPv3KeyDialog::InitDialog()
{
	CenterWindow();
	if (!m_fSupportMse)
	{
		if (m_Algid == CALG_RSA_KEYX)
		{
			EnableWindow(GetDlgItem(_hwnd, IDC_AUTHENTICATION),FALSE);
			EnableWindow(GetDlgItem(_hwnd, IDC_SIGNATURE),FALSE);
		}
		else if (m_Algid == CALG_RSA_SIGN)
		{
			EnableWindow(GetDlgItem(_hwnd, IDC_ENCRYPTION),FALSE);
		}
		ShowWindow(GetDlgItem(_hwnd, IDC_MSE_NOTE),SW_SHOW);
	}
	else
	{
		ShowWindow(GetDlgItem(_hwnd, IDC_MSE_ENABLED),SW_SHOW);
		if (m_Algid == CALG_RSA_KEYX)
		{
			EnableWindow(GetDlgItem(_hwnd, IDC_SIGNATURE),FALSE);
		}
	}
}
