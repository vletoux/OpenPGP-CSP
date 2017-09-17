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



#pragma once
#pragma comment(lib,"CryptUI")
#pragma comment(lib,"Crypt32")
#pragma comment(lib,"Winscard")
#pragma comment(lib,"Scarddlg")
#pragma comment(lib,"certidl")

#include <Windows.h>
#include <commctrl.h> 
#include <tchar.h>
#include <Cryptuiapi.h>

#include "CertificateUtilities.h"
#include "Tracing.h"
#include "resource.h"
#include "RegistrationOfTag.h"

extern WCHAR szReader[256];
extern DWORD dwReaderSize;
extern WCHAR szCard[256];
extern DWORD dwCardSize;
extern WCHAR szProvider[256];
extern HINSTANCE hInst;
extern BOOL fWindowsXPCompatible;


VOID ImportACertificate(HWND hWnd);
HRESULT Enroll(HWND hWnd);

void MessageBoxWin32Ex2(DWORD status, HWND hWnd, LPCSTR szFile, DWORD dwLine);
#define MessageBoxWin32(status) MessageBoxWin32Ex2 (status, NULL, __FILE__,__LINE__);
#define MessageBoxWin32Ex(status, hwnd ) MessageBoxWin32Ex2 (status, hwnd, __FILE__,__LINE__);