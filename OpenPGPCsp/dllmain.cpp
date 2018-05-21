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

HINSTANCE g_hInst;

BOOL WINAPI DllMain(
    HINSTANCE hinstDll,
    DWORD dwReason,
    LPVOID pReserved
    )
{
    UNREFERENCED_PARAMETER(pReserved);
	UNREFERENCED_PARAMETER(hinstDll);
	TCHAR szPath[MAX_PATH];
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
		TracingRegister();
#ifdef _DEBUG
		_CrtSetDbgFlag(_CRTDBG_CHECK_ALWAYS_DF);
#endif
		Trace(TRACE_LEVEL_VERBOSE, L"attached %p", hinstDll);
		if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath)))
		{
			Trace(TRACE_LEVEL_VERBOSE, L"process is %s", szPath);
		}
		g_hInst = hinstDll;
        break;
    case DLL_PROCESS_DETACH:
		Trace(TRACE_LEVEL_VERBOSE, L"detaching ...%p", hinstDll);
		CspContainer::Clean();
		TracingUnRegister();
		break;
    }
    return TRUE;
}
