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

class PINDialog {
public:
    PINDialog(PWSTR szPinPrompt, DWORD dwResourceId);
	~PINDialog();
    INT_PTR Show(HWND hWndParent);
	VOID GetPIN(__out_ecount(MAX_PIN_SIZE) PSTR szPin);

	virtual INT_PTR DialogProc(UINT msg, WPARAM wp, LPARAM lp);
	
protected:
	PINDialog();
    static INT_PTR CALLBACK _dialogProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
	BOOL Enter();
	VOID InitDialog();
    void CenterWindow();
	HWND  _hwnd;
	CHAR _szPin[MAX_PIN_SIZE];
	PWSTR _szPinPrompt;
	DWORD _dwResourceId;
};
