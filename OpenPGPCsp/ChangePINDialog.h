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

class ChangePINDialog {
public:
    ChangePINDialog();
	~ChangePINDialog();
    INT_PTR Show();
	VOID GetBeforePIN(__out_ecount(MAX_PIN_SIZE) PSTR szPin);
	VOID GetAfterPIN(__out_ecount(MAX_PIN_SIZE) PSTR szPin);

	virtual INT_PTR DialogProc(UINT msg, WPARAM wp, LPARAM lp);
	
protected:
    static INT_PTR CALLBACK _dialogProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
	BOOL Enter();
	VOID InitDialog();
    void CenterWindow();
	HWND  _hwnd;
	CHAR _szBeforePin[MAX_PIN_SIZE];
	CHAR _szAfterPin[MAX_PIN_SIZE];
};
