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

class SelectOpenPGPv3KeyDialog {
public:
    SelectOpenPGPv3KeyDialog(__in ALG_ID Algid, BOOL fSupportMse);
	~SelectOpenPGPv3KeyDialog();
    INT_PTR Show();

	virtual INT_PTR DialogProc(UINT msg, WPARAM wp, LPARAM lp);
	DWORD m_dwKeyId;
protected:
    static INT_PTR CALLBACK _dialogProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
	VOID InitDialog();
    void CenterWindow();
	HWND  _hwnd;
	ALG_ID m_Algid;
	BOOL m_fSupportMse;
};
