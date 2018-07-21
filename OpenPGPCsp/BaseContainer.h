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

#define KEY_SIZE 20

BOOL ExtractReaderAndContainerFromGeneralNameA(__in PCSTR szSubmittedContainer, __in PSTR szBuffer, __in DWORD dwBufferSize,
											  __out PCSTR *pszReader, __out PCSTR *pszContainer);
BOOL ExtractReaderAndContainerFromGeneralNameW(__in PCWSTR szSubmittedContainer, __in PWSTR szBuffer, __in DWORD dwBufferSize,
											  __out PCWSTR *pszReader, __out PCWSTR *pszContainer);
PWSTR DuplicateUnicodeString(PWSTR source);

class  BaseContainer  {

public:
	// PIN operations
	BOOL Authenticate(__in DWORD dwPinId);
	BOOL ChangePin();
	BOOL SetPin(__in DWORD dwPinType, PSTR szPin);
	BOOL AskPinToUserIfNeeded(__in HWND hWndParent, __in DWORD dwPinId);
	BOOL RemovePinInCache(__in DWORD dwPinId);
	BOOL GetPinInCache(__in DWORD dwPinId, __out_ecount(MAX_PIN_SIZE) PSTR szPin, __out PFILETIME Timestamp);
	BOOL SetPinInCache(__in DWORD dwPinId, __in_ecount(MAX_PIN_SIZE) PSTR szPin);
	BOOL GetPIN(__in DWORD dwOperationId, __out PDWORD pdwPinId);
	static BOOL CleanPinCache();

	// card operations
	BOOL StartTransaction();
	BOOL EndTransaction(DWORD dwPinId, BOOL fAuthenticated);
	Card* CreateContext();

	// store operations
	BOOL GetUserStore(__in PTSTR szProviderName, __out HCERTSTORE* phStore);
	BOOL PopulateUserStoreFromContainerName(__in HCERTSTORE hStore, __in PTSTR szProviderName, __in PSTR szContainer, __in DWORD dwKeySpec, __in PBYTE pbData, __in DWORD dwSize);
	BOOL LoadCertificate(_Out_writes_bytes_to_opt_(*pdwSize, *pdwSize) PBYTE pbData, __inout PDWORD pdwSize);
	BOOL SaveCertificate(__in_bcount(dwSize) PBYTE pbData, __in  DWORD dwSize, __in DWORD dwKeySpec);

	// cryto operations
	BOOL SignData(__in PCWSTR szAlgorithm, __in PBYTE pbHashValue, __in DWORD cbHashValue,
					_Out_writes_bytes_to_(*pdwSigLen, *pdwSigLen) BYTE *pbSignature,
					_Inout_  DWORD *pdwSigLen);

protected:
	BYTE m_Key[KEY_SIZE];
	BOOL m_AllowUI;
	BOOL m_VerifyContext;
	Card* m_Card;
	PWSTR m_szPinPROMPT;
	PWSTR m_szUIPROMPT;
	DWORD m_dwCardContainerId;
	
	
	SCARDCONTEXT m_hContext;
	SCARDHANDLE m_hCard;
};