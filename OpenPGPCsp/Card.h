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


#define PIN_OPERATION_SIGN 0
#define PIN_OPERATION_DECRYPT 1
#define PIN_OPERATION_CREATE 2
#define PIN_OPERATION_DELETE 3
#define PIN_OPERATION_SAVE_CERT 4
#define PIN_OPERATION_SET_KEYEXCHANGE_PIN 5
#define PIN_OPERATION_SET_SIGNATURE_PIN 6
#define PIN_OPERATION_SET_ADMIN_PIN 7

#define INVALID_CONTAINER_ID (DWORD)(-1)

class Card
{
	public:
		SCARDHANDLE hScard;
		SCARDCONTEXT hContext;
		virtual BOOL LocateContainer(__in_opt PCSTR szContainer, __out PDWORD pdwId) = 0;
		virtual BOOL GetKeySpec(__in DWORD dwKeyId, __out PDWORD pdwKeySpec) = 0;
		virtual BOOL GetPublicKey(__in DWORD dwKeyId, _Out_writes_bytes_to_opt_(*pdwSize, *pdwSize) PBYTE* ppbPubKey, __out PDWORD pdwSize) = 0;
		virtual BOOL GetContainerName(__in DWORD dwKeyId, __out_ecount(MAX_CONTAINER_NAME) PSTR szContainer) = 0;
		virtual DWORD GetMaxContainer() = 0;
		virtual BOOL GetCertificate(__in DWORD dwKeyId, _Out_writes_bytes_to_opt_(*pdwSize, *pdwSize) PBYTE pbData, __out PDWORD pdwSize) = 0;
		virtual BOOL SignHash(__in DWORD dwKeyId, __in     HCRYPTHASH  hHash, __in    DWORD  dwFlags,
					_Out_writes_bytes_to_(*pdwSigLen, *pdwSigLen) BYTE *pbSignature,
					_Inout_  DWORD       *pdwSigLen) = 0;
		virtual BOOL Decrypt(__in DWORD dwKeyId,
					_Inout_updates_bytes_to_(*pdwDataLen, *pdwDataLen) BYTE *pbData,
					 _Inout_ DWORD       *pdwDataLen) = 0;
		// called out of a transaction
		virtual BOOL GetPIN(__in DWORD dwKeyId, __in DWORD dwOperationId, __out PDWORD dwPinId) = 0;
		virtual BOOL AuthenticatePIN(__in DWORD dwPinId,__in PSTR szPin, __out PDWORD pdwRemainingAttempt) = 0;
		virtual BOOL Deauthenticate(__in DWORD dwPinId) = 0;
		virtual DWORD Card::Reinit() = 0;
		virtual BOOL GenerateKey(__in ALG_ID Algid, __in DWORD dwKeyId, __in DWORD dwBitLen) = 0;
		// called out of a transaction
		virtual BOOL GetKeyIdForNewKey(__in ALG_ID Algid, __out PDWORD dwKeyId) = 0;
		virtual BOOL AskForPin(__in PWSTR szPinPROMPT, __in DWORD dwPinId, __out_ecount(MAX_PIN_SIZE) PSTR szPin) = 0;
		virtual BOOL SaveCertificate(__in DWORD dwKey, __in_bcount(dwSize) PBYTE pbData, __in DWORD dwSize, __in DWORD dwKeySpec) = 0;
		virtual BOOL RemoveKey(__in DWORD dwKey) = 0;
		virtual BOOL SaveKey(__in DWORD dwKey, __in ALG_ID Algid, __in_bcount(dwKeySize) PBYTE pBlob, __in DWORD dwKeySize) = 0;
		virtual BOOL SetContainerName(PSTR szContainer, DWORD dwKeyId) = 0;
		virtual BOOL GetKeyLength(__out PDWORD pdwDefaultLen, __out PDWORD pdwMinLen, __out PDWORD pdwMaxLen) = 0;
	protected:
		Card()
		{
			hScard = 0;
			hContext = 0;
		}
		static DWORD Card::DecodeReturnCode(BYTE SW1, BYTE SW2);
		BOOL static MatchATR(SCARDHANDLE hSCard, SCARD_ATRMASK AtrToCheck);
		DWORD Card::Reconnect();
		DWORD Card::SendCommand(__in PBYTE pbCmd, __in DWORD dwCmdSize);
		DWORD Card::GetData( 
					__in PBYTE pbCmd, __in DWORD dwCmdSize,
					__out PBYTE* pbResponse, __out PDWORD pdwResponseSize);
		

};