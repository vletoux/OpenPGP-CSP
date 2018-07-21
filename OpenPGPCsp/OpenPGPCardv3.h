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

class Card;
class OpenPGPCardv2;

class OpenPGPCardv3: public OpenPGPCardv2
{
public:
	
	static Card* CreateContext(SCARDCONTEXT hContext, SCARDHANDLE hScard, BOOL fAllowUI, OPENPGP_AID Aid);
	//virtual BOOL LocateContainer(__in_opt PCSTR szContainer, __out PDWORD pdwId);
	//virtual BOOL GetContainerName(__in DWORD dwKeyId, __out_ecount(MAX_CONTAINER_NAME) PSTR szContainer);
	//virtual BOOL GetPublicKey(__in DWORD dwKeyId, _Out_writes_bytes_to_opt_(*pdwSize, *pdwSize) PBYTE* ppbPubKey, __out PDWORD pdwSize);
	//virtual DWORD GetMaxContainer() {return OPENPGPKEYMAX;}
	virtual BOOL GetCertificate(__in DWORD dwKeyId, _Out_writes_bytes_to_opt_(*pdwSize, *pdwSize) PBYTE pbData, __out PDWORD pdwSize);
	virtual BOOL SignData(__in DWORD dwKeyId,__in PCWSTR szAlgorithm, __in PBYTE pbHashValue, __in DWORD cbHashValue,
					_Out_writes_bytes_to_(*pdwSigLen, *pdwSigLen) BYTE *pbSignature,
					_Inout_  DWORD *pdwSigLen);
	virtual BOOL Decrypt(__in DWORD dwKeyId,
					 __in PBYTE pbEncryptedData, __in DWORD cbEncryptedData,
					_Out_writes_bytes_to_(*pcbDecryptedData, *pcbDecryptedData) BYTE *pbDecryptedData,
					_Inout_  DWORD *pcbDecryptedData);
	//virtual BOOL GetPIN(__in DWORD dwKeyId, __in DWORD dwOperationId, __out PDWORD dwPinId);
	//virtual BOOL AuthenticatePIN(__in DWORD dwPinId,__in PSTR szPin, __out PDWORD pdwRemainingAttempt);
	virtual BOOL Deauthenticate(__in DWORD dwPinId);
	//virtual DWORD Reinit();
	//virtual BOOL GenerateKey(__in ALG_ID Algid, __in DWORD dwKeyId, __in DWORD dwBitLen);
	virtual BOOL GetKeyIdForNewKey(__in ALG_ID Algid, __in_opt HWND hWndParent, __out PDWORD dwKeyId);
	//virtual BOOL AskForPin(__in HWND hWndParent, __in PWSTR szPinPROMPT, __in DWORD dwPinId, __out_ecount(MAX_PIN_SIZE) PSTR szPin);
	virtual BOOL SaveCertificate(__in DWORD dwKey, __in_bcount(dwSize) PBYTE pbData, __in DWORD dwSize, __in DWORD dwKeySpec);
private:
	static OpenPGPCardv3* AllocateCard() { return new OpenPGPCardv3();}
protected:
	BOOL SelectCertSubDO(__in DWORD dwKeyId);
	virtual DWORD CheckCapabilities(__in_bcount(dwCardCapabilitiesSize) PBYTE pbCardCapabilities, DWORD dwCardCapabilitiesSize,
							__in_bcount(dwExtendedCapabilitiesSize) PBYTE pbExtendedCapabilities, DWORD dwExtendedCapabilitiesSize);
	virtual BOOL IsKeyCompatibleWithAlgId(__in DWORD dwKeyId, __in ALG_ID algId);
	virtual ALG_ID GetAlgIdFromKeyId(__in DWORD dwKeyId);
	BOOL ManageSecurityEnvironment(__in DWORD dwKeyId, __in DWORD dwOperationId);
	BOOL m_fSupportMse;
};