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


#include <list>

#define MAX_CONTAINER_NAME 100
#define MAX_PIN_SIZE 256
#define RTL_ENCRYPT_MEMORY_SIZE 8
#define MAX_READER_NAME 256
#define MASTERKEY_SIZE 20



class ContainerKeyHandle
{
public:
	HCRYPTKEY m_hKey;
	DWORD m_dwKeySpec;
	ContainerKeyHandle(HCRYPTKEY hKey, DWORD dwKeySpec)
	{
		m_hKey = hKey;
		m_dwKeySpec = dwKeySpec;
	}
	static ContainerKeyHandle* Create(HCRYPTKEY hKey, DWORD dwKeySpec)
	{
		return new ContainerKeyHandle(hKey, dwKeySpec);
	}
};

class ContainerHashHandle
{
public:
	HCRYPTHASH m_hHash;
	ContainerKeyHandle* m_hKeyHandle;
	ALG_ID  m_Algid;
	ContainerHashHandle(HCRYPTHASH hHash, ContainerKeyHandle* hKeyHandle, ALG_ID  Algid)
	{
		m_hHash = hHash;
		m_hKeyHandle = hKeyHandle;
		m_Algid = Algid;
	}
	static ContainerHashHandle* Create(HCRYPTHASH hHash, ContainerKeyHandle* hKeyHandle, ALG_ID  Algid)
	{
		return new ContainerHashHandle(hHash, hKeyHandle, Algid);
	}
};

// This is the class which holds the private key information
class  CspContainer : BaseContainer {

public :
                ~CspContainer();
                HCRYPTPROV   getProviderHandle()  const ;

				_Ret_maybenull_ static CspContainer* Create(PCSTR szReader, PCSTR szContainer, BOOL allowUI, BOOL  bMachineKeySet);
				_Ret_maybenull_ static CspContainer* Load(PCSTR szReader, PCSTR szContainer, BOOL allowUI, BOOL  bMachineKeySet, BOOL fVerifyContext);
				static BOOL Remove( PCSTR szReader, PCSTR szContainer, BOOL allowUI, BOOL  bMachineKeySet);

				_Ret_maybenull_ static CspContainer* GetContainerFromHandle(HCRYPTPROV handle);
				static BOOL Clean();
				

				BOOL Unload();
				_Success_(return) BOOL GetProvParam(
						_In_    DWORD dwParam,
						_Out_writes_bytes_to_opt_(*pdwDataLen, *pdwDataLen) LPBYTE  pbData,
						_Inout_  DWORD *pdwDataLen,
						_In_    DWORD  dwFlags);
				BOOL SetProvParam(
						__in    DWORD dwParam,
						__in     CONST  BYTE *pbData,
						__in    DWORD  dwFlags);
				BOOL GenRandom(
					_In_                    DWORD   dwLen,
					_Inout_updates_bytes_(dwLen)   BYTE    *pbBuffer);
				BOOL CreateHash(
					__in     ALG_ID  Algid,
					__in     HCRYPTKEY   hKey,
					__in     DWORD  dwFlags,
					__out     HCRYPTHASH  *phHash);
				BOOL HashData(
					__in     HCRYPTHASH  hHash,
					_In_reads_bytes_(dwDataLen)     CONST  BYTE *pbData,
					__in    DWORD dwDataLen,
					__in    DWORD  dwFlags);
				BOOL HashSessionKey(
					__in     HCRYPTHASH  hHash,
					__in     HCRYPTKEY   hKey,
					__in    DWORD  dwFlags);
				BOOL SignHash(
					__in     HCRYPTHASH  hHash,
					__in    DWORD  dwKeySpec,
					_In_opt_    LPCTSTR szDescription,
					__in    DWORD  dwFlags,
					_Out_writes_bytes_to_opt_(*pdwSigLen, *pdwSigLen) BYTE *pbSignature,
					_Inout_  DWORD       *pdwSigLen);
				BOOL DestroyHash(
			        __in     HCRYPTHASH  hHash);
				BOOL SetHashParam(
					__in     HCRYPTHASH  hHash,
					__in    DWORD dwParam,
					__in     CONST  BYTE *pbData,
					__in    DWORD  dwFlags);
				BOOL GetHashParam(
					__in     HCRYPTHASH  hHash,
					__in    DWORD dwParam,
					_Out_writes_bytes_to_opt_(*pdwDataLen, *pdwDataLen)  LPBYTE  pbData,
					__inout  LPDWORD pdwDataLen,
					__in    DWORD  dwFlags);

				BOOL GenKey(
					__in     ALG_ID  Algid,
					__in    DWORD  dwFlags,
					__out   HCRYPTKEY  *phKey);
				BOOL DeriveKey(
					__in     ALG_ID  Algid,
					__in     HCRYPTHASH  hHash,
					__in    DWORD  dwFlags,
					__out   HCRYPTKEY  *phKey);
				BOOL DestroyKey(
					__in     HCRYPTKEY   hKey);
				BOOL SetKeyParam(
					__in     HCRYPTKEY   hKey,
					__in    DWORD dwParam,
					__in     CONST  BYTE *pbData,
					__in    DWORD  dwFlags);
				_Success_(return) BOOL GetKeyParam(
					__in     HCRYPTKEY   hKey,
					__in    DWORD dwParam,
					_Out_writes_bytes_to_opt_(*pdwDataLen, *pdwDataLen) LPBYTE  pbData,
					__inout  LPDWORD pdwDataLen,
					__in    DWORD  dwFlags);
				BOOL ExportKey(
					__in     HCRYPTKEY   hKey,
					__in     HCRYPTKEY  hPubKey,
					__in    DWORD dwBlobType,
					__in    DWORD  dwFlags,
					_Out_writes_bytes_to_opt_(*pdwDataLen, *pdwDataLen)  LPBYTE  pbData,
					__inout  LPDWORD pdwDataLen);
				BOOL ImportKey(
					__in     CONST  BYTE *pbData,
					__in    DWORD cbDataLen,
					__in     HCRYPTKEY  hPubKey,
					__in    DWORD  dwFlags,
					__out   HCRYPTKEY  *phKey);
				BOOL Encrypt(
					__in     HCRYPTKEY   hKey,
					__in     HCRYPTHASH  hHash,
					__in     BOOL  fFinal,
					__in    DWORD  dwFlags,
					__inout  LPBYTE  pbData,
					__inout  LPDWORD pcbDataLen,
					__in    DWORD cbBufLen);
				BOOL Decrypt(
					__in     HCRYPTKEY   hKey,
					__in     HCRYPTHASH  hHash,
					__in     BOOL  fFinal,
					__in    DWORD  dwFlags,
					__inout  LPBYTE  pbData,
					__inout  LPDWORD pcbDataLen);
				BOOL VerifySignature(
					__in     HCRYPTHASH  hHash,
					__in     CONST  BYTE *pbSignature,
					__in    DWORD cbSigLen,
					__in     HCRYPTKEY  hPubKey,
					__in    LPCWSTR szDescription,
					__in    DWORD  dwFlags);
				BOOL GetUserKey(
					__in    DWORD  dwKeySpec,
					__out   HCRYPTKEY  *phUserKey);

private :

                // parameters
                CHAR m_szContainerName[MAX_CONTAINER_NAME];
				CHAR m_szReader[MAX_READER_NAME];
				HCRYPTPROV m_hProv;
				DWORD m_dwKeySpec;
				HCRYPTKEY m_hKey;
				DWORD m_dwPreviousEnumeratedContainer;

				std::list<ContainerHashHandle*> m_hashHandles;
				std::list<ContainerKeyHandle*> m_keyHandles;
				BOOL CreateContainer(__in_opt PCSTR szReader, __in PCSTR szContainer, __in BOOL allowUI);
				BOOL LoadContainer(__in_opt PCSTR szReader, __in_opt PCSTR szContainer, __in BOOL allowUI, __in BOOL fVerifyContext);
				BOOL RemoveContainer(__in_opt PCSTR szReader, __in_opt PCSTR szContainer, __in BOOL allowUI);
				BOOL LocateContainer(__in_opt PCSTR szContainer);

				_Ret_maybenull_ HCRYPTHASH GetHash(__in HCRYPTHASH hHash);
				_Ret_maybenull_ HCRYPTKEY GetKey(__in HCRYPTKEY hKey, __out_opt PDWORD pdwKeySpec);
				
				BOOL AskForSmartCardReader();
				
				BOOL EnumerateContainer(_Out_writes_bytes_to_opt_(*pdwDataLen, *pdwDataLen) PSTR szContainer, __inout PDWORD pdwDataLen, DWORD dwFlags);

				HWND GetParentHwnd();
				BOOL GetKeyFromReader();
				

				static BOOL CleanProviders();
private :
                CspContainer();
				static CspContainer* Allocate() { return new CspContainer();}
};

