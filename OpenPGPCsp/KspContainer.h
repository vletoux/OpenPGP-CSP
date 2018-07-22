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


class KspContainer;

class  KspKey : BaseContainer {
public:
	static KspKey* LoadKey(KspContainer* kspcontainer, __in PCWSTR szReader, __in PCWSTR szContainer);
	static KspKey* CreateNonPersitedKey(KspContainer* kspcontainer, 
									 __in_opt LPCWSTR szKeyName, 
									 __in    DWORD   dwLegacyKeySpec,
									__in_opt BCRYPT_ALG_HANDLE hProv,
									__in_opt BCRYPT_KEY_HANDLE hKey);

	_Success_(return) BOOL GetKeyProperty(
		__in    LPCWSTR pszProperty,
		__out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
		__in    DWORD   cbOutput,
		__out   DWORD * pcbResult,
		__in    DWORD   dwFlags);
	_Success_(return) BOOL SetKeyProperty(
		__in    LPCWSTR pszProperty,
		__in_bcount(cbInput) PBYTE pbInput,
		__in    DWORD   cbInput,
		__in    DWORD   dwFlags);
	_Success_(return) BOOL ExportKey(
		__in    LPCWSTR pszBlobType,
		__in_opt NCryptBufferDesc *pParameterList,
		__out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
		__in    DWORD   cbOutput,
		__out   DWORD * pcbResult,
		__in    DWORD   dwFlags);
	_Success_(return) BOOL Encrypt(
		__in_bcount(cbInput) PBYTE pbInput,
		__in    DWORD   cbInput,
		__in    VOID *pPaddingInfo,
		__out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
		__in    DWORD   cbOutput,
		__out   DWORD * pcbResult,
		__in    DWORD   dwFlags);
	_Success_(return) BOOL Decrypt(
		__in_bcount(cbInput) PBYTE pbInput,
		__in    DWORD   cbInput,
		__in    VOID *pPaddingInfo,
		__out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
		__in    DWORD   cbOutput,
		__out   DWORD * pcbResult,
		__in    DWORD   dwFlags);
	_Success_(return) BOOL SignHash(
		__in_opt    VOID  *pPaddingInfo,
		__in_bcount(cbHashValue) PBYTE pbHashValue,
		__in    DWORD   cbHashValue,
		__out_bcount_part_opt(cbSignature, *pcbResult) PBYTE pbSignature,
		__in    DWORD   cbSignature,
		__out   DWORD * pcbResult,
		__in    DWORD   dwFlags);
	_Success_(return) BOOL VerifySignature(
		__in_opt    VOID  *pPaddingInfo,
		__in_bcount(cbHashValue) PBYTE pbHashValue,
		__in    DWORD   cbHashValue,
		__in_bcount(cbSignature) PBYTE pbSignature,
		__in    DWORD   cbSignature,
		__in    DWORD   dwFlags);
	_Success_(return) BOOL DeleteKey(DWORD dwFlags);
	_Success_(return) BOOL FinalizeKey(DWORD dwFlags);
	KspKey::~KspKey();
private:
	KspKey(KspContainer* kspcontainer);
	BOOL LoadPublicKey();
	PCWSTR m_szKeyName;
	BCRYPT_ALG_HANDLE m_hAlgProv;
	BCRYPT_KEY_HANDLE m_key;
	BOOL m_isFinalized;
	KspContainer* m_kspcontainer;
	static KspKey* Allocate(KspContainer* kspcontainer) { return new KspKey(kspcontainer);}
	WCHAR m_szReader[MAX_READER_NAME];
	DWORD m_dwLegacyKeySpec;
	DWORD m_dwBitLength; // used when creating new keys
};

#define MAX_ENUM_SUPPORTED 30
typedef struct _KspEnumNCryptKeyName
{
	DWORD dwNumberOfNCryptKeyName;
	DWORD dwCurrentNCryptKeyName;
	NCryptKeyName names[MAX_ENUM_SUPPORTED];
	WCHAR szContainerName[MAX_ENUM_SUPPORTED][MAX_CONTAINER_NAME];
} KspEnumNCryptKeyName;

class  KspContainer : BaseContainer {

public :
	~KspContainer();
	NCRYPT_PROV_HANDLE   getProviderHandle()  { return (NCRYPT_PROV_HANDLE) this;}
	_Ret_maybenull_ static KspContainer* GetContainerFromHandle(NCRYPT_PROV_HANDLE handle);
	_Ret_maybenull_ static KspContainer* Create();
	BOOL Unload();
	static BOOL Clean();

	KspKey* OpenKey(__in PCWSTR pszKeyName,__in_opt DWORD  dwLegacyKeySpec, BOOL fSilent);
	KspKey* CreateNonPersistedKey(__in_opt LPCWSTR pszKeyName,
			__in    DWORD   dwLegacyKeySpec,
			__in    DWORD   dwFlags,
			__in_opt BCRYPT_ALG_HANDLE hProv,
			__in_opt BCRYPT_KEY_HANDLE hKey);
	_Success_(return) BOOL GetProviderProperty(
		__in    LPCWSTR pszProperty,
		__out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
		__in    DWORD   cbOutput,
		__out   DWORD * pcbResult,
		__in    DWORD   dwFlags);
	_Success_(return) BOOL SetProviderProperty(__in    LPCWSTR pszProperty,
		__in_bcount(cbInput) PBYTE pbInput,
		__in    DWORD   cbInput,
		__in    DWORD   dwFlags);
	static KspKey* GetKeyFromHandle(__in    NCRYPT_PROV_HANDLE hProvider, __in    NCRYPT_KEY_HANDLE hKey);
	_Success_(return) BOOL FreeKey(__in    NCRYPT_KEY_HANDLE hKey);

	_Success_(return) BOOL  IsAlgSupported( __in    LPCWSTR pszAlgId,   __in    DWORD   dwFlags);
	_Success_(return) BOOL EnumAlgorithms(
		__in    DWORD   dwAlgOperations, // this is the crypto operations that are to be enumerated
		__out   DWORD * pdwAlgCount,
		__deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
		__in    DWORD   dwFlags);
	_Success_(return) BOOL EnumKeys(
		__in_opt LPCWSTR pszScope,
		__deref_out NCryptKeyName **ppKeyName,
		__inout PVOID * ppEnumState,
		__in    DWORD   dwFlags);
	KspKey* ImportKey(
		__in_opt NCRYPT_KEY_HANDLE hImportKey,
		__in    LPCWSTR pszBlobType,
		__in_opt NCryptBufferDesc *pParameterList,
		__in_bcount(cbData) PBYTE pbData,
		__in    DWORD   cbData,
		__in    DWORD   dwFlags);
	HWND m_hWnd;

private :
	KspContainer();
	static KspContainer* Allocate() { return new KspContainer();}
	static BOOL CleanProviders();
	std::list<KspKey*> m_keyHandles;
	KspKey* LocateKey(__in    NCRYPT_KEY_HANDLE hKey);
	KspEnumNCryptKeyName* BuildEnumData(__in_opt LPCWSTR pszScope);
	BOOL GetUserStoreWithAllCard(__out HCERTSTORE* phStore);
	GUID m_LastGUIDSeen;
};