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

// important:
// this is a program designed to be modified at a specific test case
// uncommented / move the test instruction to run the test case

#include "stdafx.h"

VOID VerifyKeyProp(PCCERT_CONTEXT pCertContext)
{
	BYTE temp[4096];
	DWORD dwSize2 = sizeof(temp);
	CRYPT_KEY_PROV_INFO * temp2 = (CRYPT_KEY_PROV_INFO*) temp;
	if (CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, temp, &dwSize2))
	{
		printf("ok");
	}
	else
	{
		printf("not ok");
	}
}

BOOL testKeyImport(PCCERT_CONTEXT pCertContext)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	DWORD dwKeySpec;
	BOOL freehProv;
	HCRYPTKEY hKey = NULL;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY h3DesKey = NULL;
	HCRYPTKEY hPubKey = NULL, hKeyImported = NULL;
	BYTE pbBuffer[10000];
	DWORD dwSize = 0;
	HCRYPTPROV hverifyProv = NULL;
	BYTE testData[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
	__try
	{
		if (!pCertContext)
		{
			__leave;
		}
		if (!CryptAcquireContext(&hverifyProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			dwError = GetLastError();
			printf("error CryptAcquireContext 0x%08X\r\n", dwError);
			__leave;
		}
		if (!CryptAcquireCertificatePrivateKey(pCertContext, 0, NULL, &hProv, &dwKeySpec, &freehProv))
		{
			dwError = GetLastError();
			printf("error CryptAcquireCertificatePrivateKey 0x%08X\r\n", dwError);
			__leave;
		}
		if (!CryptGetUserKey(hProv, dwKeySpec, &hKey))
		{
			dwError = GetLastError();
			printf("error CryptGetUserKey 0x%08X\r\n", dwError);
			__leave;
		}
		if (!CryptGenKey(hverifyProv, CALG_3DES, CRYPT_EXPORTABLE, &h3DesKey))
		{
			dwError = GetLastError();
			printf("error CryptGenKey 0x%08X\r\n", dwError);
			__leave;
		}
		if (!CryptImportPublicKeyInfo(hverifyProv, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &(pCertContext->pCertInfo->SubjectPublicKeyInfo), &hPubKey))
		{
			dwError = GetLastError();
			printf("error CryptImportPublicKeyInfo 0x%08X\r\n", dwError);
			__leave;
		}
		dwSize = 0;
		if (!CryptExportKey(h3DesKey, hPubKey, SIMPLEBLOB, 0, NULL, &dwSize))
		{
			dwError = GetLastError();
			printf("error CryptImportPublicKeyInfo 0x%08X\r\n", dwError);
			__leave;
		}
		if (!CryptExportKey(h3DesKey, hPubKey, SIMPLEBLOB, 0, pbBuffer, &dwSize))
		{
			dwError = GetLastError();
			printf("error CryptImportPublicKeyInfo 0x%08X\r\n", dwError);
			__leave;
		}
		if (!CryptImportKey(hProv, pbBuffer, dwSize, hKey, 0, &hKeyImported))
		{
			dwError = GetLastError();
			printf("error CryptImportPublicKeyInfo 0x%08X\r\n", dwError);
			__leave;
		}
		memcpy(pbBuffer, testData, sizeof(testData));
		dwSize = sizeof(testData);
		if (!CryptEncrypt(h3DesKey, NULL, TRUE, 0, pbBuffer, &dwSize, sizeof(pbBuffer)))
		{
			dwError = GetLastError();
			printf("error CryptImportPublicKeyInfo 0x%08X\r\n", dwError);
			__leave;
		}
		if (!CryptDecrypt(hKeyImported, NULL, TRUE, 0, pbBuffer, &dwSize))
		{
			dwError = GetLastError();
			printf("error CryptImportPublicKeyInfo 0x%08X\r\n", dwError);
			__leave;
		}
		if (dwSize != sizeof(testData) || memcmp(testData, pbBuffer, dwSize) != 0)
		{
			dwError = NTE_BAD_DATA;
			printf("error CryptDecrypt invalid\r\n");
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hKeyImported)
			CryptDestroyKey(hKeyImported);
		if (hPubKey)
			CryptDestroyKey(hPubKey);
		if (h3DesKey)
			CryptDestroyKey(h3DesKey);
		if (hKey)
			CryptDestroyKey(hKey);
		if (freehProv && hProv)
			CryptReleaseContext(hProv, 0);
	}
	return fReturn;
}

BOOL testEncryption(PCCERT_CONTEXT pCertContext, HCRYPTKEY hverifyKey)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	DWORD dwKeySpec;
	BOOL freehProv;
	HCRYPTKEY hKey = NULL;
	HCRYPTPROV hProv = NULL;
	HCRYPTHASH hHash = NULL;
	BYTE testData[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
	BYTE pbBuffer[10000];
	DWORD dwSize =sizeof(pbBuffer);
	__try
	{
		if (!pCertContext)
		{
			__leave;
		}
		if (!CryptAcquireCertificatePrivateKey(pCertContext, 0, NULL, &hProv, &dwKeySpec, &freehProv))
		{
			dwError = GetLastError();
			printf("error CryptAcquireCertificatePrivateKey 0x%08X\r\n", dwError);
			__leave;
		}
		if (!CryptGetUserKey(hProv, dwKeySpec, &hKey))
		{
			dwError = GetLastError();
			printf("error CryptGetUserKey 0x%08X\r\n", dwError);
			__leave;
		}
		memcpy(pbBuffer, testData, sizeof(testData));
		dwSize = sizeof(testData);
		if (!CryptEncrypt(hverifyKey, NULL, TRUE, 0, pbBuffer, &dwSize, sizeof(pbBuffer)))
		{
			dwError = GetLastError();
			printf("error CryptEncrypt 0x%08X\r\n", dwError);
			__leave;
		}
		if (!CryptDecrypt(hKey, NULL, TRUE, 0, pbBuffer, &dwSize))
		{
			dwError = GetLastError();
			printf("error CryptDecrypt 0x%08X\r\n", dwError);
			__leave;
		}
		if (dwSize != sizeof(testData) || memcmp(pbBuffer, testData, dwSize) != 0)
		{
			dwError = NTE_BAD_DATA;
			printf("error CryptDecrypt invalid\r\n");
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hHash)
			CryptDestroyHash(hHash);
		if (hKey)
			CryptDestroyKey(hKey);
		if (freehProv && hProv)
			CryptReleaseContext(hProv, 0);
		if( pbBuffer)
			free(pbBuffer);
	}
	return fReturn;
}
BOOL testSignature(PCCERT_CONTEXT pCertContext, ALG_ID alg)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	DWORD dwKeySpec;
	BOOL freehProv;
	HCRYPTKEY hKey = NULL;
	HCRYPTPROV hProv = NULL;
	PBYTE pbBuffer = NULL;
	HCRYPTHASH hHash = NULL;
	__try
	{
		if (!pCertContext)
		{
			__leave;
		}
		printf("Test hash %d\r\n", alg);
		if (!CryptAcquireCertificatePrivateKey(pCertContext, 0, NULL, &hProv, &dwKeySpec, &freehProv))
		{
			dwError = GetLastError();
			printf("error CryptAcquireCertificatePrivateKey 0x%08X\r\n", dwError);
			__leave;
		}
		if (!CryptGetUserKey(hProv, dwKeySpec, &hKey))
		{
			dwError = GetLastError();
			printf("error CryptGetUserKey 0x%08X\r\n", dwError);
			__leave;
		}
		if (!CryptCreateHash(hProv, CALG_SHA1, NULL,0,&hHash))
		{
			dwError = GetLastError();
			printf("error CryptCreateHash 0x%08X\r\n", dwError);
			__leave;
		}
		if (!CryptHashData(hHash, (PBYTE) "b,srklhg,nslgnsklgeglseklngeklsnglsenge", 20, 0))
		{
			dwError = GetLastError();
			printf("error CryptHashData 0x%08X\r\n", dwError);
			__leave;
		}
		DWORD dwsha1 = 20;
		BYTE sha1[20];
		if (!CryptGetHashParam(hHash, HP_HASHVAL, sha1, &dwsha1, 0))
		{
			dwError = GetLastError();
			printf("error CryptGetHashParam 0x%08X\r\n", dwError);
			__leave;
		}
		DWORD dwSize = 0;
		if (!CryptSignHash(hHash, dwKeySpec, NULL, 0, NULL, &dwSize))
		{
			dwError = GetLastError();
			printf("error CryptSignHash 0x%08X\r\n", dwError);
			__leave;
		}
		pbBuffer = (PBYTE) malloc(dwSize);
		if (!pbBuffer)
		{
			dwError = ERROR_OUTOFMEMORY;
			printf("error malloc 0x%08X\r\n", dwError);
			__leave;
		}
		if (!CryptSignHash(hHash, dwKeySpec, NULL, 0, pbBuffer, &dwSize))
		{
			dwError = GetLastError();
			printf("error CryptSignHash 0x%08X\r\n", dwError);
			__leave;
		}
		if (!CryptVerifySignature(hHash, pbBuffer, dwSize, hKey, NULL, 0))
		{
			dwError = GetLastError();
			printf("error CryptVerifySignature 0x%08X\r\n", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hHash)
			CryptDestroyHash(hHash);
		if (hKey)
			CryptDestroyKey(hKey);
		if (freehProv && hProv)
			CryptReleaseContext(hProv, 0);
		if( pbBuffer)
			free(pbBuffer);
	}
	return fReturn;
}

#define CHECK_RETURN_BOOL(function) if (!fReturn) { printf( #function " failed 0x%08X", GetLastError()); __leave;}

void TestCreateKey(PWSTR slot)
{
	HCRYPTPROV hProv = NULL;
	BOOL fReturn = FALSE;
	HCRYPTKEY hKey = NULL;
	PCCERT_CONTEXT pCertificateContext = NULL;
	BYTE buffer[256];
	CERT_NAME_BLOB SubjectIssuerBlob = {sizeof(buffer), buffer};
	__try
	{
		fReturn = CryptAcquireContext(&hProv, TEXT("test"), TEXT(CSPNAME), PROV_RSA_FULL, CRYPT_NEWKEYSET);
		CHECK_RETURN_BOOL(CryptAcquireContext);

		fReturn = CryptGenKey(hProv, AT_SIGNATURE, NULL, &hKey);
		CHECK_RETURN_BOOL(CryptGenKey);

		BYTE Data[4096];
		DWORD DataSize = 4096;
		if (CryptGetKeyParam(hKey,
				KP_CERTIFICATE,
				Data,
				&DataSize,
				0))
		{
			// certificate
				PCCERT_CONTEXT pCertContext= CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, Data, DataSize);
						
				BOOL fPropertiesChanged;
				CRYPTUI_VIEWCERTIFICATE_STRUCT certViewInfo;
				ZeroMemory(&certViewInfo,sizeof(certViewInfo));
				certViewInfo.dwSize = sizeof(CRYPTUI_VIEWCERTIFICATE_STRUCT);
				certViewInfo.hwndParent = NULL;
				certViewInfo.szTitle = TEXT("Info");
				certViewInfo.pCertContext = pCertContext;
				CryptUIDlgViewCertificate(&certViewInfo,&fPropertiesChanged);
				CertFreeCertificateContext(pCertContext);
		}
		fReturn = CertStrToName(X509_ASN_ENCODING,TEXT("CN=test"),CERT_X500_NAME_STR,NULL,(PBYTE)SubjectIssuerBlob.pbData,&SubjectIssuerBlob.cbData,NULL);
		CHECK_RETURN_BOOL(CertStrToName);

		pCertificateContext = CertCreateSelfSignCertificate(hProv,&SubjectIssuerBlob,
			0,NULL,NULL,NULL,NULL,NULL);

		fReturn = CryptSetKeyParam(hKey, KP_CERTIFICATE, pCertificateContext->pbCertEncoded, 0);
		CHECK_RETURN_BOOL(CryptSetKeyParam);
	}
	__finally
	{
		if (hKey)
			CryptDestroyKey(hKey);
	}
}



void TestCreateCert(HCRYPTPROV hProv )
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	HCRYPTKEY hKey = NULL;
	PCCERT_CONTEXT pCertificateContext = NULL;
	BYTE buffer[256];
	CERT_NAME_BLOB SubjectIssuerBlob = {sizeof(buffer), buffer};
	__try
	{

		fReturn = CertStrToName(X509_ASN_ENCODING,TEXT("CN=test"),CERT_X500_NAME_STR,NULL,(PBYTE)SubjectIssuerBlob.pbData,&SubjectIssuerBlob.cbData,NULL);
		CHECK_RETURN_BOOL(CertStrToName);

		pCertificateContext = CertCreateSelfSignCertificate(hProv,&SubjectIssuerBlob,
			0,NULL,NULL,NULL,NULL,NULL);

		CryptGetUserKey(hProv, AT_SIGNATURE, &hKey);
		CHECK_RETURN_BOOL(CryptGetUserKey);

		fReturn = CryptSetKeyParam(hKey, KP_CERTIFICATE, pCertificateContext->pbCertEncoded, 0);
		CHECK_RETURN_BOOL(CryptSetKeyParam);
	}
	__finally
	{
		if (pCertificateContext)
			CertFreeCertificateContext(pCertificateContext);
		if (hKey)
			CryptDestroyKey(hKey);
	}
}

void VerifyCert(PCCERT_CONTEXT pCertContext, DWORD dwKeySpec)
{
	BOOL fReturn = FALSE;
	HCRYPTPROV hVerifyProv = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTHASH hHash = NULL;
	__try
	{
		fReturn = CryptAcquireContext(&hVerifyProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
		CHECK_RETURN_BOOL(CryptAcquireContext);
		fReturn = CryptImportPublicKeyInfo(hVerifyProv, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &(pCertContext->pCertInfo->SubjectPublicKeyInfo), &hKey);
		CHECK_RETURN_BOOL(CryptImportPublicKeyInfo);

		if (dwKeySpec == AT_KEYEXCHANGE)
		{
			testEncryption(pCertContext, hKey);
			CHECK_RETURN_BOOL(testEncryption);
		}
		else
		{
			testSignature(pCertContext, CALG_SHA1);
			CHECK_RETURN_BOOL(testSignature);
		}
	}
	__finally
	{
		if (hHash)
			CryptDestroyHash(hHash);
		if (hKey)
			CryptDestroyKey(hKey);
		if (hVerifyProv)
			CryptReleaseContext(hVerifyProv, 0);
	}
}

int _tmain(int argc, _TCHAR* argv[])
{
	HCRYPTPROV hProv = NULL;
	HCRYPTPROV hProvCurrent = NULL;
	HCRYPTKEY hKey = NULL;
	DWORD pKeySpecs[2] = {AT_KEYEXCHANGE,AT_SIGNATURE};
	HCERTSTORE hStore = NULL;

	//TestCreateKey(NULL);
	//return 1;
	/*TestCreateCert(NULL);
	return 1;*/

	hStore = CertOpenStore(CERT_STORE_PROV_MEMORY,0,0,0,NULL);
	if (!hStore)
	{
		return 0;
	}
	HWND hwnd = GetConsoleWindow();
	if (!CryptSetProvParam(NULL, PP_CLIENT_HWND, (PBYTE) &hwnd, 0))
	{
		return 0;
	}
		
	printf( "Connecting to the csp\r\n");
	BOOL fReturn = CryptAcquireContext(&hProv, NULL,TEXT(CSPNAME), PROV_RSA_FULL, 0);
	if (!fReturn)
	{
		DWORD dwError = GetLastError();
		printf( "CryptAcquireContext failed 0x%08X\r\n", dwError);
		return -1;
	}
	printf( "manual enumeration\r\n");
	DWORD dwFlags = CRYPT_FIRST;
		/* Enumerate all the containers */
	CHAR szCharContainerName[256];
	TCHAR szContainerName[256];
	DWORD dwContainerNameLen = ARRAYSIZE(szContainerName);
	while (CryptGetProvParam(hProv,
				PP_ENUMCONTAINERS,
				(PBYTE) szCharContainerName,
				&dwContainerNameLen,
				dwFlags)
			)
	{
		// convert the container name to unicode
#ifdef UNICODE
		MultiByteToWideChar(CP_ACP, 0, szCharContainerName, (int)strlen(szCharContainerName)+1, szContainerName, ARRAYSIZE(szContainerName));
#else
		strcpy_s(szContainerName,ARRAYSIZE(szContainerName),szCharContainerName);
#endif
		// create a CContainer item
		if (CryptAcquireContext(&hProvCurrent,
			szContainerName,
			TEXT(CSPNAME),
			PROV_RSA_FULL,
			CRYPT_SILENT))
		{
			BOOL fHashKey = FALSE;
			for (DWORD i = 0; i < ARRAYSIZE(pKeySpecs); i++)
			{
				if (CryptGetUserKey(hProvCurrent,
						pKeySpecs[i],
						&hKey) )
				{
					fHashKey = TRUE;
					BYTE Data[4096];
					DWORD DataSize = 4096;
					if (CryptGetKeyParam(hKey,
							KP_CERTIFICATE,
							Data,
							&DataSize,
							0))
					{
						// certificate
						PCCERT_CONTEXT pCertContext= CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, Data, DataSize);
						/*BOOL fPropertiesChanged;
						CRYPTUI_VIEWCERTIFICATE_STRUCT certViewInfo;
						ZeroMemory(&certViewInfo,sizeof(certViewInfo));
						certViewInfo.dwSize = sizeof(CRYPTUI_VIEWCERTIFICATE_STRUCT);
						certViewInfo.hwndParent = NULL;
						certViewInfo.szTitle = TEXT("Info");
						certViewInfo.pCertContext = pCertContext;
						CryptUIDlgViewCertificate(&certViewInfo,&fPropertiesChanged);*/
						CertAddCertificateContextToStore(hStore, pCertContext, 0, NULL);
						CertFreeCertificateContext(pCertContext);
					}
					
					// next loop
					CryptDestroyKey(hKey);
					hKey = NULL;
				}
			}
		}
		CryptReleaseContext(hProvCurrent, 0);
		hProvCurrent = NULL;
		dwFlags = CRYPT_NEXT;
		dwContainerNameLen = ARRAYSIZE(szContainerName);
	}
	printf( "automatic enumeration\r\n");
	DWORD dwSize = sizeof(hStore);
	if (!CryptGetProvParam(hProv, PP_USER_CERTSTORE, (PBYTE) &hStore, &dwSize, 0))
	{
		DWORD dwError = GetLastError();
		_tprintf( TEXT("CryptAcquireContext failed 0x%08X\r\n"), dwError);
		return -1;
	}
	printf( "selecting a cert hosted in the csp (not the windows store)\r\n");
	PCCERT_CONTEXT selectedCert = CryptUIDlgSelectCertificateFromStore(hStore, hwnd, NULL, NULL, 0, 0, NULL);
	if (!selectedCert)
	{
		DWORD dwError = GetLastError();
		printf( "CryptUIDlgSelectCertificateFromStore failed 0x%08X\r\n", dwError);
		return -1;
	}
	//VerifyCert(selectedCert, AT_KEYEXCHANGE);
	//testKeyImport(selectedCert);
	//VerifyKeyProp(selectedCert);
	return -1;
	

	printf( "testing signatures\r\n");
	if (!testSignature(selectedCert, CALG_SHA1))
	{
		DWORD dwError = GetLastError();
		printf( "testSignature CALG_SHA1 failed 0x%08X\r\n", dwError);
		return -1;
	}
	if (!testSignature(selectedCert, CALG_SHA_256))
	{
		DWORD dwError = GetLastError();
		printf( "testSignature CALG_SHA_256 failed 0x%08X\r\n", dwError);
		return -1;
	}
	if (!testSignature(selectedCert, CALG_SHA_384))
	{
		DWORD dwError = GetLastError();
		printf( "testSignature CALG_SHA_384 failed 0x%08X\r\n", dwError);
		return -1;
	}
	if (!testSignature(selectedCert, CALG_SHA_512))
	{
		DWORD dwError = GetLastError();
		printf( "testSignature CALG_SHA_512 failed 0x%08X\r\n", dwError);
		return -1;
	}
	if (!testSignature(selectedCert, CALG_MD5))
	{
		DWORD dwError = GetLastError();
		printf( "testSignature CALG_MD5 failed 0x%08X\r\n", dwError);
		return -1;
	}
	if (!testSignature(selectedCert, CALG_SSL3_SHAMD5))
	{
		DWORD dwError = GetLastError();
		printf( "testSignature CALG_SSL3_SHAMD5 failed 0x%08X\r\n", dwError);
		return -1;
	}
	printf( "signature test done\r\n");
	return 0;
}

