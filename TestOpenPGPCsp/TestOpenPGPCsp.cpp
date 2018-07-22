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

BOOL testEncryptionCNG(PCCERT_CONTEXT pCertContext)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	DWORD dwKeySpec;
	BOOL freehProv;
	NCRYPT_KEY_HANDLE hKey = NULL;
	BYTE testData[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
	BYTE testData2[ARRAYSIZE(testData)];
	BYTE pbBuffer[10000];
	DWORD dwSize =sizeof(pbBuffer);
	__try
	{
		if (!pCertContext)
		{
			__leave;
		}
		if (!CryptAcquireCertificatePrivateKey(pCertContext, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG , NULL, &hKey, &dwKeySpec, &freehProv))
		{
			dwError = GetLastError();
			printf("error CryptAcquireCertificatePrivateKey 0x%08X\r\n", dwError);
			__leave;
		}
		memcpy(pbBuffer, testData, sizeof(testData));
		dwSize = sizeof(pbBuffer);
		dwError = NCryptEncrypt(hKey, testData, sizeof(testData), NULL, pbBuffer, dwSize, &dwSize, NCRYPT_PAD_PKCS1_FLAG);
		if (dwError)
		{
			printf("error NCryptEncrypt 0x%08X\r\n", dwError);
			__leave;
		}
		DWORD dwDecryptedSize;
		dwError = NCryptDecrypt(hKey, pbBuffer, dwSize, NULL, NULL, 0, &dwDecryptedSize,NCRYPT_PAD_PKCS1_FLAG);
		if (dwError)
		{
			printf("error NCryptDecrypt 0x%08X\r\n", dwError);
			__leave;
		}
		dwError = NCryptDecrypt(hKey, pbBuffer, dwSize, NULL, testData2, ARRAYSIZE(testData2), &dwDecryptedSize,NCRYPT_PAD_PKCS1_FLAG);
		if (dwError)
		{
			printf("error NCryptDecrypt 0x%08X\r\n", dwError);
			__leave;
		}
		if (dwDecryptedSize != sizeof(testData) || memcmp(testData2, testData, sizeof(testData)) != 0)
		{
			dwError = NTE_BAD_DATA;
			printf("error CryptDecrypt invalid\r\n");
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		NCryptFreeObject(hKey);
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

int testCsp()
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


BOOL testSignatureCNG(PCCERT_CONTEXT pCertContext, PWSTR szAlg)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	DWORD dwKeySpec;
	DWORD dwSize = 0;
	BOOL freehProv;
	PBYTE pbBuffer = NULL;
	NCRYPT_KEY_HANDLE hKey = NULL;
	BCRYPT_ALG_HANDLE hHashAlg = NULL;
	DWORD cbHash;
	BYTE pbHash[100];
	BYTE pbHashObject[1000];
	DWORD cbHashObject = 0;
	BCRYPT_HASH_HANDLE hHash = NULL;
	BYTE pbRsaTest[1000];
	BCRYPT_KEY_HANDLE       hTmpKey         = NULL;
	BCRYPT_ALG_HANDLE       hSignAlg        = NULL;
	BCRYPT_PKCS1_PADDING_INFO  pi = {szAlg};
	__try
	{
		if (!pCertContext)
		{
			__leave;
		}
		printf("Test hash %S\r\n", szAlg);
		if (!CryptAcquireCertificatePrivateKey(pCertContext,  CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, NULL, &hKey, &dwKeySpec, &freehProv))
		{
			dwError = GetLastError();
			printf("error CryptAcquireCertificatePrivateKey 0x%08X\r\n", dwError);
			__leave;
		}
		if (szAlg)
		{
			dwError = BCryptOpenAlgorithmProvider(&hHashAlg,szAlg,NULL,0);
			if (dwError)
			{
				printf("error BCryptOpenAlgorithmProvider 0x%08X\r\n", dwError);
				__leave;
			}
			dwSize = sizeof(DWORD);
			dwError = BCryptGetProperty(hHashAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &dwSize, 0);
			if (dwError)
			{
				printf("error BCryptOpenAlgorithmProvider 0x%08X\r\n", dwError);
				__leave;
			}
			dwSize = sizeof(DWORD);
			dwError = BCryptGetProperty(hHashAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &dwSize, 0);
			if (dwError)
			{
				printf("error BCryptGetProperty 0x%08X\r\n", dwError);
				__leave;
			}
			dwError = BCryptCreateHash(
											hHashAlg, 
											&hHash, 
											pbHashObject, 
											cbHashObject, 
											NULL, 
											0, 
											0);
			if (dwError)
			{
				printf("error BCryptCreateHash 0x%08X\r\n", dwError);
				__leave;
			}
			dwError = BCryptHashData(
											hHash,
											(PUCHAR) "b,srklhg,nslgnsklgeglseklngeklsnglsenge", 20,
											0);
			if (dwError)
			{
				printf("error BCryptHashData 0x%08X\r\n", dwError);
				__leave;
			}
    
			//close the hash
			dwError = BCryptFinishHash(
												hHash, 
												pbHash, 
												cbHash, 
												0);
			if (dwError)
			{
				printf("error BCryptFinishHash 0x%08X\r\n", dwError);
				__leave;
			}
		
			DWORD dwSize = 0;
			dwError = NCryptSignHash(hKey, &pi,pbHash,cbHash,NULL,0,&dwSize,NCRYPT_PAD_PKCS1_FLAG);
			if (dwError)
			{
				printf("error NCryptSignHash 0x%08X\r\n", dwError);
				__leave;
			}
			pbBuffer = (PBYTE) malloc(dwSize);
			if (!pbBuffer)
			{
				dwError = ERROR_OUTOFMEMORY;
				printf("error malloc 0x%08X\r\n", dwError);
				__leave;
			}
			dwError = NCryptSignHash(hKey, &pi,pbHash,cbHash,pbBuffer,dwSize,&dwSize,NCRYPT_PAD_PKCS1_FLAG);
			if (dwError)
			{
				printf("error NCryptSignHash 0x%08X\r\n", dwError);
				__leave;
			}
			dwError = NCryptVerifySignature(hKey, &pi, pbHash, cbHash,pbBuffer, dwSize, NCRYPT_PAD_PKCS1_FLAG);
			if (dwError)
			{
				printf("error NCryptVerifySignature 0x%08X\r\n", dwError);
				__leave;
			}
			DWORD dwBlobSize = sizeof(pbRsaTest);
			dwError = NCryptExportKey(hKey,NULL,
											BCRYPT_RSAPUBLIC_BLOB,
											NULL,
											pbRsaTest,
											sizeof(pbRsaTest),
											&dwBlobSize,
											0);
			if (dwError)
			{
				printf("error NCryptExportKey 0x%08X\r\n", dwError);
				__leave;
			}
			dwError = BCryptOpenAlgorithmProvider(
													&hSignAlg,
													BCRYPT_RSA_ALGORITHM,
													NULL,
													0);
			if (dwError)
			{
				printf("error BCryptOpenAlgorithmProvider 0x%08X\r\n", dwError);
				__leave;
			}
			dwError = BCryptImportKeyPair(hSignAlg,NULL,BCRYPT_RSAPUBLIC_BLOB,&hTmpKey,pbRsaTest,dwBlobSize,0);
			if (dwError)
			{
				printf("error BCryptImportKeyPair 0x%08X\r\n", dwError);
				__leave;
			}
		
			dwError = BCryptVerifySignature(hTmpKey,&pi,pbHash, cbHash,pbBuffer, dwSize,BCRYPT_PAD_PKCS1);
			if (dwError)
			{
				printf("error BCryptVerifySignature 0x%08X\r\n", dwError);
				__leave;
			}
		}
		else //shamd5
		{
			memcpy(pbHash, "gnesjogseonbsdo bosdbnsdbsdklnblsdn hesjgvslegpgesoeskseg,glse,vl,sel,evl,slev,ls,lvle", 36);
			cbHash = 36;
			DWORD dwSize = 0;
			dwError = NCryptSignHash(hKey, NULL,pbHash,cbHash,NULL,0,&dwSize,0);
			if (dwError)
			{
				printf("error NCryptSignHash 0x%08X\r\n", dwError);
				__leave;
			}
			pbBuffer = (PBYTE) malloc(dwSize);
			if (!pbBuffer)
			{
				dwError = ERROR_OUTOFMEMORY;
				printf("error malloc 0x%08X\r\n", dwError);
				__leave;
			}
			dwError = NCryptSignHash(hKey, NULL,pbHash,cbHash,pbBuffer,dwSize,&dwSize,0);
			if (dwError)
			{
				printf("error NCryptSignHash 0x%08X\r\n", dwError);
				__leave;
			}
			dwError = NCryptVerifySignature(hKey, &pi, pbHash, cbHash,pbBuffer, dwSize, NCRYPT_PAD_PKCS1_FLAG);
			if (dwError)
			{
				printf("error NCryptVerifySignature 0x%08X\r\n", dwError);
				__leave;
			}
			DWORD dwBlobSize = sizeof(pbRsaTest);
			dwError = NCryptExportKey(hKey,NULL,
											BCRYPT_RSAPUBLIC_BLOB,
											NULL,
											pbRsaTest,
											sizeof(pbRsaTest),
											&dwBlobSize,
											0);
			if (dwError)
			{
				printf("error NCryptExportKey 0x%08X\r\n", dwError);
				__leave;
			}
			dwError = BCryptOpenAlgorithmProvider(
													&hSignAlg,
													BCRYPT_RSA_ALGORITHM,
													NULL,
													0);
			if (dwError)
			{
				printf("error BCryptOpenAlgorithmProvider 0x%08X\r\n", dwError);
				__leave;
			}
			dwError = BCryptImportKeyPair(hSignAlg,NULL,BCRYPT_RSAPUBLIC_BLOB,&hTmpKey,pbRsaTest,dwBlobSize,0);
			if (dwError)
			{
				printf("error BCryptImportKeyPair 0x%08X\r\n", dwError);
				__leave;
			}
		
			dwError = BCryptVerifySignature(hTmpKey,&pi,pbHash, cbHash,pbBuffer, dwSize,NCRYPT_PAD_PKCS1_FLAG);
			if (dwError)
			{
				printf("error BCryptVerifySignature 0x%08X\r\n", dwError);
				__leave;
			}
		}
		fReturn = TRUE;
	}
	__finally
	{

		if (hTmpKey)
			BCryptDestroyKey(hTmpKey);
		if (hSignAlg)
			BCryptCloseAlgorithmProvider(hSignAlg,0);
		if (hHash)
			BCryptDestroyHash(hHash);
		if (freehProv && hKey)
			NCryptFreeObject(hKey);

		if( pbBuffer)
			free(pbBuffer);
	}
	return fReturn;
}

void testKsp()
{
	NCRYPT_PROV_HANDLE HProv = NULL;
	DWORD dwReturn = 0;
	HCERTSTORE hStore = NULL;
	__try
	{
		dwReturn = NCryptOpenStorageProvider(&HProv, TEXT(KSPNAME),0);
		if (dwReturn)
		{
			__leave;
		}
		NCryptKeyName* key = NULL;
		PVOID pEnumContext = NULL;
		while (dwReturn == 0)
		{
			dwReturn = NCryptEnumKeys(HProv, NULL, &key, &pEnumContext, 0);
			if (!dwReturn)
			{
				DWORD dwTemp = 0;
				NCRYPT_KEY_HANDLE hKey = NULL;
				dwTemp = NCryptOpenKey(HProv, &hKey, key->pszName, key->dwLegacyKeySpec, 0);
				if (!dwTemp)
				{
					BYTE pbTemp[4000];
					DWORD dwSize = sizeof(pbTemp);
					dwTemp = NCryptGetProperty(hKey, NCRYPT_CERTIFICATE_PROPERTY, pbTemp, dwSize, &dwSize, 0);
					if (!dwTemp)
					{
						PCCERT_CONTEXT pCertContext= CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pbTemp, dwSize);
						if (pCertContext)
						{
							/*BOOL fPropertiesChanged;
							CRYPTUI_VIEWCERTIFICATE_STRUCT certViewInfo;
							ZeroMemory(&certViewInfo,sizeof(certViewInfo));
							certViewInfo.dwSize = sizeof(CRYPTUI_VIEWCERTIFICATE_STRUCT);
							certViewInfo.hwndParent = NULL;
							certViewInfo.szTitle = TEXT("Info");
							certViewInfo.pCertContext = pCertContext;
							CryptUIDlgViewCertificate(&certViewInfo,&fPropertiesChanged);*/
							CertFreeCertificateContext(pCertContext);
						}
					}
					NCryptFreeObject(hKey);
				}
			}
		}
		if (pEnumContext)
			NCryptFreeBuffer(pEnumContext);
		DWORD dwSize = sizeof(hStore);
		dwReturn = NCryptGetProperty(HProv,NCRYPT_USER_CERTSTORE_PROPERTY, (PBYTE) &hStore, dwSize, &dwSize, 0);
		if (dwReturn)
		{
			_tprintf( TEXT("NCryptGetProperty failed 0x%08X\r\n"), dwReturn);
			__leave;
		}
		printf( "selecting a cert hosted in the csp (not the windows store)\r\n");
		HWND hwnd = GetConsoleWindow();

		PCCERT_CONTEXT selectedCert = CryptUIDlgSelectCertificateFromStore(hStore, hwnd, NULL, NULL, 0, 0, NULL);
		if (!selectedCert)
		{
			dwReturn = GetLastError();
			printf( "CryptUIDlgSelectCertificateFromStore failed 0x%08X\r\n", dwReturn);
			__leave;
		}

		if (!testEncryptionCNG(selectedCert))
		{
			DWORD dwError = GetLastError();
			printf( "testEncryption failed 0x%08X\r\n", dwError);
			__leave;
		}
		printf( "encryption test done\r\n");


		printf( "testing signatures\r\n");
		if (!testSignatureCNG(selectedCert, BCRYPT_SHA1_ALGORITHM))
		{
			DWORD dwError = GetLastError();
			printf( "testSignature CALG_SHA1 failed 0x%08X\r\n", dwError);
			__leave;
		}
		if (!testSignatureCNG(selectedCert, BCRYPT_SHA256_ALGORITHM))
		{
			DWORD dwError = GetLastError();
			printf( "testSignature CALG_SHA_256 failed 0x%08X\r\n", dwError);
			__leave;
		}
		if (!testSignatureCNG(selectedCert, BCRYPT_SHA384_ALGORITHM))
		{
			DWORD dwError = GetLastError();
			printf( "testSignature CALG_SHA_384 failed 0x%08X\r\n", dwError);
			__leave;
		}
		/*
		if (!testSignatureCNG(selectedCert, BCRYPT_SHA512_ALGORITHM))
		{
			DWORD dwError = GetLastError();
			printf( "testSignature CALG_SHA_512 failed 0x%08X\r\n", dwError);
			__leave;
		}
		if (!testSignatureCNG(selectedCert, BCRYPT_MD5_ALGORITHM))
		{
			DWORD dwError = GetLastError();
			printf( "testSignature CALG_MD5 failed 0x%08X\r\n", dwError);
			__leave;
		}*/
		if (!testSignatureCNG(selectedCert, NULL))
		{
			DWORD dwError = GetLastError();
			printf( "testSignature CALG_SSL3_SHAMD5 failed 0x%08X\r\n", dwError);
			__leave;
		}
		printf( "signature test done\r\n");
	}
	__finally
	{
		if (hStore)
			CertCloseStore(hStore, 0);
		if (HProv) 
			NCryptFreeObject(HProv);
	}
}

void testImportCNG()
{
	NCRYPT_PROV_HANDLE HProv = NULL;
	DWORD dwReturn = 0;
	HCERTSTORE hStore = NULL;
	BCRYPT_ALG_HANDLE hBRSA = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	NCRYPT_KEY_HANDLE hTestKey = NULL;
	BYTE pbRsaTest[50000];
	__try
	{
		dwReturn = BCryptOpenAlgorithmProvider(&hBRSA,BCRYPT_RSA_ALGORITHM,NULL,0);
		if (dwReturn)
		{
			printf("error BCryptOpenAlgorithmProvider 0x%08X\r\n", dwReturn);
			__leave;
		}
		dwReturn = BCryptGenerateKeyPair(hBRSA, &hKey, 2048, 0);
		if (dwReturn)
		{
			printf("error BCryptGenerateKeyPair 0x%08X\r\n", dwReturn);
			__leave;
		}
		dwReturn = BCryptFinalizeKeyPair(hKey, 0);
		if (dwReturn)
		{
			printf("error BCryptFinalizeKeyPair 0x%08X\r\n", dwReturn);
			__leave;
		}
		DWORD dwBlobSize = sizeof (pbRsaTest);
		dwReturn = BCryptExportKey(hKey,NULL,
											BCRYPT_RSAPRIVATE_BLOB,
											pbRsaTest,
											sizeof(pbRsaTest),
											&dwBlobSize,
											0);
		if (dwReturn)
		{
			printf("error BCryptExportKey 0x%08X\r\n", dwReturn);
			__leave;
		}
		dwReturn = NCryptOpenStorageProvider(&HProv, TEXT(KSPNAME),0);
		if (dwReturn)
		{
			printf("error NCryptOpenStorageProvider 0x%08X\r\n", dwReturn);
			__leave;
		}
		dwReturn = NCryptImportKey(HProv, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, &hTestKey, pbRsaTest, dwBlobSize, 0);
		if (dwReturn)
		{
			printf("error NCryptImportKey 0x%08X\r\n", dwReturn);
			__leave;
		}
		// to test: NCRYPT_DO_NOT_FINALIZE_FLAG 
	}
	__finally
	{

		if (hKey)
			BCryptDestroyKey(hKey);
		if (hBRSA)
			BCryptCloseAlgorithmProvider(hBRSA, 0);
		if (hTestKey)
			NCryptFreeObject(hTestKey);
		if (HProv) 
			NCryptFreeObject(HProv);
	}
}

void testCreateKeyCNG()
{
	NCRYPT_PROV_HANDLE HProv = NULL;
	DWORD dwReturn = 0;
	NCRYPT_KEY_HANDLE hTestKey = NULL;
	__try
	{
		dwReturn = NCryptOpenStorageProvider(&HProv, TEXT(KSPNAME),0);
		if (dwReturn)
		{
			printf("error NCryptOpenStorageProvider 0x%08X\r\n", dwReturn);
			__leave;
		}
		dwReturn = NCryptCreatePersistedKey(HProv, &hTestKey, BCRYPT_RSA_ALGORITHM, L"test for CNG", AT_KEYEXCHANGE, 0);
		if (dwReturn)
		{
			printf("error NCryptCreatePersistedKey 0x%08X\r\n", dwReturn);
			__leave;
		}
		DWORD dwLength = 2048;
		DWORD dwSize = 4;
		dwReturn = NCryptSetProperty(hTestKey, NCRYPT_LENGTH_PROPERTY, (PBYTE) &dwLength, dwSize, 0);
		if (dwReturn)
		{
			printf("error NCryptSetProperty 0x%08X\r\n", dwReturn);
			__leave;
		}
		dwReturn = NCryptFinalizeKey(hTestKey, 0);
		if (dwReturn)
		{
			printf("error NCryptFinalizeKey 0x%08X\r\n", dwReturn);
			__leave;
		}
	}
	__finally
	{
		if (hTestKey)
			NCryptFreeObject(hTestKey);
		if (HProv) 
			NCryptFreeObject(HProv);
	}
}

typedef enum _KERB_LOGON_SUBMIT_TYPE {
  KerbInteractiveLogon        ,
  KerbSmartCardLogon          ,
  KerbWorkstationUnlockLogon  ,
  KerbSmartCardUnlockLogon    ,
  KerbProxyLogon              ,
  KerbTicketLogon             ,
  KerbTicketUnlockLogon       ,
  KerbS4ULogon                ,
  KerbCertificateLogon        ,
  KerbCertificateS4ULogon     ,
  KerbCertificateUnlockLogon  ,
  KerbNoElevationLogon        ,
  KerbLuidLogon
} KERB_LOGON_SUBMIT_TYPE, *PKERB_LOGON_SUBMIT_TYPE;

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength/2), length_is(Length/2)]
#endif // MIDL_PASS
    PWSTR  Buffer;
} UNICODE_STRING, *PLSA_UNICODE_STRING;

typedef struct _KERB_SMARTCARD_CSP_INFO {
  DWORD dwCspInfoLen;
  DWORD MessageType;
  union {
    PVOID   ContextInformation;
    ULONG64 SpaceHolderForWow64;
  };
  DWORD flags;
  DWORD KeySpec;
  ULONG nCardNameOffset;
  ULONG nReaderNameOffset;
  ULONG nContainerNameOffset;
  ULONG nCSPNameOffset;
  TCHAR bBuffer;
} KERB_SMARTCARD_CSP_INFO, *PKERB_SMARTCARD_CSP_INFO;

typedef struct _KERB_CERTIFICATE_LOGON {
  KERB_LOGON_SUBMIT_TYPE MessageType;
  UNICODE_STRING         DomainName;
  UNICODE_STRING         UserName;
  UNICODE_STRING         Pin;
  ULONG                  Flags;
  ULONG                  CspDataLength;
  PUCHAR                 CspData;
} KERB_CERTIFICATE_LOGON, *PKERB_CERTIFICATE_LOGON;

void TestLogin()
{
	BOOL save = false;
	DWORD authPackage = 0;
	LPVOID authBuffer;
	ULONG authBufferSize = 0;
	CREDUI_INFO credUiInfo = {0};
	KERB_CERTIFICATE_LOGON* pCertLogon;
	KERB_SMARTCARD_CSP_INFO *cspData;
	CoInitializeEx(NULL,COINIT_APARTMENTTHREADED); 

	credUiInfo.pszCaptionText = TEXT("My caption");
	credUiInfo.pszMessageText = TEXT("My message");
	credUiInfo.cbSize = sizeof(credUiInfo);

	DWORD result = 0;
	result = CredUIPromptForWindowsCredentials(&(credUiInfo), 0, &(authPackage), 
		NULL, 0, &authBuffer, &authBufferSize, &(save), 0);
	if (result == ERROR_SUCCESS)
	{
		pCertLogon = (KERB_CERTIFICATE_LOGON*) authBuffer;
		cspData = (PKERB_SMARTCARD_CSP_INFO) ((LONG_PTR)authBuffer + pCertLogon->CspData);
		PWSTR szCSP = &cspData->bBuffer + cspData->nCSPNameOffset;
		PWSTR szCardNameOffset = &cspData->bBuffer + cspData->nCardNameOffset;
		PWSTR szContainerNameOffset = &cspData->bBuffer + cspData->nContainerNameOffset;
		PWSTR szReaderNameOffset = &cspData->bBuffer + cspData->nReaderNameOffset;
		int i = 0;
		/**BOOL fReturn = FALSE;
		LSA_HANDLE hLsa;
		MSV1_0_INTERACTIVE_PROFILE *Profile;
		ULONG ProfileLen;
		LSA_STRING Origin = { (USHORT)strlen("MYTEST"), (USHORT)sizeof("MYTEST"), "MYTEST" };
		TOKEN_SOURCE Source = { "TEST", { 0, 101 } };
		QUOTA_LIMITS Quota = {0};
		LUID Luid;
		NTSTATUS err,stat;
		HANDLE Token;
		err = LsaConnectUntrusted(&hLsa);
	
		err = LsaLogonUser(hLsa, &Origin, (SECURITY_LOGON_TYPE)  Interactive , authPackage, authBuffer,authBufferSize,NULL, &Source, (PVOID*)&Profile, &ProfileLen, &Luid, &Token, &Quota, &stat);
	
		LsaDeregisterLogonProcess(hLsa);
		if (err)
		{
			SetLastError(LsaNtStatusToWinError(err));
		}
		else
		{
			fReturn = TRUE;
			LsaFreeReturnBuffer(Profile);
			CloseHandle(Token);
		
		}*/
	}
}

int _tmain(int argc, _TCHAR* argv[])
{

	//testKsp();
	TestLogin();
	//testCsp();
	//testCreateKeyCNG();
	//testImportCNG();
	return 0;
}