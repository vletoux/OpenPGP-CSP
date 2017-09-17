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


#include "global.h"



BOOL SchGetProviderNameFromCardName(__in PCTSTR szCardName, __out_ecount(*pdwProviderNameLen) PTSTR szProviderName, __inout PDWORD pdwProviderNameLen)
{
	// get provider name
	SCARDCONTEXT hSCardContext;
	LONG lCardStatus;
	lCardStatus = SCardEstablishContext(SCARD_SCOPE_USER,NULL,NULL,&hSCardContext);
	if (SCARD_S_SUCCESS != lCardStatus)
	{
		Trace(TRACE_LEVEL_WARNING,L"SCardEstablishContext 0x%08x",lCardStatus);
		return FALSE;
	}
	
	lCardStatus = SCardGetCardTypeProviderName(hSCardContext,
									   szCardName,
									   SCARD_PROVIDER_CSP,
									   szProviderName,
									   pdwProviderNameLen);
	if (SCARD_S_SUCCESS != lCardStatus)
	{
		Trace(TRACE_LEVEL_WARNING,L"SCardGetCardTypeProviderName 0x%08x",lCardStatus);
		SCardReleaseContext(hSCardContext);
		return FALSE;
	}
	SCardReleaseContext(hSCardContext);
	return TRUE;
}

_Ret_maybenull_ PBYTE AllocateAndEncodeObject(LPVOID pvStruct, LPCSTR lpszStructType, LPDWORD pdwSize )
{
   // Get Key Usage blob size   
   PBYTE pbEncodedObject = NULL;
   BOOL bResult = TRUE;
   DWORD dwError;
	__try
   {
	   *pdwSize = 0;	
	   bResult = CryptEncodeObject(X509_ASN_ENCODING,   
								   lpszStructType,   
								   pvStruct,   
								   NULL, pdwSize);   
	   if (!bResult)   
	   {   
		  dwError = GetLastError();
		  __leave;   
	   }   

	   // Allocate Memory for Key Usage Blob   
	   pbEncodedObject = (PBYTE)new BYTE[*pdwSize];
	   if (!pbEncodedObject)   
	   {   
		  bResult = FALSE;
		  dwError = GetLastError();   
		  __leave;   
	   }   

	   // Get Key Usage Extension blob   
	   bResult = CryptEncodeObject(X509_ASN_ENCODING,   
								   lpszStructType,   
								   pvStruct,   
								   pbEncodedObject, pdwSize);   
	   if (!bResult)   
	   {   
		  dwError = GetLastError();  
		  __leave;   
	   }   
   }
   __finally
   {
		if (pbEncodedObject && !bResult)
		{
			delete[] (pbEncodedObject);
			pbEncodedObject = NULL;
		}
   }
   return pbEncodedObject;
}

BOOL CreateSelfSignCertificate(PTSTR szReader, PTSTR szSubject, BOOL fKeyExchange)
{
	BOOL fReturn = FALSE;
	TCHAR szContainerName[256];
	CHAR tempName[256];
	CERT_NAME_BLOB SubjectIssuerBlob = {0};
	BYTE ByteData;   
    CRYPT_BIT_BLOB KeyUsage;  
	CERT_EXTENSIONS CertExtensions = {0};
	CERT_EXTENSION CertExtension[4];
	CertExtensions.rgExtension = CertExtension;
	HCRYPTPROV hProv = NULL;
	BOOL bDestroyContainer = FALSE;
	HCRYPTKEY hKey = NULL;
	SYSTEMTIME StartTime, EndTime;
    DWORD dwSize; 
	PCCERT_CONTEXT pCertificateContext = NULL;
	PBYTE pbKeyUsage = NULL; 
	PBYTE pbBasicConstraints = NULL;
	PBYTE pbEnhKeyUsage = NULL;
	CERT_BASIC_CONSTRAINTS2_INFO BasicConstraints;
	PSTR KeyUsageIdentifier[4];
	CERT_ENHKEY_USAGE CertEnhKeyUsage = { 4, KeyUsageIdentifier };  
	CRYPT_KEY_PROV_INFO kpi;

	DWORD dwError = 0;
	__try   
    { 
		Trace(TRACE_LEVEL_INFORMATION,L"Enter");
		
		GetSystemTime(&StartTime);
		memcpy(&EndTime, &StartTime, sizeof(StartTime));
		// validation time : 10 years
		EndTime.wYear += 10;

		_stprintf_s(szContainerName,ARRAYSIZE(szContainerName), _T("\\\\.\\%s\\"), szReader);

		// create container
		if (!CryptAcquireContext(
			&hProv,
			szContainerName,   
			szProvider,
			PROV_RSA_FULL,
			CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"CryptAcquireContext 0x%08X", dwError);
			__leave;
		}
		bDestroyContainer=TRUE;

		dwSize = sizeof(tempName);
		if (!CryptGetProvParam(hProv, PP_CONTAINER, (PBYTE) tempName, &dwSize, 0))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"CryptGetProvParam 0x%08X", dwError);
			__leave;
		}
		MultiByteToWideChar(CP_ACP, 0, tempName, (int) strlen(tempName) +1,szContainerName, ARRAYSIZE(szContainerName));
		// generate key
		// Key Size
		if (!CryptGenKey(hProv, (fKeyExchange? AT_KEYEXCHANGE:AT_SIGNATURE), 2048 * 0x10000, &hKey))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"CryptGenKey 0x%08X", dwError);
			__leave;
		}

		
		// create the cert data
		if (!CertStrToName(X509_ASN_ENCODING,szSubject,CERT_X500_NAME_STR,NULL,NULL,&SubjectIssuerBlob.cbData,NULL))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"CertStrToName 0x%08X", dwError);
			__leave;
		}
		SubjectIssuerBlob.pbData = (PBYTE) new BYTE[SubjectIssuerBlob.cbData];
		if (!SubjectIssuerBlob.pbData)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"EIDAlloc 0x%08X", dwError);
			__leave;
		}
		if (!CertStrToName(X509_ASN_ENCODING,szSubject,CERT_X500_NAME_STR,NULL,(PBYTE)SubjectIssuerBlob.pbData,&SubjectIssuerBlob.cbData,NULL))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"CertStrToName 0x%08X", dwError);
			__leave;
		}

		//////////////////////////////////////////////////
		// Key Usage & ...
		


		// Set Key Usage according to Public Key Type   
		ZeroMemory(&KeyUsage, sizeof(KeyUsage));   
		KeyUsage.cbData = 1;   
		KeyUsage.pbData = &ByteData;   
      
		ByteData = CERT_DIGITAL_SIGNATURE_KEY_USAGE |   
					CERT_DATA_ENCIPHERMENT_KEY_USAGE|   
					CERT_KEY_ENCIPHERMENT_KEY_USAGE |   
					CERT_KEY_AGREEMENT_KEY_USAGE;   


		pbKeyUsage = AllocateAndEncodeObject(&KeyUsage,X509_KEY_USAGE,&dwSize);
		if (!pbKeyUsage) 
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"AllocateAndEncodeObject 0x%08X", dwError);
			__leave;
		}

		CertExtensions.rgExtension[CertExtensions.cExtension].pszObjId = szOID_KEY_USAGE;   
		CertExtensions.rgExtension[CertExtensions.cExtension].fCritical = FALSE;   
		CertExtensions.rgExtension[CertExtensions.cExtension].Value.cbData = dwSize;   
		CertExtensions.rgExtension[CertExtensions.cExtension].Value.pbData = pbKeyUsage;   
		// Increase extension count   
		CertExtensions.cExtension++; 
	   //////////////////////////////////////////////////

	   // Zero Basic Constraints structure   
		ZeroMemory(&BasicConstraints, sizeof(BasicConstraints));   
    
		// Self-signed is always a CA   
		Trace(TRACE_LEVEL_ERROR,L"SelfSigned");
		BasicConstraints.fCA = TRUE;   
		BasicConstraints.fPathLenConstraint = TRUE;   
		BasicConstraints.dwPathLenConstraint = 1;      

		pbBasicConstraints = AllocateAndEncodeObject(&BasicConstraints,X509_BASIC_CONSTRAINTS2,&dwSize);
		if (!pbBasicConstraints) 
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"AllocateAndEncodeObject 0x%08X", dwError);
			__leave;
		}

		// Set Basic Constraints extension   
		CertExtensions.rgExtension[CertExtensions.cExtension].pszObjId = szOID_BASIC_CONSTRAINTS2;   
		CertExtensions.rgExtension[CertExtensions.cExtension].fCritical = FALSE;   
		CertExtensions.rgExtension[CertExtensions.cExtension].Value.cbData = dwSize;   
		CertExtensions.rgExtension[CertExtensions.cExtension].Value.pbData = pbBasicConstraints;   
		// Increase extension count   
		CertExtensions.cExtension++;  
		//////////////////////////////////////////////////

		CertEnhKeyUsage.cUsageIdentifier = 0;
		CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = szOID_PKIX_KP_CLIENT_AUTH;
		CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = szOID_PKIX_KP_SERVER_AUTH;
		CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = szOID_KP_SMARTCARD_LOGON;
		CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = szOID_KP_EFS;
		pbEnhKeyUsage = AllocateAndEncodeObject(&CertEnhKeyUsage,X509_ENHANCED_KEY_USAGE,&dwSize);
		if (!pbEnhKeyUsage)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"AllocateAndEncodeObject 0x%08X", dwError);
			__leave;
		}

		// Set Basic Constraints extension   
		CertExtensions.rgExtension[CertExtensions.cExtension].pszObjId = szOID_ENHANCED_KEY_USAGE;   
		CertExtensions.rgExtension[CertExtensions.cExtension].fCritical = FALSE;   
		CertExtensions.rgExtension[CertExtensions.cExtension].Value.cbData = dwSize;   
		CertExtensions.rgExtension[CertExtensions.cExtension].Value.pbData = pbEnhKeyUsage;   
		// Increase extension count   
		CertExtensions.cExtension++; 

		// trick to use AT_KEYEXCHANGE instead of AT_SIGNATURE
		ZeroMemory(&kpi, sizeof(kpi));
		kpi.pwszContainerName = szContainerName;
		kpi.pwszProvName = szProvider;
		kpi.dwProvType = PROV_RSA_FULL;
		kpi.dwFlags = CERT_SET_KEY_CONTEXT_PROP_ID;
		kpi.dwKeySpec = (fKeyExchange?AT_KEYEXCHANGE:AT_SIGNATURE);

		//////////////////////////////////////////////////
		pCertificateContext = CertCreateSelfSignCertificate(hProv,&SubjectIssuerBlob,
			0,&kpi,NULL,&StartTime,&EndTime,&CertExtensions);
		if (!pCertificateContext)
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"CertCreateSelfSignCertificate 0x%08X", dwError);
			__leave;
		}
		if (!CryptSetKeyParam(hKey, KP_CERTIFICATE,pCertificateContext->pbCertEncoded, 0))
		{
			dwError = GetLastError();
			Trace(TRACE_LEVEL_ERROR,L"CryptSetKeyParam 0x%08X", dwError);
			__leave;
		}
		Trace(TRACE_LEVEL_INFORMATION,L"Success");
		bDestroyContainer = FALSE;
		fReturn = TRUE;
	}
	__finally
	{
		if (pCertificateContext) CertFreeCertificateContext(pCertificateContext);
		if (hKey) CryptDestroyKey(hKey);
		if (pbKeyUsage) delete[] pbKeyUsage;
		if (pbBasicConstraints) delete[] pbBasicConstraints;
		if (pbEnhKeyUsage) delete[] pbEnhKeyUsage;
		if (SubjectIssuerBlob.pbData) delete[] SubjectIssuerBlob.pbData;
		if (hProv) CryptReleaseContext(hProv,0);
		if (bDestroyContainer)
		{
			// if a temp container has been created, delete it
			CryptAcquireContext(
				&hProv,
				szContainerName,
				szProvider,
				PROV_RSA_FULL,
				CRYPT_DELETE_KEYSET);
		}
	}
	SetLastError(dwError);
	return fReturn;
}