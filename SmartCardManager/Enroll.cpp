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
#include <CertEnroll.h>
#include <XEnroll.h>
#include <CertSrv.h>

BOOL Is_Vista_or_Later () 
{
   OSVERSIONINFOEX osvi;
   DWORDLONG dwlConditionMask = 0;
   BYTE op=VER_GREATER_EQUAL;

   // Initialize the OSVERSIONINFOEX structure.

   ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
   osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
   osvi.dwMajorVersion = 6;

   // Initialize the condition mask.
   VER_SET_CONDITION( dwlConditionMask, VER_MAJORVERSION,  op );

   // Perform the test.
   return VerifyVersionInfo(
      &osvi, 
      VER_MAJORVERSION,
      dwlConditionMask);
}

HRESULT Enroll(HWND hWnd)
{
	HRESULT hr = S_OK;
	BSTR bstrTemplate = SysAllocString(L"SmartcardLogon");
	BSTR bstrCspName = SysAllocString(szProvider);
	BSTR bstrRequest = NULL;
	BSTR bstrCAConfig = NULL;
	BSTR bstrCertificate = NULL;
	// create certiticate Vista
	IX509Enrollment *pEnroll = NULL;
	IX509CertificateRequestPkcs10 *pRequest = NULL;
	IX509PrivateKey *pPrivateKey = NULL;
	// create certificate XP
	IEnroll4* pEnroll4 = NULL;
	VARIANT varFullResp;
	CRYPT_DATA_BLOB pBlob = {0};
	PWSTR szRequest = NULL;
	// submit certificate
	ICertRequest2* pCertRequest = NULL;
	ICertConfig* pCertConfig = NULL;
	__try
	{
		// initialize COM
		VariantInit(&varFullResp);
		hr = CoInitializeEx( NULL, COINIT_APARTMENTTHREADED );
		if (FAILED(hr))
		{
			Trace(TRACE_LEVEL_ERROR, L"CoInitializeEx failed 0x%08X",hr);
			__leave;
		}
		if (Is_Vista_or_Later())
		{
			Trace(TRACE_LEVEL_INFORMATION, L"Vista and later enrollement type");
			hr = CoCreateInstance( CLSID_CX509CertificateRequestPkcs10,
								   NULL,
								   CLSCTX_INPROC_SERVER,
								   IID_IX509CertificateRequestPkcs10,
								   (void **)&pRequest);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"CoCreateInstance IID_IX509CertificateRequestPkcs10 failed 0x%08X",hr);
				__leave;
			}
			hr = pRequest->InitializeFromTemplateName(ContextUser,bstrTemplate);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"InitializeFromTemplateName failed 0x%08X",hr);
				__leave;
			}
		
			hr = pRequest->get_PrivateKey(&pPrivateKey);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"get_PrivateKey failed 0x%08X",hr);
				__leave;
			}
			hr = pPrivateKey->put_ProviderName(bstrCspName);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"put_ProviderName failed 0x%08X",hr);
				__leave;
			}
			hr = pPrivateKey->put_KeySpec(XCN_AT_KEYEXCHANGE);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"put_KeySpec failed 0x%08X",hr);
				__leave;
			}
			hr = pPrivateKey->put_KeyUsage(XCN_NCRYPT_ALLOW_ALL_USAGES);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"put_KeyUsage failed 0x%08X",hr);
				__leave;
			}
			hr = pPrivateKey->put_MachineContext(FALSE);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"put_MachineContext failed 0x%08X",hr);
				__leave;
			}
			hr = pPrivateKey->put_Length(2048);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"put_Length failed 0x%08X",hr);
				__leave;
			}
#pragma warning(push)
#pragma warning(disable:4311)
#pragma warning(disable:4302)
			hr = pPrivateKey->put_ParentWindow((LONG)hWnd);
#pragma warning(pop)
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"put_ParentWindow failed 0x%08X",hr);
				__leave;
			}
			hr = CoCreateInstance( CLSID_CX509Enrollment,
								   NULL,
								   CLSCTX_INPROC_SERVER,
								   IID_IX509Enrollment,
								   (void **)&pEnroll);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"CoCreateInstance IID_IX509Enrollment failed 0x%08X",hr);
				__leave;
			}
			hr = pEnroll->InitializeFromRequest(pRequest);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"InitializeFromRequest failed 0x%08X",hr);
				__leave;
			}
			hr = pEnroll->CreateRequest(XCN_CRYPT_STRING_BASE64, &bstrRequest);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"CreateRequest failed 0x%08X",hr);
				__leave;
			}
		}
		else
		{
			Trace(TRACE_LEVEL_INFORMATION, L"Windows XP enrollement type");
			hr = CoCreateInstance( CLSID_CEnroll,
							   NULL,
							   CLSCTX_INPROC_SERVER,
							   IID_IEnroll4,
							   (void **)&pEnroll4);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"CoCreateInstance IID_IEnroll4 failed 0x%08X",hr);
				__leave;
			}
			hr = pEnroll4->put_ProviderNameWStr(szProvider);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"put_ProviderNameWStr failed 0x%08X",hr);
				__leave;
			}
			hr = pEnroll4->put_KeySpec(AT_KEYEXCHANGE);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"put_KeySpec failed 0x%08X",hr);
				__leave;
			}
			hr = pEnroll4->put_ProviderType(PROV_RSA_FULL);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"put_KeySpec failed 0x%08X",hr);
				__leave;
			}
			hr = pEnroll4->put_GenKeyFlags(2048 << 16);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"put_Length failed 0x%08X",hr);
				__leave;
			}
			hr = pEnroll4->AddCertTypeToRequestWStr(bstrTemplate);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"AddCertTypeToRequestWStr failed 0x%08X",hr);
				__leave;
			}
						Trace(TRACE_LEVEL_ERROR,L"A");

			hr = pEnroll4->createRequestWStr(XECR_PKCS10_V1_5, NULL, NULL, &pBlob);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"CreateRequest failed 0x%08X",hr);
				__leave;
			}
			hr = pEnroll4->binaryBlobToString(CRYPT_STRING_BASE64,&pBlob, &szRequest);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"binaryBlobToString failed 0x%08X",hr);
				__leave;
			}
			bstrRequest = SysAllocString(szRequest);
			if (!bstrRequest)
			{
				Trace(TRACE_LEVEL_ERROR,L"OUT OF MEMORY bstrRequest");
				hr = E_OUTOFMEMORY;
				__leave;
			}
		}
		hr = CoCreateInstance( CLSID_CCertConfig,
							   NULL,
							   CLSCTX_INPROC_SERVER,
							   IID_ICertConfig,
							   (void **)&pCertConfig);
		if (FAILED(hr))
		{
			Trace(TRACE_LEVEL_ERROR, L"CoCreateInstance IID_ICertConfig failed 0x%08X",hr);
			__leave;
		}
		hr = pCertConfig->GetConfig(CC_UIPICKCONFIG, &bstrCAConfig);
		if (FAILED(hr))
		{
			Trace(TRACE_LEVEL_ERROR, L"GetConfig failed 0x%08X",hr);
			__leave;
		}
		// do something with the PKCS10 (bstrReq);
		LONG Disp;

		hr = CoCreateInstance(CLSID_CCertRequest, NULL, CLSCTX_INPROC_SERVER, IID_ICertRequest2, (PVOID*) &pCertRequest);
		if (FAILED(hr))
		{
			Trace(TRACE_LEVEL_ERROR, L"CoCreateInstance IID_ICertRequest2 failed 0x%08X",hr);
			__leave;
		}
		hr = pCertRequest->Submit(CR_IN_ENCODEANY | CR_IN_FORMATANY, bstrRequest, NULL, bstrCAConfig, &Disp);
		if (FAILED(hr))
		{
			Trace(TRACE_LEVEL_ERROR, L"Submit failed 0x%08X",hr);
			__leave;
		}
		switch(Disp)
		{
		case CR_DISP_ISSUED:
			Trace(TRACE_LEVEL_INFORMATION, L"certificate CR_DISP_ISSUED");
			break;
		case CR_DISP_DENIED:
			hr = E_ACCESSDENIED;
			Trace(TRACE_LEVEL_INFORMATION, L"Access denied for certificate request from the CA");
			__leave;
		default:
			hr = E_UNEXPECTED;
			Trace(TRACE_LEVEL_ERROR, L"Disp != CR_DISP_ISSUED 0x%08X",Disp);
			__leave;
		}
		
		if (Is_Vista_or_Later())
		{
			hr = pCertRequest->GetCertificate(CR_OUT_BASE64 | CR_OUT_CHAIN, &bstrCertificate);
			if (FAILED(hr))
			{

				Trace(TRACE_LEVEL_ERROR, L"GetFullResponseProperty failed 0x%08X",hr);
				__leave;
			} 
			hr = pEnroll->InstallResponse(AllowUntrustedRoot, bstrCertificate, XCN_CRYPT_STRING_BASE64, NULL);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"InstallResponse failed 0x%08X",hr);
				__leave;
			}
		}
		else
		{
			Trace(TRACE_LEVEL_ERROR,L"1");
			CRYPT_DATA_BLOB certBlob = {0};
			hr = pCertRequest->GetFullResponseProperty(FR_PROP_FULLRESPONSE, 0, PROPTYPE_BINARY, CR_OUT_BINARY, &varFullResp);
			if (FAILED(hr))
			{

				Trace(TRACE_LEVEL_ERROR, L"GetFullResponseProperty failed 0x%08X",hr);
				__leave;
			}
			Trace(TRACE_LEVEL_ERROR,L"2");
			certBlob.cbData = SysStringByteLen(varFullResp.bstrVal);
			certBlob.pbData = (PBYTE) varFullResp.bstrVal;
			hr = pEnroll4->acceptResponseBlob(&certBlob);
			if (FAILED(hr))
			{
				Trace(TRACE_LEVEL_ERROR, L"InstallResponse failed 0x%08X",hr);
				__leave;
			}
			Trace(TRACE_LEVEL_ERROR,L"3");
		}
	}
	__finally
	{
		//clean up resources, etc.
		VariantClear(&varFullResp);
		if (szRequest) LocalFree(szRequest);
		if (pBlob.pbData) CoTaskMemFree(pBlob.pbData);
		if (bstrCspName) SysFreeString(bstrCspName);
		if (bstrTemplate) SysFreeString(bstrTemplate);
		if (bstrRequest) SysFreeString(bstrRequest);
		if (bstrCAConfig) SysFreeString(bstrCAConfig);
		if (bstrCertificate) SysFreeString(bstrCertificate);
		if (pEnroll) pEnroll->Release();
		if (pRequest) pRequest->Release();
		if (pPrivateKey) pPrivateKey->Release();
		if (pCertRequest) pCertRequest->Release();
		if (pCertConfig) pCertConfig->Release();
		CoUninitialize();
	}
	return hr;
}