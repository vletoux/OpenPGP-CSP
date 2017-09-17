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

#include "stdafx.h"

/** called to re-select the Openpgp application when a SCARD_W_RESET occured */
DWORD Card::Reconnect()
{
	DWORD     dwAP;
	DWORD dwReturn;
	__try
	{
		// reset the card
		Trace(TRACE_LEVEL_VERBOSE, L"Enter");
		dwReturn = SCardReconnect(hScard,
                         SCARD_SHARE_SHARED,
                         SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                         SCARD_LEAVE_CARD,
                         &dwAP );
		if (dwReturn)
		{
			Trace(TRACE_LEVEL_ERROR, L"SCardReconnect 0x%08X", dwReturn);
			__leave;
		}

		dwReturn = Reinit();
	}
	__finally
	{
	}
	return dwReturn;
}

/** send a command to the smart card with no response expected */
DWORD Card::SendCommand(__in PBYTE pbCmd, __in DWORD dwCmdSize)
{
	DWORD             dwReturn = 0;

	BYTE     recvbuf[256];
	DWORD     recvlen = sizeof(recvbuf);
	BYTE              SW1, SW2;
	__try
	{
		TraceAPDUIn(pbCmd, dwCmdSize);
		dwReturn = SCardTransmit(hScard, 
									SCARD_PCI_T1, 
									pbCmd, 
									dwCmdSize, 
									NULL, 
									recvbuf, 
									&recvlen);
		TraceAPDUOut(dwReturn, recvbuf, recvlen);
		if ( dwReturn != SCARD_S_SUCCESS )
		{
			if (dwReturn == SCARD_W_RESET_CARD)
			{
				dwReturn = Reconnect();
				if (dwReturn)
				{
					__leave;
				}
				dwReturn = SendCommand(pbCmd, dwCmdSize);
				__leave;
			}
			Trace(TRACE_LEVEL_ERROR, L"SCardTransmit errorcode: [0x%02X]", dwReturn);
			__leave;
		}
		SW1 = recvbuf[recvlen-2];
		SW2 = recvbuf[recvlen-1];
		if ( (SW1 == 0x6A) && (SW2 == 0x88) )
		{
			Trace(TRACE_LEVEL_ERROR, L"card reset");
			recvlen = sizeof(recvbuf);
			dwReturn = Reinit();
			if (dwReturn)
			{
				__leave;
			}
			TraceAPDUIn(pbCmd, dwCmdSize);
			dwReturn = SCardTransmit(hScard, 
									SCARD_PCI_T1, 
									pbCmd, 
									dwCmdSize, 
									NULL, 
									recvbuf, 
									&recvlen);
			TraceAPDUOut(dwReturn, recvbuf, recvlen);
			SW1 = recvbuf[recvlen-2];
			SW2 = recvbuf[recvlen-1];
		}
		if ( ( SW1 == 0x90 ) && ( SW2 == 0x00 ) )
		{

		}
		else if ( (SW1 == 0x69) && (SW2 == 0x82) )
		{
			Trace(TRACE_LEVEL_ERROR, L"SCARD_W_WRONG_CHV");
			dwReturn = SCARD_W_WRONG_CHV;
			__leave;
		}
		else if ( (SW1 == 0x69) && (SW2 == 0x83) )
		{
			Trace(TRACE_LEVEL_ERROR, L"SCARD_W_CHV_BLOCKED");
			dwReturn = SCARD_W_CHV_BLOCKED;
			__leave;
		}
		else if ( (SW1 == 0x69) && (SW2 == 0x85) )
		{
			Trace(TRACE_LEVEL_ERROR, L"SCARD_W_SECURITY_VIOLATION");
			dwReturn = SCARD_W_SECURITY_VIOLATION;
			__leave;
		}
		else
		{
			TraceDump(TRACE_LEVEL_ERROR, pbCmd,dwCmdSize);
			Trace(TRACE_LEVEL_ERROR, L"SW1=0x%02X SW2=0x%02X", SW1, SW2);
			dwReturn = SCARD_F_UNKNOWN_ERROR;
			__leave;
		}
	}
	__finally
	{
	}
	return dwReturn;
}


DWORD Card::Reinit()
{
	return 0;
}



/** send a command to the smart card with response expected */
DWORD Card::GetData(
					__in PBYTE pbCmd, __in DWORD dwCmdSize,
					__out PBYTE* pbResponse, __out PDWORD pdwResponseSize)
{

	DWORD dwReturn;
	BYTE pbGetResponse[] = {0x00, 
				    0xC0,
					0x00,
					0x00,
					0x00
					};
	DWORD dwGetResponseSize = ARRAYSIZE(pbGetResponse);
	BYTE			recvbuf[0x800];
	DWORD			recvlen = sizeof(recvbuf);
	BYTE            SW1, SW2;
	DWORD			dwDataSize = 0;
	__try
	{

		*pbResponse = NULL;
		TraceAPDUIn(pbCmd, dwCmdSize);
		dwReturn = SCardTransmit(hScard, 
									SCARD_PCI_T1, 
									pbCmd, 
									dwCmdSize, 
									NULL, 
									recvbuf, 
									&recvlen);
		TraceAPDUOut(dwReturn, recvbuf, recvlen);
		do
		{
			if ( dwReturn != SCARD_S_SUCCESS )
			{
				if (dwReturn == SCARD_W_RESET_CARD)
				{
					dwReturn = Reconnect();
					if (dwReturn)
					{
						__leave;
					}
					dwReturn = GetData(pbCmd, dwCmdSize,pbResponse, pdwResponseSize);
					__leave;
				}
				Trace(TRACE_LEVEL_ERROR, L"SCardTransmit errorcode: [0x%02X]", dwReturn);
				__leave;
			}
			SW1 = recvbuf[recvlen-2];
			SW2 = recvbuf[recvlen-1];
			if ( (SW1 == 0x6A) && (SW2 == 0x88) )
			{
				Trace(TRACE_LEVEL_ERROR, L"card reset");
				recvlen = sizeof(recvbuf);
				dwReturn = Reinit();
				if (dwReturn)
				{
					__leave;
				}
				TraceAPDUIn(pbCmd, dwCmdSize);
				dwReturn = SCardTransmit(hScard, 
									SCARD_PCI_T1, 
									pbCmd, 
									dwCmdSize, 
									NULL, 
									recvbuf, 
									&recvlen);
				TraceAPDUOut(dwReturn, recvbuf, recvlen);
				SW1 = recvbuf[recvlen-2];
				SW2 = recvbuf[recvlen-1];
			}
			if ( ( SW1 == 0x90 ) && ( SW2 == 0x00 ) )
			{
				dwDataSize = recvlen-2;
				*pbResponse = (BYTE*) malloc(dwDataSize);
				if (! *pbResponse)
				{
					Trace(TRACE_LEVEL_ERROR, L"SCARD_E_NO_MEMORY");
					dwReturn = SCARD_E_NO_MEMORY;
					__leave;
				}
				memcpy(*pbResponse, recvbuf, dwDataSize);
			}
			else if (SW1 == 0x61)
			{
				PBYTE old = *pbResponse;
				dwDataSize += SW2;
				if (*pbResponse)
				{
					PBYTE old = *pbResponse;
					*pbResponse = (BYTE*) realloc(*pbResponse, dwDataSize);
				}
				else
				{
					*pbResponse = (BYTE*) malloc(dwDataSize);
				}
				if (! *pbResponse)
				{
					Trace(TRACE_LEVEL_ERROR, L"SCARD_E_NO_MEMORY");
					if (old) free(old);
					dwReturn = SCARD_E_NO_MEMORY;
					__leave;
				}
				dwGetResponseSize = ARRAYSIZE(pbGetResponse);
				TraceAPDUIn(pbCmd, dwCmdSize);
				dwReturn = SCardTransmit(hScard, 
									SCARD_PCI_T1, 
									pbGetResponse, 
									dwGetResponseSize, 
									NULL, 
									recvbuf, 
									&recvlen);
				TraceAPDUOut(dwReturn, recvbuf, recvlen);
			}
			else if ( (SW1 == 0x69) && (SW2 == 0x82) )
			{
				Trace(TRACE_LEVEL_ERROR, L"SCARD_W_WRONG_CHV");
				dwReturn = SCARD_W_WRONG_CHV;
				__leave;
			}
			else if ( (SW1 == 0x69) && (SW2 == 0x83) )
			{
				Trace(TRACE_LEVEL_ERROR, L"SCARD_W_CHV_BLOCKED");
				dwReturn = SCARD_W_CHV_BLOCKED;
				__leave;
			}
			else if ( (SW1 == 0x69) && (SW2 == 0x85) )
			{
				Trace(TRACE_LEVEL_ERROR, L"SCARD_W_SECURITY_VIOLATION");
				dwReturn = SCARD_W_SECURITY_VIOLATION;
				__leave;
			}
			else
			{
				TraceDump(TRACE_LEVEL_ERROR, pbCmd,dwCmdSize);
				Trace(TRACE_LEVEL_ERROR, L"SW1=0x%02X SW2=0x%02X", SW1, SW2);
				dwReturn = SCARD_F_UNKNOWN_ERROR;
				__leave;
			}

		} while (SW1 == 0x61);
		if (pdwResponseSize)
		{
			*pdwResponseSize = dwDataSize;
		}
	}
	__finally
	{
	}
	return dwReturn;
}

DWORD Card::DecodeReturnCode(BYTE SW1, BYTE SW2)
{
	DWORD dwReturn = ERROR_SUCCESS;
	if ( ( SW1 == 0x90 ) && ( SW2 == 0x00 ) )
	{

	}
	else if ( (SW1 == 0x69) && (SW2 == 0x82) )
	{
		Trace(TRACE_LEVEL_ERROR, L"SCARD_W_WRONG_CHV");
		dwReturn = SCARD_W_WRONG_CHV;
	}
	else if ( (SW1 == 0x69) && (SW2 == 0x83) )
	{
		Trace(TRACE_LEVEL_ERROR, L"SCARD_W_CHV_BLOCKED");
		dwReturn = SCARD_W_CHV_BLOCKED;
	}
	else if ( (SW1 == 0x69) && (SW2 == 0x85) )
	{
		Trace(TRACE_LEVEL_ERROR, L"SCARD_W_SECURITY_VIOLATION");
		dwReturn = SCARD_W_SECURITY_VIOLATION;
	}
	else if ( (SW1 == 0x6A) && (SW2 == 0x82) )
	{
		Trace(TRACE_LEVEL_ERROR, L"ERROR_FILE_NOT_FOUND");
		dwReturn = ERROR_FILE_NOT_FOUND;
	}
	else if ( (SW1 == 0x6A) && (SW2 == 0x86) )
	{
		Trace(TRACE_LEVEL_ERROR, L"ERROR_DIR_NOT_EMPTY");
		dwReturn = ERROR_DIR_NOT_EMPTY ;
	}
	else if ( (SW1 == 0x6A) && (SW2 == 0x87) )
	{
		Trace(TRACE_LEVEL_ERROR, L"SCARD_E_DIR_NOT_FOUND");
		dwReturn = SCARD_E_DIR_NOT_FOUND;
	}
	else if ( (SW1 == 0x6A) && (SW2 == 0x88) )
	{
		Trace(TRACE_LEVEL_ERROR, L"SCARD_E_FILE_NOT_FOUND");
		dwReturn = SCARD_E_FILE_NOT_FOUND;
	}
	else if ( (SW1 == 0x6A) && (SW2 == 0x89) )
	{
		Trace(TRACE_LEVEL_ERROR, L"ERROR_FILE_EXISTS");
		dwReturn = ERROR_FILE_EXISTS;
	}
	else if ( (SW1 == 0x67) && (SW2 == 0x00) )
	{
		Trace(TRACE_LEVEL_ERROR, L"SCARD_E_INVALID_PARAMETER");
		dwReturn = SCARD_E_INVALID_PARAMETER;
	}
	else if ( (SW1 == 0x6A) && (SW2 == 0x84) )
	{
		Trace(TRACE_LEVEL_ERROR, L"SCARD_E_WRITE_TOO_MANY");
		dwReturn = SCARD_E_WRITE_TOO_MANY ;
	}
	else
	{
		Trace(TRACE_LEVEL_ERROR, L"SW1=0x%02X SW2=0x%02X", SW1, SW2);
		dwReturn = SCARD_F_UNKNOWN_ERROR;
	}
	return dwReturn;
}

/*
DWORD CCIDfindFeature(BYTE featureTag, BYTE* features, DWORD featuresLength) 
{
    DWORD idx = 0;
    int count;
    while (idx < featuresLength) {
        BYTE tag = features[idx];
        idx++;
        idx++;
        if (featureTag == tag) {
            DWORD feature = 0;
            for (count = 0; count < 3; count++) {
                feature |= features[idx] & 0xff;
                idx++;
                feature <<= 8;
            }
            feature |= features[idx] & 0xff;
            return feature;
        }
        idx += 4;
    }
    return 0;
}

DWORD CCIDgetFeatures(__in PCARD_DATA  pCardData) 
{
	BYTE pbRecvBuffer[200];
	DWORD dwRecvLength, dwReturn;
	__try
	{
		POPENPGP_CONTEXT pContext = (POPENPGP_CONTEXT) pCardData->pvVendorSpecific;

		pContext->SmartCardReaderFeatures.VERIFY_PIN_START = 0;
		pContext->SmartCardReaderFeatures.VERIFY_PIN_FINISH = 0;
		pContext->SmartCardReaderFeatures.VERIFY_PIN_DIRECT = 0;
		pContext->SmartCardReaderFeatures.MODIFY_PIN_START = 0;
		pContext->SmartCardReaderFeatures.MODIFY_PIN_FINISH = 0;
		pContext->SmartCardReaderFeatures.MODIFY_PIN_DIRECT = 0;
		pContext->SmartCardReaderFeatures.GET_KEY_PRESSED = 0;
		pContext->SmartCardReaderFeatures.ABORT = 0;

		dwReturn = SCardControl(pCardData->hScard, 
			SCARD_CTL_CODE(3400),
			NULL,
			0,
			pbRecvBuffer,
			sizeof(pbRecvBuffer),
			&dwRecvLength);
		if ( dwReturn ) 
		{
			Trace(TRACE_LEVEL_ERROR, L"SCardControl errorcode: [0x%02X]", dwReturn);
			__leave;
		}
		pContext->SmartCardReaderFeatures.VERIFY_PIN_START = CCIDfindFeature(FEATURE_VERIFY_PIN_START, pbRecvBuffer, dwRecvLength);
		pContext->SmartCardReaderFeatures.VERIFY_PIN_FINISH = CCIDfindFeature(FEATURE_VERIFY_PIN_FINISH, pbRecvBuffer, dwRecvLength);
		pContext->SmartCardReaderFeatures.VERIFY_PIN_DIRECT = CCIDfindFeature(FEATURE_VERIFY_PIN_DIRECT, pbRecvBuffer, dwRecvLength);
		pContext->SmartCardReaderFeatures.MODIFY_PIN_START = CCIDfindFeature(FEATURE_MODIFY_PIN_START, pbRecvBuffer, dwRecvLength);
		pContext->SmartCardReaderFeatures.MODIFY_PIN_FINISH = CCIDfindFeature(FEATURE_MODIFY_PIN_FINISH, pbRecvBuffer, dwRecvLength);
		pContext->SmartCardReaderFeatures.MODIFY_PIN_DIRECT = CCIDfindFeature(FEATURE_MODIFY_PIN_DIRECT, pbRecvBuffer, dwRecvLength);
		pContext->SmartCardReaderFeatures.GET_KEY_PRESSED = CCIDfindFeature(FEATURE_GET_KEY_PRESSED, pbRecvBuffer, dwRecvLength);
		pContext->SmartCardReaderFeatures.ABORT = CCIDfindFeature(FEATURE_ABORT, pbRecvBuffer, dwRecvLength);
	}
	__finally
	{
	}
   return dwReturn;
}
*/

BOOL Card::MatchATR(SCARDHANDLE hSCard, SCARD_ATRMASK AtrToCheck)
{
	DWORD dwReaderSize = 0, dwState,dwProtocol;
	DWORD dwAtrLen = SCARD_ATR_LENGTH;
	BYTE pbAtr[SCARD_ATR_LENGTH];
	DWORD dwStatus = SCardStatus(hSCard, NULL, &dwReaderSize, &dwState, &dwProtocol, pbAtr, &dwAtrLen);
	if (dwStatus != 0)
	{
		Trace(TRACE_LEVEL_ERROR, L"SCardStatus = %08X", dwStatus);
		return FALSE;
	}
	if (AtrToCheck.cbAtr != dwAtrLen)
	{
		return FALSE;
	}
	for( DWORD dwI = 0; dwI < AtrToCheck.cbAtr; dwI++)
	{
		pbAtr[dwI] &= AtrToCheck.rgbMask[dwI];
	}
	if (memcmp(pbAtr, AtrToCheck.rgbAtr, AtrToCheck.cbAtr) == 0)
	{
		return TRUE;
	}
	return FALSE;
}