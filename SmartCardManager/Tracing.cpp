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

#include <Windows.h>
#include <Wmistr.h>
#include <Evntrace.h>
#include <stdio.h>
#include <tchar.h>

#define INITGUID
#include <guiddef.h>

// to enable tracing in kernel debugger, issue the following command in windbg : ed nt!Kd_DEFAULT_MASK  0xFFFFFFFF
// OR
// Open up the registry and go to this path,
// HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter 
// and add the following value "DEFAULT" : REG_DWORD : 0xFFFFFFFF and then reboot

// new GUID to generate for each component
// {6E8E0049-A205-4524-9E25-7AD3E8A5A2F2}
DEFINE_GUID(TracingGuid, 
0x6e8e0049, 0xa205, 0x4524, 0x9e, 0x25, 0x7a, 0xd3, 0xe8, 0xa5, 0xa2, 0xf2);

// define the number of parallel session handled
#define MAX_NUM_TRACING_SESSION 10

TRACEHANDLE hRegistration = 0;
BOOL          g_bTracingEnabled                        = FALSE;
TRACEHANDLE   g_SessionHandle[MAX_NUM_TRACING_SESSION] = {0}; // The handle to the session that enabled the provider.
UCHAR         g_EnableLevel[MAX_NUM_TRACING_SESSION]   = {0}; // Determines the severity of events to log.


#ifdef _DEBUG
BOOL fDebugOutputIsEnabled = TRUE;
#else
BOOL fDebugOutputIsEnabled = FALSE;
#endif

// The callback function that receives enable/disable notifications
// from one or more ETW sessions. 

ULONG WINAPI ControlCallback(
    WMIDPREQUESTCODE RequestCode,
    PVOID Context,
    ULONG* Reserved, 
    PVOID Header
    )
{
	ULONG status = ERROR_SUCCESS;
    TRACEHANDLE TempSessionHandle = 0; 
	int i;
    UNREFERENCED_PARAMETER(RequestCode);
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Reserved);
    switch (RequestCode)
    {
        case WMI_ENABLE_EVENTS:  // Enable the provider.
        {
#ifdef _DEBUG
			OutputDebugString(TEXT("ControlCallback called with WMI_ENABLE_EVENTS\r\n"));
#endif
			SetLastError(0);

            // If the provider is already enabled to a provider, ignore 
            // the request. Get the session handle of the enabling session.
            // You need the session handle to call the TraceEvent function.
            // The session could be enabling the provider or it could be
            // updating the level and enable flags.

            TempSessionHandle = GetTraceLoggerHandle(Header);
            if (INVALID_HANDLE_VALUE == (HANDLE)TempSessionHandle)
            {
                TCHAR szMessage[1024];
				_stprintf_s(szMessage,ARRAYSIZE(szMessage),TEXT("GetTraceLoggerHandle failed. Error code is %lu.\n"), status = GetLastError());
				OutputDebugString(szMessage);
                break;
            }
			// if no tracing session is available, nothing is done
			for (i = 0; i < MAX_NUM_TRACING_SESSION; i++)
			{
				if (g_SessionHandle[i] == 0 || g_SessionHandle[i] == TempSessionHandle)
				{
					// Get the severity level of the events that the
					// session wants you to log.
					g_SessionHandle[i] = TempSessionHandle;
					g_EnableLevel[i] = GetTraceEnableLevel(TempSessionHandle); 
					g_bTracingEnabled = TRUE;
#ifdef _DEBUG
					TCHAR szMessage[256];
					_stprintf_s(szMessage, TEXT("Provider %d activated with level %d (handle=0x%IX)\r\n"),i,g_EnableLevel[i], TempSessionHandle);
					OutputDebugString(szMessage);
#endif
					break;
				}
			}
            break;
        }
 
        case WMI_DISABLE_EVENTS:  // Disable the provider.
        {
#ifdef _DEBUG
			OutputDebugString(TEXT("ControlCallback called with WMI_DISABLE_EVENTS\r\n"));
#endif
            // Disable the provider only if the request is coming from the
            // session that enabled the provider.

            TempSessionHandle = GetTraceLoggerHandle(Header);
            if (INVALID_HANDLE_VALUE == (HANDLE)TempSessionHandle)
            {
                TCHAR szMessage[1024];
				_stprintf_s(szMessage,ARRAYSIZE(szMessage), TEXT("GetTraceLoggerHandle failed. Error code is %lu.\n"), status = GetLastError());
				OutputDebugString(szMessage);
                break;
            }
			// clear the session if found
			for (i = 0; i < MAX_NUM_TRACING_SESSION; i++)
			{
				if (g_SessionHandle[i] == TempSessionHandle)
				{
					g_SessionHandle[i] = 0;
				}
            }
			g_bTracingEnabled = FALSE;

			for (i = 0; i < MAX_NUM_TRACING_SESSION; i++)
			{
				if (g_SessionHandle[i] != 0)
				{
					g_bTracingEnabled = TRUE;
					break;
				}
			}
            break;
        }

        default:
        {
#ifdef _DEBUG
			OutputDebugString(TEXT("ControlCallback called with other\r\n"));
#endif
			status = ERROR_INVALID_PARAMETER;
            break;
        }
    }

    return status;
}

// called to setup the tracing context
void TracingRegister() 
{
	TRACE_GUID_REGISTRATION registration = {&TracingGuid,0};
	ULONG code = RegisterTraceGuids(
			ControlCallback,
			NULL,
			&TracingGuid, 
			1, &registration, NULL, 
			NULL,
			&hRegistration);
	if (code)
	{
#ifdef _DEBUG
		TCHAR szMessage[256];
		_stprintf_s(szMessage,TEXT("EventRegister failed 0x%08X\r\n"), code);
		OutputDebugString(szMessage);
#endif
	}
}

// called to clean up the tracing context
void TracingUnRegister() 
{
	if (hRegistration)
	{
		if (UnregisterTraceGuids(hRegistration))
		{
#ifdef _DEBUG
			OutputDebugString(L"EventUnregister failed\r\n");
#endif
		}
	}
	hRegistration = 0;
}

typedef struct _event
{
    EVENT_TRACE_HEADER Header;
    MOF_FIELD Data[MAX_MOF_FIELDS];  // Event-specific data
} MY_EVENT, *PMY_EVENT;

#define MY_EVENT_TYPE 1
#define EVENT_DATA_FIELDS_CNT  1

// write to the event log
VOID TraceWriteString(
	__in UCHAR Level,
	__in PCWSTR String
	)
{
	MY_EVENT MyEvent; 
	ULONG status;
	int i;
	if (g_bTracingEnabled)
	{
		for (i = 0; i < MAX_NUM_TRACING_SESSION; i++)
		{
			if (g_SessionHandle[i] != 0  &&  (0 == g_EnableLevel[i] || Level <= g_EnableLevel[i]))
			{
				// Initialize the event data structure.

				ZeroMemory(&MyEvent, sizeof(MY_EVENT));
				MyEvent.Header.Size = sizeof(EVENT_TRACE_HEADER) + (sizeof(MOF_FIELD) * EVENT_DATA_FIELDS_CNT);
				MyEvent.Header.Flags = WNODE_FLAG_TRACED_GUID | WNODE_FLAG_USE_MOF_PTR;
				MyEvent.Header.Guid = TracingGuid;
				MyEvent.Header.Class.Type = MY_EVENT_TYPE;
				MyEvent.Header.Class.Version = 1;
				MyEvent.Header.Class.Level = Level;

				// Load the event data. 
				DEFINE_TRACE_MOF_FIELD(&MyEvent.Data[0],(ULONG64) String,(ULONG) (sizeof(WCHAR) * (1 + wcslen(String))),ETW_STRING_TYPE_VALUE);

				// Write the event.
				status = TraceEvent(g_SessionHandle[i], &(MyEvent.Header));
#ifdef _DEBUG
				if (ERROR_SUCCESS != status)
				{
					OutputDebugString(L"TraceEvent failed\r\n");
				}
#endif
			}
		}
	}
}

// main tracing function
void TraceEx(LPCSTR szFile, int iLine, LPCSTR szFunction, UCHAR dwLevel, PCWSTR szFormat,...) 
{
	WCHAR Buffer[1024];
	WCHAR Buffer2[1024+256];
	int ret;
	va_list ap;
#ifndef _DEBUG
	UNREFERENCED_PARAMETER(iLine);
	UNREFERENCED_PARAMETER(szFile);
#endif

	if ( g_bTracingEnabled || fDebugOutputIsEnabled) {

		va_start (ap, szFormat);
		ret = _vsnwprintf_s (Buffer, ARRAYSIZE(Buffer), _TRUNCATE, szFormat, ap);
		va_end (ap);
		if (ret <= 0) return;
		if (ret > ARRAYSIZE(Buffer)) ret = ARRAYSIZE(Buffer)-1;
		Buffer[ARRAYSIZE(Buffer)-1] = L'\0';
		if (fDebugOutputIsEnabled)
		{
			swprintf_s(Buffer2,ARRAYSIZE(Buffer2),L"%S(%d) : %S - %s\r\n",szFile,iLine,szFunction,Buffer);
			OutputDebugString(Buffer2);
		}
		if (g_bTracingEnabled)
		{
			swprintf_s(Buffer2,ARRAYSIZE(Buffer2),L"%S(%d) : %s",szFunction,iLine,Buffer);
			TraceWriteString(dwLevel, Buffer2);
		}
	}
}