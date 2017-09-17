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

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN

#include <stdlib.h>
#include <list>
#include <windows.h>
#include <Wincrypt.h>
#include <Winscard.h>
#include <Winsmcrd.h>
#include <Evntrace.h>
#include <tchar.h>
#include "cspsdk.h"
#include "tracing.h"
#include "constants.h"
#include "Container.h"
#include "Card.h"
#include "OpenPGPCardv2.h"
#include "OpenPGPCardv3.h"
#include "PINDialog.h"
#include "ChangePINDialog.h"
#include "SelectOpenPGPv2KeyDialog.h"
#include "SelectOpenPGPv3KeyDialog.h"
#include "resource.h"


extern HINSTANCE g_hInst;
typedef   void  (WINAPI *CRYPT_RETURN_HWND)(HWND *phWnd);
extern CRYPT_RETURN_HWND GetHWND;

#define CSPNAME "OpenPGP CSP"

// fix ntdsapi.h - WINAPI missing
#define RtlEncryptMemory                SystemFunction040
#define RtlDecryptMemory                SystemFunction041

EXTERN_C NTSTATUS WINAPI
RtlEncryptMemory(
    _Inout_updates_bytes_(MemorySize) PVOID Memory,
    _In_ ULONG MemorySize,
    _In_ ULONG OptionFlags
    );

EXTERN_C NTSTATUS WINAPI
RtlDecryptMemory(
    _Inout_updates_bytes_(MemorySize) PVOID Memory,
    _In_ ULONG MemorySize,
    _In_ ULONG OptionFlags
    );


typedef struct _RSAPUBLICKEYBLOB
{
	BLOBHEADER blobheader;
	RSAPUBKEY rsapubkey;
	BYTE modulus[sizeof(DWORD)];
} RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;

typedef struct _PLAINTEXTKEYBLOB 
{
	BLOBHEADER blobheader;
	DWORD      dwKeySize;
	BYTE       rgbKeyData[sizeof(DWORD)];
} PLAINTEXTKEYBLOBTYPE, *PPLAINTEXTKEYBLOBTYPE;

typedef struct _SIMPLEKEYBLOB 
{
	BLOBHEADER blobheader;
	ALG_ID algid;
	BYTE encryptedkey[sizeof(DWORD)];
} SIMPLEKEYBLOBTYPE, *PSIMPLEKEYBLOBTYPE;
