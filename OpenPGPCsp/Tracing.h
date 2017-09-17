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
/**
 *  Tracing function.
 */



/*
TRACE_LEVEL_CRITICAL Abnormal exit or termination events.
TRACE_LEVEL_ERROR Severe error events.
TRACE_LEVEL_WARNING Warning events such as allocation failures.
TRACE_LEVEL_INFO Non-error events such as entry or exit events.
TRACE_LEVEL_VERBOSE Detailed trace events.
*/

#pragma once

#define TRACE_LEVEL_CRITICAL 1
#define TRACE_LEVEL_ERROR    2
#define TRACE_LEVEL_WARNING  3
#define TRACE_LEVEL_INFO     4
#define TRACE_LEVEL_VERBOSE  5

void TracingRegister();
void TracingUnRegister();

#define Trace(dwLevel, ...) \
	TraceEx(__FILE__,__LINE__,__FUNCTION__, dwLevel, __VA_ARGS__);

void TraceEx(__in LPCSTR szFile, __in int iLine, __in LPCSTR szFunction, __in UCHAR dwLevel, __format_string PCWSTR szFormat,...);


void TraceDumpEx(LPCSTR szFile, DWORD dwLine, LPCSTR szFunction, UCHAR dwLevel,
			   __in PBYTE pbCmd, __in DWORD dwCmdSize);

#define TraceDump(dwLevel, pbCmd,dwCmdSize) \
	TraceDumpEx(__FILE__,__LINE__,__FUNCTION__, dwLevel, pbCmd,dwCmdSize);

void TraceAPDUInEx(LPCSTR szFile, DWORD dwLine, LPCSTR szFunction, __in PBYTE pbCmd, __in DWORD dwCmdSize);

#define TraceAPDUIn(pbCmd,dwCmdSize) \
	TraceAPDUInEx(__FILE__,__LINE__,__FUNCTION__, pbCmd,dwCmdSize);

void TraceAPDUOutEx(LPCSTR szFile, DWORD dwLine, LPCSTR szFunction, __in DWORD dwReturn, __in PBYTE pbCmd, __in DWORD dwCmdSize);

#define TraceAPDUOut(dwReturn, pbCmd,dwCmdSize) \
	TraceAPDUOutEx(__FILE__,__LINE__,__FUNCTION__, dwReturn, pbCmd,dwCmdSize);