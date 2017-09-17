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

#define TRACE_LEVEL_CRITICAL 1
#define TRACE_LEVEL_ERROR    2
#define TRACE_LEVEL_WARNING  3
#define TRACE_LEVEL_INFORMATION     4
#define TRACE_LEVEL_VERBOSE  5

void TracingRegister();
void TracingUnRegister();

#define Trace(dwLevel, ...) \
	TraceEx(__FILE__,__LINE__,__FUNCTION__, dwLevel, __VA_ARGS__);

void TraceEx(PCSTR szFile, int iLine, PCSTR szFunction, UCHAR dwLevel, PCWSTR szFormat,...);
