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

#pragma comment(lib,"Winscard")
#pragma comment(lib,"Crypt32")
#pragma comment(lib,"Scarddlg")
#pragma comment(lib,"Rpcrt4")
#pragma comment(lib,"AdvAPI32")
#ifdef _WIN64
#pragma comment(lib, "..\\lib\\bcrypt_x64")
#else
#pragma comment(lib, "..\\lib\\bcrypt_x86")
#endif