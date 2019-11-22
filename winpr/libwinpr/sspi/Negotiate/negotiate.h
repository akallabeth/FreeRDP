/**
 * WinPR: Windows Portable Runtime
 * Negotiate Security Package
 *
 * Copyright 2011-2012 Jiten Pathy
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WINPR_SSPI_NEGOTIATE_PRIVATE_H
#define WINPR_SSPI_NEGOTIATE_PRIVATE_H

#include <winpr/sspi.h>

extern const CHAR NEGOTIATE_PACKAGE_NAME_A[];
extern const WCHAR NEGOTIATE_PACKAGE_NAME_W[];

extern const SecPkgInfoA NEGOTIATE_SecPkgInfoA;
extern const SecPkgInfoW NEGOTIATE_SecPkgInfoW;
extern const SecurityFunctionTableA NEGOTIATE_SecurityFunctionTableA;
extern const SecurityFunctionTableW NEGOTIATE_SecurityFunctionTableW;

#endif /* WINPR_SSPI_NEGOTIATE_PRIVATE_H */
