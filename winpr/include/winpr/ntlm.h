/**
 * WinPR: Windows Portable Runtime
 * NTLM Utils
 *
 * Copyright 2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

#ifndef WINPR_UTILS_NTLM_H
#define WINPR_UTILS_NTLM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winpr/winpr.h>
#include <winpr/wtypes.h>
#include <winpr/sspi.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef SECURITY_STATUS(*psPeerComputeNtlmHash)(void* client,
        const PSEC_WINNT_AUTH_IDENTITY_OPAQUE authIdentity,
        const SecBuffer* ntproofvalue, const BYTE* randkey, const BYTE* mic, const SecBuffer* micvalue,
        BYTE* ntlmhash);

WINPR_API BOOL NTOWFv1W(LPCWSTR Password, UINT32 PasswordLength, BYTE* NtHash);
WINPR_API BOOL NTOWFv1A(LPCSTR Password, UINT32 PasswordLength, BYTE* NtHash);

WINPR_API BOOL NTOWFv2W(LPCWSTR Password, UINT32 PasswordLength, LPCWSTR User,
                        UINT32 UserLength, LPCWSTR Domain, UINT32 DomainLength, BYTE* NtHash);
WINPR_API BOOL NTOWFv2A(LPCSTR Password, UINT32 PasswordLength, LPCSTR User,
                        UINT32 UserLength, LPCSTR Domain, UINT32 DomainLength, BYTE* NtHash);

WINPR_API BOOL NTOWFv2FromHashW(const BYTE* NtHashV1, LPCWSTR User, UINT32 UserLength,
                                LPCWSTR Domain, UINT32 DomainLength, BYTE* NtHash);
WINPR_API BOOL NTOWFv2FromHashA(const BYTE* NtHashV1, LPCSTR User, UINT32 UserLength,
                                LPCSTR Domain, UINT32 DomainLength, BYTE* NtHash);

#ifdef __cplusplus
}
#endif

#ifdef UNICODE
#define NTOWFv1 		NTOWFv1W
#define NTOWFv2 		NTOWFv2W
#define NTOWFv2FromHash		NTOWFv2FromHashW
#else
#define NTOWFv1 		NTOWFv1A
#define NTOWFv2 		NTOWFv2A
#define NTOWFv2FromHash		NTOWFv2FromHashA
#endif

#endif /* WINPR_UTILS_NTLM_H */

