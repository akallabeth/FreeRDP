/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Drive Virtual Channel
 *
 * Copyright 2024 Armin Novak <armin.novak@gmail.com>
 * Copyright 2024 Thincast Technologies GmbH
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

#pragma once

#include <freerdp/channels/rdpdr.h>

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct rdp_drive_driver rdpDriveDriver;
	typedef struct rdp_drive_context rdpDriveContext;

	struct rdp_drive_driver
	{
		rdpDriveContext* (*new)(rdpContext* context);
		void (*free)(rdpDriveContext*);

		bool (*setPath)(rdpDriveContext* context, const WCHAR* base_path, const WCHAR* filename);
		bool (*createDirectory)(rdpDriveContext* context);
		bool (*createFile)(rdpDriveContext* context, UINT32 dwDesiredAccess, UINT32 dwShareMode,
		                   UINT32 dwCreationDisposition, UINT32 dwFlagsAndAttributes);

		SSIZE_T (*seek)(rdpDriveContext* context, SSIZE_T offset, int whence);
		SSIZE_T (*read)(rdpDriveContext* context, void* buf, size_t nbyte);
		SSIZE_T (*write)(rdpDriveContext* context, const void* buf, size_t nbyte);
		bool (*remove)(rdpDriveContext* context);
		bool (*move)(rdpDriveContext* context, const WCHAR* newName, size_t numCharacters);
		bool (*exists)(rdpDriveContext* context);
		bool (*empty)(rdpDriveContext* context);
		bool (*setSize)(rdpDriveContext* context, INT64 size);

		UINT32 (*getFileAttributes)(rdpDriveContext* context);
		bool (*setFileAttributesAndTimes)(rdpDriveContext* context, UINT64 CreationTime,
		                                  UINT64 LastAccessTime, UINT64 LastWriteTime,
		                                  UINT64 ChangeTime, UINT32 dwFileAttributes);

		const WIN32_FIND_DATAW* (*first)(rdpDriveContext* context, const WCHAR* query,
		                                 size_t numCharacters);
		const WIN32_FIND_DATAW* (*next)(rdpDriveContext* context);

		const BY_HANDLE_FILE_INFORMATION* (*getFileAttributeData)(rdpDriveContext* context);
	};

#ifdef __cplusplus
}
#endif
