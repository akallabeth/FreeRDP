/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Audio Output Virtual Channel
 *
 * Copyright 2020 Armin Novak <armin.novak@thincast.com>
 * Copyright 2020 Thincast Technologies GmbH
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

#include <winpr/crt.h>
#include <winpr/cmdline.h>
#include <winpr/sysinfo.h>

#include <freerdp/types.h>
#include <freerdp/channels/log.h>

#include "rdpsnd_main.h"

typedef struct rdpsnd_wasapi_plugin rdpsndWinmmPlugin;

struct rdpsnd_wasapi_plugin
{
	rdpsndDevicePlugin device;

	WAVEFORMATEX format;
	UINT32 volume;
	wLog* log;
	UINT32 latency;
	HANDLE semaphore;
};

static BOOL rdpsnd_wasapi_convert_format(const AUDIO_FORMAT* in, WAVEFORMATEX* out)
{
	if (!in || !out)
		return FALSE;

	ZeroMemory(out, sizeof(WAVEFORMATEX));
	out->wFormatTag = WAVE_FORMAT_PCM;
	out->nChannels = in->nChannels;
	out->nSamplesPerSec = in->nSamplesPerSec;

	switch (in->wFormatTag)
	{
		case WAVE_FORMAT_PCM:
			out->wBitsPerSample = in->wBitsPerSample;
			break;

		default:
			return FALSE;
	}

	out->nBlockAlign = out->nChannels * out->wBitsPerSample / 8;
	out->nAvgBytesPerSec = out->nSamplesPerSec * out->nBlockAlign;
	return TRUE;
}

static BOOL rdpsnd_wasapi_set_format(rdpsndDevicePlugin* device, const AUDIO_FORMAT* format,
                                     UINT32 latency)
{
	rdpsndWinmmPlugin* wasapi = (rdpsndWinmmPlugin*)device;

	wasapi->latency = latency;
	if (!rdpsnd_wasapi_convert_format(format, &wasapi->format))
		return FALSE;

	return TRUE;
}

static void CALLBACK waveOutProc(HWAVEOUT hwo, UINT uMsg, DWORD_PTR dwInstance, DWORD_PTR dwParam1,
                                 DWORD_PTR dwParam2)
{
	rdpsndWinmmPlugin* wasapi = (rdpsndWinmmPlugin*)dwInstance;
	LPWAVEHDR lpWaveHdr = (LPWAVEHDR)dwParam1;

	switch (uMsg)
	{
		case WOM_OPEN:
		case WOM_CLOSE:
			break;
		case WOM_DONE:
			waveOutUnprepareHeader(hwo, lpWaveHdr, sizeof(WAVEHDR));
			free(lpWaveHdr);
			ReleaseSemaphore(wasapi->semaphore, 1, NULL);
			break;
		default:
			break;
	}
}

static BOOL rdpsnd_wasapi_open(rdpsndDevicePlugin* device, const AUDIO_FORMAT* format,
                               UINT32 latency)
{
	MMRESULT mmResult;
	rdpsndWinmmPlugin* wasapi = (rdpsndWinmmPlugin*)device;

	if (wasapi->hWaveOut)
		return TRUE;

	if (!rdpsnd_wasapi_set_format(device, format, latency))
		return FALSE;

	mmResult = waveOutOpen(&wasapi->hWaveOut, WAVE_MAPPER, &wasapi->format, (DWORD_PTR)waveOutProc,
	                       (DWORD_PTR)wasapi, CALLBACK_FUNCTION);

	if (mmResult != MMSYSERR_NOERROR)
	{
		WLog_Print(wasapi->log, WLOG_ERROR, "waveOutOpen failed: %" PRIu32 "", mmResult);
		return FALSE;
	}

	ReleaseSemaphore(wasapi->semaphore, SEM_COUNT_MAX, NULL);

	mmResult = waveOutSetVolume(wasapi->hWaveOut, wasapi->volume);

	if (mmResult != MMSYSERR_NOERROR)
	{
		WLog_Print(wasapi->log, WLOG_ERROR, "waveOutSetVolume failed: %" PRIu32 "", mmResult);
		return FALSE;
	}

	return TRUE;
}

static void rdpsnd_wasapi_close(rdpsndDevicePlugin* device)
{
	size_t x;
	MMRESULT mmResult;
	rdpsndWinmmPlugin* wasapi = (rdpsndWinmmPlugin*)device;

	if (wasapi->hWaveOut)
	{
		for (x = 0; x < SEM_COUNT_MAX; x++)
			WaitForSingleObject(wasapi->semaphore, INFINITE);
		mmResult = waveOutClose(wasapi->hWaveOut);
		if (mmResult != MMSYSERR_NOERROR)
			WLog_Print(wasapi->log, WLOG_ERROR, "waveOutClose failure: %" PRIu32 "", mmResult);

		wasapi->hWaveOut = NULL;
	}
}

static void rdpsnd_wasapi_free(rdpsndDevicePlugin* device)
{
	rdpsndWinmmPlugin* wasapi = (rdpsndWinmmPlugin*)device;

	if (wasapi)
	{
		rdpsnd_wasapi_close(device);
		CloseHandle(wasapi->semaphore);
		free(wasapi);
	}
}

static BOOL rdpsnd_wasapi_format_supported(rdpsndDevicePlugin* device, const AUDIO_FORMAT* format)
{
	MMRESULT result;
	WAVEFORMATEX out;

	WINPR_UNUSED(device);
	if (rdpsnd_wasapi_convert_format(format, &out))
	{
		result = waveOutOpen(NULL, WAVE_MAPPER, &out, 0, 0, WAVE_FORMAT_QUERY);

		if (result == MMSYSERR_NOERROR)
			return TRUE;
	}

	return FALSE;
}

static UINT32 rdpsnd_wasapi_get_volume(rdpsndDevicePlugin* device)
{
	MMRESULT mmResult;
	DWORD dwVolume = UINT32_MAX;
	rdpsndWinmmPlugin* wasapi = (rdpsndWinmmPlugin*)device;

	if (!wasapi->hWaveOut)
		return dwVolume;

	mmResult = waveOutGetVolume(wasapi->hWaveOut, &dwVolume);
	if (mmResult != MMSYSERR_NOERROR)
	{
		WLog_Print(wasapi->log, WLOG_ERROR, "waveOutGetVolume failure: %" PRIu32 "", mmResult);
		dwVolume = UINT32_MAX;
	}
	return dwVolume;
}

static BOOL rdpsnd_wasapi_set_volume(rdpsndDevicePlugin* device, UINT32 value)
{
	MMRESULT mmResult;
	rdpsndWinmmPlugin* wasapi = (rdpsndWinmmPlugin*)device;
	wasapi->volume = value;

	if (!wasapi->hWaveOut)
		return TRUE;

	mmResult = waveOutSetVolume(wasapi->hWaveOut, value);
	if (mmResult != MMSYSERR_NOERROR)
	{
		WLog_Print(wasapi->log, WLOG_ERROR, "waveOutGetVolume failure: %" PRIu32 "", mmResult);
		return FALSE;
	}
	return TRUE;
}

static void rdpsnd_wasapi_start(rdpsndDevicePlugin* device)
{
	// rdpsndWinmmPlugin* wasapi = (rdpsndWinmmPlugin*) device;
	WINPR_UNUSED(device);
}

static UINT rdpsnd_wasapi_play(rdpsndDevicePlugin* device, const BYTE* data, size_t size)
{
	MMRESULT mmResult;
	LPWAVEHDR lpWaveHdr;
	rdpsndWinmmPlugin* wasapi = (rdpsndWinmmPlugin*)device;

	if (!wasapi->hWaveOut)
		return 0;

	if (size > UINT32_MAX)
		return 0;

	lpWaveHdr = malloc(sizeof(WAVEHDR));
	if (!lpWaveHdr)
		return 0;

	lpWaveHdr->dwFlags = 0;
	lpWaveHdr->dwLoops = 0;
	lpWaveHdr->lpData = (LPSTR)data;
	lpWaveHdr->dwBufferLength = (DWORD)size;

	mmResult = waveOutPrepareHeader(wasapi->hWaveOut, lpWaveHdr, sizeof(WAVEHDR));

	if (mmResult != MMSYSERR_NOERROR)
	{
		WLog_Print(wasapi->log, WLOG_ERROR, "waveOutPrepareHeader failure: %" PRIu32 "", mmResult);
		free(lpWaveHdr);
		return 0;
	}

	WaitForSingleObject(wasapi->semaphore, INFINITE);
	mmResult = waveOutWrite(wasapi->hWaveOut, lpWaveHdr, sizeof(WAVEHDR));

	if (mmResult != MMSYSERR_NOERROR)
	{
		WLog_Print(wasapi->log, WLOG_ERROR, "waveOutWrite failure: %" PRIu32 "", mmResult);
		waveOutUnprepareHeader(wasapi->hWaveOut, lpWaveHdr, sizeof(WAVEHDR));
		free(lpWaveHdr);
		return 0;
	}

	return wasapi->latency;
}

static void rdpsnd_wasapi_parse_addin_args(rdpsndDevicePlugin* device, ADDIN_ARGV* args)
{
	WINPR_UNUSED(device);
	WINPR_UNUSED(args);
}

#ifdef BUILTIN_CHANNELS
#define freerdp_rdpsnd_client_subsystem_entry wasapi_freerdp_rdpsnd_client_subsystem_entry
#else
#define freerdp_rdpsnd_client_subsystem_entry FREERDP_API freerdp_rdpsnd_client_subsystem_entry
#endif

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
UINT freerdp_rdpsnd_client_subsystem_entry(PFREERDP_RDPSND_DEVICE_ENTRY_POINTS pEntryPoints)
{
	ADDIN_ARGV* args;
	rdpsndWinmmPlugin* wasapi;
	wasapi = (rdpsndWinmmPlugin*)calloc(1, sizeof(rdpsndWinmmPlugin));

	if (!wasapi)
		return CHANNEL_RC_NO_MEMORY;

	if (waveOutGetNumDevs() == 0)
		return ERROR_DEVICE_NOT_AVAILABLE;

	wasapi->device.Open = rdpsnd_wasapi_open;
	wasapi->device.FormatSupported = rdpsnd_wasapi_format_supported;
	wasapi->device.GetVolume = rdpsnd_wasapi_get_volume;
	wasapi->device.SetVolume = rdpsnd_wasapi_set_volume;
	wasapi->device.Start = rdpsnd_wasapi_start;
	wasapi->device.Play = rdpsnd_wasapi_play;
	wasapi->device.Close = rdpsnd_wasapi_close;
	wasapi->device.Free = rdpsnd_wasapi_free;
	wasapi->log = WLog_Get(TAG);
	wasapi->semaphore = CreateSemaphore(NULL, 0, SEM_COUNT_MAX, NULL);
	if (!wasapi->semaphore)
		goto fail;
	args = pEntryPoints->args;
	rdpsnd_wasapi_parse_addin_args((rdpsndDevicePlugin*)wasapi, args);
	wasapi->volume = 0xFFFFFFFF;
	pEntryPoints->pRegisterRdpsndDevice(pEntryPoints->rdpsnd, (rdpsndDevicePlugin*)wasapi);
	return CHANNEL_RC_OK;

fail:
	rdpsnd_wasapi_free((rdpsndDevicePlugin*)wasapi);
	return ERROR_INTERNAL_ERROR;
}
