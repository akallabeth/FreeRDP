/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Audio Input Redirection Virtual Channel - WinMM implementation
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
#include <freerdp/addin.h>
#include <freerdp/client/audin.h>

#include "audin_main.h"

typedef struct _AudinWinmmDevice
{
	IAudinDevice iface;

	char* device_name;
	AudinReceive receive;
	void* user_data;
	HANDLE thread;
	HANDLE stopEvent;
	HWAVEIN hWaveIn;
	PWAVEFORMATEX* ppwfx;
	PWAVEFORMATEX pwfx_cur;
	UINT32 ppwfx_size;
	UINT32 cFormats;
	UINT32 frames_per_packet;
	rdpContext* rdpcontext;
	wLog* log;
} AudinWinmmDevice;

static DWORD WINAPI audin_wasapi_thread_func(LPVOID arg)
{
	AudinWinmmDevice* wasapi = (AudinWinmmDevice*)arg;
	char* buffer;
	int size, i;
	WAVEHDR waveHdr[4];
	DWORD status;
	MMRESULT rc;

	if (!wasapi->hWaveIn)
	{
		if (MMSYSERR_NOERROR != waveInOpen(&wasapi->hWaveIn, WAVE_MAPPER, wasapi->pwfx_cur,
		                                   (DWORD_PTR)waveInProc, (DWORD_PTR)wasapi,
		                                   CALLBACK_FUNCTION))
		{
			if (wasapi->rdpcontext)
				setChannelError(wasapi->rdpcontext, ERROR_INTERNAL_ERROR,
				                "audin_wasapi_thread_func reported an error");

			return ERROR_INTERNAL_ERROR;
		}
	}

	size = (wasapi->pwfx_cur->wBitsPerSample * wasapi->pwfx_cur->nChannels *
	            wasapi->frames_per_packet +
	        7) /
	       8;

	for (i = 0; i < 4; i++)
	{
		buffer = (char*)malloc(size);

		if (!buffer)
			return CHANNEL_RC_NO_MEMORY;

		waveHdr[i].dwBufferLength = size;
		waveHdr[i].dwFlags = 0;
		waveHdr[i].lpData = buffer;
		rc = waveInPrepareHeader(wasapi->hWaveIn, &waveHdr[i], sizeof(waveHdr[i]));

		if (MMSYSERR_NOERROR != rc)
		{
			WLog_Print(wasapi->log, WLOG_DEBUG, "waveInPrepareHeader failed. %" PRIu32 "", rc);

			if (wasapi->rdpcontext)
				setChannelError(wasapi->rdpcontext, ERROR_INTERNAL_ERROR,
				                "audin_wasapi_thread_func reported an error");
		}

		rc = waveInAddBuffer(wasapi->hWaveIn, &waveHdr[i], sizeof(waveHdr[i]));

		if (MMSYSERR_NOERROR != rc)
		{
			WLog_Print(wasapi->log, WLOG_DEBUG, "waveInAddBuffer failed. %" PRIu32 "", rc);

			if (wasapi->rdpcontext)
				setChannelError(wasapi->rdpcontext, ERROR_INTERNAL_ERROR,
				                "audin_wasapi_thread_func reported an error");
		}
	}

	rc = waveInStart(wasapi->hWaveIn);

	if (MMSYSERR_NOERROR != rc)
	{
		WLog_Print(wasapi->log, WLOG_DEBUG, "waveInStart failed. %" PRIu32 "", rc);

		if (wasapi->rdpcontext)
			setChannelError(wasapi->rdpcontext, ERROR_INTERNAL_ERROR,
			                "audin_wasapi_thread_func reported an error");
	}

	status = WaitForSingleObject(wasapi->stopEvent, INFINITE);

	if (status == WAIT_FAILED)
	{
		WLog_Print(wasapi->log, WLOG_DEBUG, "WaitForSingleObject failed.");

		if (wasapi->rdpcontext)
			setChannelError(wasapi->rdpcontext, ERROR_INTERNAL_ERROR,
			                "audin_wasapi_thread_func reported an error");
	}

	rc = waveInReset(wasapi->hWaveIn);

	if (MMSYSERR_NOERROR != rc)
	{
		WLog_Print(wasapi->log, WLOG_DEBUG, "waveInReset failed. %" PRIu32 "", rc);

		if (wasapi->rdpcontext)
			setChannelError(wasapi->rdpcontext, ERROR_INTERNAL_ERROR,
			                "audin_wasapi_thread_func reported an error");
	}

	for (i = 0; i < 4; i++)
	{
		rc = waveInUnprepareHeader(wasapi->hWaveIn, &waveHdr[i], sizeof(waveHdr[i]));

		if (MMSYSERR_NOERROR != rc)
		{
			WLog_Print(wasapi->log, WLOG_DEBUG, "waveInUnprepareHeader failed. %" PRIu32 "", rc);

			if (wasapi->rdpcontext)
				setChannelError(wasapi->rdpcontext, ERROR_INTERNAL_ERROR,
				                "audin_wasapi_thread_func reported an error");
		}

		free(waveHdr[i].lpData);
	}

	rc = waveInClose(wasapi->hWaveIn);

	if (MMSYSERR_NOERROR != rc)
	{
		WLog_Print(wasapi->log, WLOG_DEBUG, "waveInClose failed. %" PRIu32 "", rc);

		if (wasapi->rdpcontext)
			setChannelError(wasapi->rdpcontext, ERROR_INTERNAL_ERROR,
			                "audin_wasapi_thread_func reported an error");
	}

	wasapi->hWaveIn = NULL;
	return 0;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT audin_wasapi_free(IAudinDevice* device)
{
	UINT32 i;
	AudinWinmmDevice* wasapi = (AudinWinmmDevice*)device;

	if (!wasapi)
		return ERROR_INVALID_PARAMETER;

	for (i = 0; i < wasapi->cFormats; i++)
	{
		free(wasapi->ppwfx[i]);
	}

	free(wasapi->ppwfx);
	free(wasapi->device_name);
	free(wasapi);
	return CHANNEL_RC_OK;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT audin_wasapi_close(IAudinDevice* device)
{
	DWORD status;
	UINT error = CHANNEL_RC_OK;
	AudinWinmmDevice* wasapi = (AudinWinmmDevice*)device;

	if (!wasapi)
		return ERROR_INVALID_PARAMETER;

	SetEvent(wasapi->stopEvent);
	status = WaitForSingleObject(wasapi->thread, INFINITE);

	if (status == WAIT_FAILED)
	{
		error = GetLastError();
		WLog_Print(wasapi->log, WLOG_ERROR, "WaitForSingleObject failed with error %" PRIu32 "!",
		           error);
		return error;
	}

	CloseHandle(wasapi->thread);
	CloseHandle(wasapi->stopEvent);
	wasapi->thread = NULL;
	wasapi->stopEvent = NULL;
	wasapi->receive = NULL;
	wasapi->user_data = NULL;
	return error;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT audin_wasapi_set_format(IAudinDevice* device, const AUDIO_FORMAT* format,
                                    UINT32 FramesPerPacket)
{
	UINT32 i;
	AudinWinmmDevice* wasapi = (AudinWinmmDevice*)device;

	if (!wasapi || !format)
		return ERROR_INVALID_PARAMETER;

	wasapi->frames_per_packet = FramesPerPacket;

	for (i = 0; i < wasapi->cFormats; i++)
	{
		if (wasapi->ppwfx[i]->wFormatTag == format->wFormatTag &&
		    wasapi->ppwfx[i]->nChannels == format->nChannels &&
		    wasapi->ppwfx[i]->wBitsPerSample == format->wBitsPerSample)
		{
			wasapi->pwfx_cur = wasapi->ppwfx[i];
			break;
		}
	}

	return CHANNEL_RC_OK;
}

static BOOL audin_wasapi_format_supported(IAudinDevice* device, const AUDIO_FORMAT* format)
{
	AudinWinmmDevice* wasapi = (AudinWinmmDevice*)device;
	PWAVEFORMATEX pwfx;
	BYTE* data;

	if (!wasapi || !format)
		return FALSE;

	pwfx = (PWAVEFORMATEX)malloc(sizeof(WAVEFORMATEX) + format->cbSize);

	if (!pwfx)
		return FALSE;

	pwfx->cbSize = format->cbSize;
	pwfx->wFormatTag = format->wFormatTag;
	pwfx->nChannels = format->nChannels;
	pwfx->nSamplesPerSec = format->nSamplesPerSec;
	pwfx->nBlockAlign = format->nBlockAlign;
	pwfx->wBitsPerSample = format->wBitsPerSample;
	data = (BYTE*)pwfx + sizeof(WAVEFORMATEX);
	memcpy(data, format->data, format->cbSize);

	if (pwfx->wFormatTag == WAVE_FORMAT_PCM)
	{
		pwfx->nAvgBytesPerSec = pwfx->nSamplesPerSec * pwfx->nBlockAlign;

		if (MMSYSERR_NOERROR == waveInOpen(NULL, WAVE_MAPPER, pwfx, 0, 0, WAVE_FORMAT_QUERY))
		{
			if (wasapi->cFormats >= wasapi->ppwfx_size)
			{
				PWAVEFORMATEX* tmp_ppwfx;
				tmp_ppwfx = realloc(wasapi->ppwfx, sizeof(PWAVEFORMATEX) * wasapi->ppwfx_size * 2);

				if (!tmp_ppwfx)
					return FALSE;

				wasapi->ppwfx_size *= 2;
				wasapi->ppwfx = tmp_ppwfx;
			}

			wasapi->ppwfx[wasapi->cFormats++] = pwfx;
			return TRUE;
		}
	}

	free(pwfx);
	return FALSE;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT audin_wasapi_open(IAudinDevice* device, AudinReceive receive, void* user_data)
{
	AudinWinmmDevice* wasapi = (AudinWinmmDevice*)device;

	if (!wasapi || !receive || !user_data)
		return ERROR_INVALID_PARAMETER;

	wasapi->receive = receive;
	wasapi->user_data = user_data;

	if (!(wasapi->stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL)))
	{
		WLog_Print(wasapi->log, WLOG_ERROR, "CreateEvent failed!");
		return ERROR_INTERNAL_ERROR;
	}

	if (!(wasapi->thread = CreateThread(NULL, 0, audin_wasapi_thread_func, wasapi, 0, NULL)))
	{
		WLog_Print(wasapi->log, WLOG_ERROR, "CreateThread failed!");
		CloseHandle(wasapi->stopEvent);
		wasapi->stopEvent = NULL;
		return ERROR_INTERNAL_ERROR;
	}

	return CHANNEL_RC_OK;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT audin_wasapi_parse_addin_args(AudinWinmmDevice* device, ADDIN_ARGV* args)
{
	int status;
	DWORD flags;
	COMMAND_LINE_ARGUMENT_A* arg;
	AudinWinmmDevice* wasapi = (AudinWinmmDevice*)device;
	COMMAND_LINE_ARGUMENT_A audin_wasapi_args[] = { { "dev", COMMAND_LINE_VALUE_REQUIRED,
		                                              "<device>", NULL, NULL, -1, NULL,
		                                              "audio device name" },
		                                            { NULL, 0, NULL, NULL, NULL, -1, NULL, NULL } };

	flags =
	    COMMAND_LINE_SIGIL_NONE | COMMAND_LINE_SEPARATOR_COLON | COMMAND_LINE_IGN_UNKNOWN_KEYWORD;
	status = CommandLineParseArgumentsA(args->argc, args->argv, audin_wasapi_args, flags, wasapi,
	                                    NULL, NULL);
	arg = audin_wasapi_args;

	do
	{
		if (!(arg->Flags & COMMAND_LINE_VALUE_PRESENT))
			continue;

		CommandLineSwitchStart(arg) CommandLineSwitchCase(arg, "dev")
		{
			wasapi->device_name = _strdup(arg->Value);

			if (!wasapi->device_name)
			{
				WLog_Print(wasapi->log, WLOG_ERROR, "_strdup failed!");
				return CHANNEL_RC_NO_MEMORY;
			}
		}
		CommandLineSwitchEnd(arg)
	} while ((arg = CommandLineFindNextArgumentA(arg)) != NULL);

	return CHANNEL_RC_OK;
}

#ifdef BUILTIN_CHANNELS
#define freerdp_audin_client_subsystem_entry wasapi_freerdp_audin_client_subsystem_entry
#else
#define freerdp_audin_client_subsystem_entry FREERDP_API freerdp_audin_client_subsystem_entry
#endif

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
UINT freerdp_audin_client_subsystem_entry(PFREERDP_AUDIN_DEVICE_ENTRY_POINTS pEntryPoints)
{
	ADDIN_ARGV* args;
	AudinWinmmDevice* wasapi;
	UINT error;

	if (waveInGetNumDevs() == 0)
		return ERROR_DEVICE_NOT_AVAILABLE;

	wasapi = (AudinWinmmDevice*)calloc(1, sizeof(AudinWinmmDevice));

	if (!wasapi)
	{
		WLog_ERR(TAG, "calloc failed!");
		return CHANNEL_RC_NO_MEMORY;
	}

	wasapi->log = WLog_Get(TAG);
	wasapi->iface.Open = audin_wasapi_open;
	wasapi->iface.FormatSupported = audin_wasapi_format_supported;
	wasapi->iface.SetFormat = audin_wasapi_set_format;
	wasapi->iface.Close = audin_wasapi_close;
	wasapi->iface.Free = audin_wasapi_free;
	wasapi->rdpcontext = pEntryPoints->rdpcontext;
	args = pEntryPoints->args;

	if ((error = audin_wasapi_parse_addin_args(wasapi, args)))
	{
		WLog_Print(wasapi->log, WLOG_ERROR,
		           "audin_wasapi_parse_addin_args failed with error %" PRIu32 "!", error);
		goto error_out;
	}

	if (!wasapi->device_name)
	{
		wasapi->device_name = _strdup("default");

		if (!wasapi->device_name)
		{
			WLog_Print(wasapi->log, WLOG_ERROR, "_strdup failed!");
			error = CHANNEL_RC_NO_MEMORY;
			goto error_out;
		}
	}

	wasapi->ppwfx_size = 10;
	wasapi->ppwfx = malloc(sizeof(PWAVEFORMATEX) * wasapi->ppwfx_size);

	if (!wasapi->ppwfx)
	{
		WLog_Print(wasapi->log, WLOG_ERROR, "malloc failed!");
		error = CHANNEL_RC_NO_MEMORY;
		goto error_out;
	}

	if ((error = pEntryPoints->pRegisterAudinDevice(pEntryPoints->plugin, (IAudinDevice*)wasapi)))
	{
		WLog_Print(wasapi->log, WLOG_ERROR, "RegisterAudinDevice failed with error %" PRIu32 "!",
		           error);
		goto error_out;
	}

	return CHANNEL_RC_OK;
error_out:
	free(wasapi->ppwfx);
	free(wasapi->device_name);
	free(wasapi);
	return error;
}
