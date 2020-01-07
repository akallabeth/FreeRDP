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
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <endpointvolume.h>
#include <comdef.h>
#include <initguid.h>

#include <winpr/crt.h>
#include <winpr/cmdline.h>
#include <winpr/sysinfo.h>

#include <freerdp/types.h>
#include <freerdp/channels/log.h>

#include "rdpsnd_main.h"

#define SAFE_RELEASE(punk) \
	if ((punk) != NULL) \
	{ \
		(punk)->Release(); \
		(punk) = NULL; \
	}

typedef struct rdpsnd_wasapi_plugin rdpsndWasapiPlugin;

struct rdpsnd_wasapi_plugin
{
	rdpsndDevicePlugin device;

	IMMDeviceEnumerator *pEnumerator;
	IMMDevice *pDevice;
	IAudioClient *pAudioClient;
	IAudioRenderClient *pRenderClient;
	WAVEFORMATEX *pwfx;
	IAudioEndpointVolume* ifcVolume;

	BOOL started;
	WAVEFORMATEX format;
	UINT32 volume;
	wLog* log;
	UINT32 latency;
};

static BOOL check_call_success(const char* fkt, HRESULT hr)
{
	if (FAILED(hr))
	{
		_com_error err(hr);
		_bstr_t b(err.ErrorMessage());
		_bstr_t e(err.Description());
		const char* c = b;
		const char* ec = e;
		WLog_ERR(TAG, "%s failed with %s [%s]", fkt, c, ec);
		return FALSE;
	}

	return TRUE;
}

static BOOL rdpsnd_wasapi_convert_format(const AUDIO_FORMAT* in, WAVEFORMATEX* out)
{
	if (!in || !out)
		return FALSE;

	out->cbSize = in->cbSize;
	out->nChannels = in->nChannels;
	out->wFormatTag = in->wFormatTag;
	out->nBlockAlign = in->nBlockAlign;
	out->nSamplesPerSec = in->nSamplesPerSec;
	out->nAvgBytesPerSec = in->nAvgBytesPerSec;

	return TRUE;
}

static BOOL rdpsnd_wasapi_set_format(rdpsndDevicePlugin* device, const AUDIO_FORMAT* format,
                                     UINT32 latency)
{
    rdpsndWasapiPlugin* wasapi = (rdpsndWasapiPlugin*)device;

	wasapi->latency = latency;
	if (!rdpsnd_wasapi_convert_format(format, &wasapi->format))
		return FALSE;

	return TRUE;
}

static BOOL rdpsnd_wasapi_open(rdpsndDevicePlugin* device, const AUDIO_FORMAT* format,
                               UINT32 latency)
{
	if (!rdpsnd_wasapi_set_format(device, format, latency))
		return FALSE;

	return TRUE;
}

static void rdpsnd_wasapi_close(rdpsndDevicePlugin* device)
{
	HRESULT hr;
	rdpsndWasapiPlugin* wasapi = (rdpsndWasapiPlugin*)device;

	hr = wasapi->pAudioClient->Stop();
	check_call_success("pAudioClient->Stop()", hr);
	wasapi->started = FALSE;
}

static void rdpsnd_wasapi_free(rdpsndDevicePlugin* device)
{
	rdpsndWasapiPlugin* wasapi = (rdpsndWasapiPlugin*)device;

	if (wasapi)
	{
		rdpsnd_wasapi_close(device);
		CoTaskMemFree(wasapi->pwfx);
		SAFE_RELEASE(wasapi->pEnumerator)
		SAFE_RELEASE(wasapi->pDevice)
		SAFE_RELEASE(wasapi->pAudioClient)
		SAFE_RELEASE(wasapi->pRenderClient)
		free(wasapi);
	}
}

static BOOL rdpsnd_wasapi_format_supported(rdpsndDevicePlugin* device, const AUDIO_FORMAT* format)
{
	WAVEFORMATEX out;
	WAVEFORMATEX* closest = NULL;
	rdpsndWasapiPlugin* wasapi = (rdpsndWasapiPlugin*)device;

	if (rdpsnd_wasapi_convert_format(format, &out))
	{
		BOOL match;
		HRESULT hr = wasapi->pAudioClient->IsFormatSupported(AUDCLNT_SHAREMODE_SHARED, &out, &closest);
		CoTaskMemFree(closest);
		switch(hr)
		{
			case S_OK:
				match = TRUE;
				break;
			case S_FALSE:
				match = FALSE;
				break;
			default:
				match = FALSE;
				break;
		}

		if(match)
			return TRUE;
	}

	return FALSE;
}

static UINT32 rdpsnd_wasapi_get_volume(rdpsndDevicePlugin* device)
{
	HRESULT hr;
	BOOL mute;
	float volume;
	DWORD dwVolume = UINT32_MAX;
	rdpsndWasapiPlugin* wasapi = (rdpsndWasapiPlugin*)device;

	if (!wasapi->ifcVolume)
		return dwVolume;

	hr = wasapi->ifcVolume->GetMute(&mute);
	check_call_success("ifcVolume->GetMute()", hr);
	hr = wasapi->ifcVolume->GetMasterVolumeLevel(&volume);
	check_call_success("ifcVolume->GetMasterVolumeLevel()", hr);
	// TODO

	return dwVolume;
}

static BOOL rdpsnd_wasapi_set_volume(rdpsndDevicePlugin* device, UINT32 value)
{
	HRESULT hr;
	float volume;
	BOOL mute;
	rdpsndWasapiPlugin* wasapi = (rdpsndWasapiPlugin*)device;
	GUID guidMute, guidVolume;
	hr = CoCreateGuid( &guidMute );
	check_call_success("CoCreateGuid()", hr);
	hr = CoCreateGuid( &guidVolume );
	check_call_success("CoCreateGuid()", hr);

	wasapi->volume = value;

	if (!wasapi->ifcVolume)
		return TRUE;

	// TODO
	mute = value == 0;
	volume = value / 0x10000 * 100.0f;
	hr = wasapi->ifcVolume->SetMute(mute, &guidMute);
	check_call_success("ifcVolume->SetMute()", hr);
	hr = wasapi->ifcVolume->SetMasterVolumeLevelScalar(volume, &guidVolume);
	check_call_success("ifcVolume->SetMasterVolumeLevelScalar()", hr);

	return TRUE;
}

static BOOL rdpsnd_fill_buffer(rdpsndWasapiPlugin* wasapi, const BYTE* data, UINT32 size)
{
	UINT32 frames;
	HRESULT hr = wasapi->pAudioClient->GetBufferSize(&frames);
	if (!check_call_success("pAudioClient->GetBufferSize()", hr))
		goto fail;
	if (size == 0)
		size = frames;

	while(size > 0)
	{
		UINT32 padding, available, use;
		BYTE* bufferData;


		hr = wasapi->pAudioClient->GetCurrentPadding(&padding);
		if (!check_call_success("pAudioClient->GetCurrentPadding()", hr))
			goto fail;
		available = frames - padding;
		if (available < size)
			use = available;
		else
			use = size;

		if (use == 0)
			continue;

		hr = wasapi->pRenderClient->GetBuffer(use, &bufferData);
		if (!check_call_success("pRenderClient->GetBuffer()", hr))
			goto fail;
		if (data)
			memcpy(bufferData, data, use);
		else
			memset(bufferData, 0, use);

		hr = wasapi->pRenderClient->ReleaseBuffer(use, 0);
		if (!check_call_success("pRenderClient->ReleaseBuffer()", hr))
			goto fail;
		size -= use;
		data += use;
	}

	return TRUE;
	fail:
		return FALSE;
}
static BOOL rdpsnd_wasapi_start(rdpsndDevicePlugin* device)
{
	HRESULT hr;
	rdpsndWasapiPlugin* wasapi = (rdpsndWasapiPlugin*) device;

	if (wasapi->started)
	{
		WLog_WARN(TAG, "rdpsnd_wasapi_start() called on already running device");
		return TRUE;
	}

	rdpsnd_fill_buffer(wasapi, NULL, 0);
	hr = wasapi->pAudioClient->Start();
	if (!check_call_success("pAudioClient->Start()", hr))
		return FALSE;

	wasapi->started = TRUE;
	return TRUE;
}

static UINT rdpsnd_wasapi_play(rdpsndDevicePlugin* device, const BYTE* data, size_t size)
{
	HRESULT hr;
	REFERENCE_TIME latency; /* 100ns */
	rdpsndWasapiPlugin* wasapi = (rdpsndWasapiPlugin*)device;

	if (!wasapi->started)
	{
		if (!rdpsnd_wasapi_start(&wasapi->device))
			return 0;
	}

	if (size > UINT32_MAX)
		return 0;

	if (!rdpsnd_fill_buffer(wasapi, data, (UINT32)size))
		return 0;

	hr = wasapi->pAudioClient->GetStreamLatency(&latency);
	if (!check_call_success("pAudioClient->GetStreamLatency()", hr))
		goto fail;

	fail:
		return wasapi->latency + (UINT)(latency / 10000);
}

static BOOL rdpsnd_wasapi_parse_addin_args(rdpsndWasapiPlugin* wasapi, ADDIN_ARGV* args)
{
	WINPR_UNUSED(wasapi);
	WINPR_UNUSED(args);

	return TRUE;
}

static BOOL initWaveEx(WAVEFORMATEX ** wave)
{
	UINT BitResolution = 16;
	UINT SampleRate = 48000;
	const GUID		PcmSubformatGuid = {STATIC_KSDATAFORMAT_SUBTYPE_PCM};
	WAVEFORMATEXTENSIBLE* ex;

	if (!wave)
		return FALSE;
	ex = (WAVEFORMATEXTENSIBLE*)calloc(1, sizeof(WAVEFORMATEXTENSIBLE));
	if (!ex)
		return FALSE;

	ex->Format.nChannels = 2;
	ex->Format.nSamplesPerSec = SampleRate;
	ex->Format.wBitsPerSample = ex->Samples.wValidBitsPerSample = BitResolution;
	ex->Format.nBlockAlign = 2 * (BitResolution/8);
	if (BitResolution == 24)
	{
		ex->Format.wBitsPerSample = 32;
		ex->Format.nBlockAlign = 2 * (32/8);
	}
	CopyMemory(&ex->SubFormat, &PcmSubformatGuid, sizeof(GUID));
	ex->Format.nAvgBytesPerSec = SampleRate * ex->Format.nBlockAlign;

	ex->Format.wFormatTag = WAVE_FORMAT_EXTENSIBLE;
	ex->Format.cbSize = 22;
	*wave = &ex->Format;
	return TRUE;
}

static BOOL freerdp_rdpsnd_open_device(rdpsndWasapiPlugin* wasapi)
{
	HRESULT hr;
	WAVEFORMATEX* closest = NULL;
	REFERENCE_TIME minDuration, defaultDuration;
	const CLSID lCLSID_MMDeviceEnumerator = __uuidof(MMDeviceEnumerator);
	const IID lIID_IMMDeviceEnumerator = __uuidof(IMMDeviceEnumerator);
	const IID lIID_IAudioClient = __uuidof(IAudioClient);
	const IID lIID_IAudioRenderClient = __uuidof(IAudioRenderClient);

	hr = CoCreateInstance(lCLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL, lIID_IMMDeviceEnumerator, (void**)&wasapi->pEnumerator);
	if (!check_call_success("CoCreateInstance()", hr))
		goto fail;
	hr = wasapi->pEnumerator->GetDefaultAudioEndpoint(eRender, eConsole, &wasapi->pDevice);
	if (!check_call_success("pEnumerator->GetDefaultAudioEndpoint()", hr))
		goto fail;
	hr = wasapi->pDevice->Activate(
		lIID_IAudioClient, CLSCTX_ALL,
		NULL, (void**)&wasapi->pAudioClient);
	if (!check_call_success("pDevice->Activate()", hr))
		goto fail;

#if 0
	hr = wasapi->pAudioClient->GetMixFormat(&wasapi->pwfx);
	if (!check_call_success("pAudioClient->GetMixFormat()", hr))
		goto fail;
#else
	initWaveEx(&wasapi->pwfx);
#endif
	hr = wasapi->pAudioClient->IsFormatSupported(AUDCLNT_SHAREMODE_SHARED, wasapi->pwfx, &closest);
	CoTaskMemFree(closest);
	if (!check_call_success("pAudioClient->IsFormatSupported()", hr))
		goto fail;
	hr = wasapi->pAudioClient->GetDevicePeriod(&defaultDuration, &minDuration);
	if (!check_call_success("pAudioClient->GetDevicePeriod()", hr))
		goto fail;
	hr = wasapi->pAudioClient->Initialize(
		AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM,// | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY | AUDCLNT_STREAMFLAGS_RATEADJUST,
		minDuration, minDuration,
		wasapi->pwfx,
		NULL);
	if (!check_call_success("pAudioClient->Initialize()", hr))
		goto fail;
	hr = wasapi->pAudioClient->GetService(
		lIID_IAudioRenderClient,
		(void**)&wasapi->pRenderClient);
	if (!check_call_success("pAudioClient->GetService()", hr))
		goto fail;
	return TRUE;

	fail:
		return FALSE;
}

#ifdef BUILTIN_CHANNELS
#define freerdp_rdpsnd_client_subsystem_entry wasapi_freerdp_rdpsnd_client_subsystem_entry
#else
#define freerdp_rdpsnd_client_subsystem_entry FREERDP_API freerdp_rdpsnd_client_subsystem_entry
#endif

EXTERN_C_START
/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
UINT freerdp_rdpsnd_client_subsystem_entry(PFREERDP_RDPSND_DEVICE_ENTRY_POINTS pEntryPoints)
{

	rdpsndWasapiPlugin* wasapi;

	wasapi = (rdpsndWasapiPlugin*)calloc(1, sizeof(rdpsndWasapiPlugin));

	if (!wasapi)
		return CHANNEL_RC_NO_MEMORY;

	wasapi->device.Open = rdpsnd_wasapi_open;
	wasapi->device.FormatSupported = rdpsnd_wasapi_format_supported;
	wasapi->device.GetVolume = rdpsnd_wasapi_get_volume;
	wasapi->device.SetVolume = rdpsnd_wasapi_set_volume;
	wasapi->device.Play = rdpsnd_wasapi_play;
	wasapi->device.Close = rdpsnd_wasapi_close;
	wasapi->device.Free = rdpsnd_wasapi_free;
	wasapi->log = WLog_Get(TAG);

	if (!rdpsnd_wasapi_parse_addin_args(wasapi, pEntryPoints->args))
		goto fail;
	wasapi->volume = 0xFFFFFFFF;
	if (!freerdp_rdpsnd_open_device(wasapi))
		goto fail;

	pEntryPoints->pRegisterRdpsndDevice(pEntryPoints->rdpsnd, &wasapi->device);
	return CHANNEL_RC_OK;

fail:
	rdpsnd_wasapi_free(&wasapi->device);
	return ERROR_INTERNAL_ERROR;
}
EXTERN_C_END
