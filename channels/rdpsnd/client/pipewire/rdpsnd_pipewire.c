/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Audio Output Virtual Channel
 *
 * Copyright 2023 Armin Novak <anovak@thincast.com>
 * Copyright 2023 Thincast Technologies GmbH
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

#include <freerdp/config.h>
#include <freerdp/freerdp.h>
#include <freerdp/client/rdpsnd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winpr/crt.h>
#include <winpr/assert.h>
#include <winpr/stream.h>
#include <winpr/cmdline.h>

#include <pipewire/pipewire.h>
#include <spa/param/audio/format-utils.h>

#include <freerdp/types.h>
#include <freerdp/codec/dsp.h>

#include "rdpsnd_main.h"

typedef struct
{
	rdpsndDevicePlugin device;

	char* device_name;

	struct pw_main_loop* mainloop;
	struct pw_stream* stream;
	UINT32 latency;
	UINT32 volume;

	struct spa_audio_info_raw format;
	HANDLE thread;
	HANDLE started;
	HANDLE available;
	wQueue* queue;
	wLog* log;
} rdpsndPipewirePlugin;

static BOOL rdpsnd_check_pipewire(rdpsndPipewirePlugin* pipewire, BOOL haveStream)
{
	BOOL rc = TRUE;
	WINPR_ASSERT(pipewire);
#if 0
	if (!pipewire->stream)
	{
		WLog_WARN(TAG, "pipewire->stream=%p", pipewire->stream);
		rc = !haveStream;
	}

	if (!pipewire->mainloop)
	{
		WLog_WARN(TAG, "pipewire->mainloop=%p", pipewire->mainloop);
		rc = !haveStream;
	}
#endif
	return rc;
}

static BOOL rdpsnd_pipewire_format_supported(rdpsndDevicePlugin* device,
                                             const AUDIO_FORMAT* format);
static BOOL queue_buffer(rdpsndPipewirePlugin* pipewire, const BYTE* data, size_t size);

static void on_process(void* userdata)
{
	rdpsndPipewirePlugin* pipewire = userdata;
	WINPR_ASSERT(pipewire);
	SetEvent(pipewire->available);

	WLog_INFO(TAG, "xxxx");
	char data[1024] = { 0 };
	size_t size = sizeof(data);
	winpr_RAND(data, size);

	queue_buffer(pipewire, data, size);
}

static BOOL wait_for_buffer(rdpsndPipewirePlugin* pipewire)
{
	WINPR_ASSERT(pipewire);
	rdpContext* context = freerdp_rdpsnd_get_context(pipewire->device.rdpsnd);
	WINPR_ASSERT(context);

	HANDLE handles[] = { pipewire->available, freerdp_abort_event(context) };

	const DWORD status = WaitForMultipleObjects(ARRAYSIZE(handles), handles, FALSE, INFINITE);
	if (status != WAIT_OBJECT_0)
		return FALSE;
	ResetEvent(pipewire->available);
	return TRUE;
}

BOOL queue_buffer(rdpsndPipewirePlugin* pipewire, const BYTE* data, size_t size)
{
	WINPR_ASSERT(pipewire);

	struct pw_buffer* b = pw_stream_dequeue_buffer(pipewire->stream);
	if (!b)
		return FALSE;

	if (b->size < size)
		return FALSE;
	memcpy(b->buffer, data, size);

	const int rc = pw_stream_queue_buffer(pipewire->stream, b);
	return rc == 0;
}

static void do_quit(void* userdata, int signal_number)
{
	rdpsndPipewirePlugin* data = userdata;
	WINPR_ASSERT(data);
	if (data->mainloop)
	{
		WLog_Print(data->log, WLOG_DEBUG, "quitting with signal %d [%s]", signal_number,
		           strsignal(signal_number));
		pw_main_loop_quit(data->mainloop);
		WaitForSingleObject(data->thread, INFINITE);
	}
	data->thread = NULL;
}

static void rdpsnd_pipewire_cleanup(rdpsndPipewirePlugin* pipewire)
{
	WINPR_ASSERT(pipewire);

	pw_stream_destroy(pipewire->stream);
	pw_main_loop_destroy(pipewire->mainloop);

	pipewire->stream = NULL;
	pipewire->mainloop = NULL;

	pw_deinit();
}

static void on_state_changed(void* data, enum pw_stream_state old, enum pw_stream_state state,
                             const char* error)
{
	rdpsndPipewirePlugin* pipewire = data;
	WINPR_ASSERT(pipewire);

	const char* ostr = pw_stream_state_as_string(old);
	const char* nstr = pw_stream_state_as_string(state);

	WLog_Print(pipewire->log, WLOG_INFO, "%s -> %s [%s]", ostr, nstr, error);
}

static void on_add_buffer(void* data, struct pw_buffer* buffer)
{
	rdpsndPipewirePlugin* pipewire = data;
	WINPR_ASSERT(pipewire);

	WLog_Print(pipewire->log, WLOG_INFO, "[%p]", buffer);
}

static void on_remove_buffer(void* data, struct pw_buffer* buffer)
{
	rdpsndPipewirePlugin* pipewire = data;
	WINPR_ASSERT(pipewire);

	WLog_Print(pipewire->log, WLOG_INFO, "[%p]", buffer);
}

static void on_destroy(void* data)
{
	rdpsndPipewirePlugin* pipewire = data;
	WINPR_ASSERT(pipewire);

	WLog_Print(pipewire->log, WLOG_INFO, "[]");
}

static void on_drained(void* data)
{
	rdpsndPipewirePlugin* pipewire = data;
	WINPR_ASSERT(pipewire);

	WLog_Print(pipewire->log, WLOG_INFO, "[]");
}

static const struct pw_stream_events stream_events = { PW_VERSION_STREAM_EVENTS,
	                                                   .destroy = on_destroy,
	                                                   .drained = on_drained,
	                                                   .process = on_process,
	                                                   .add_buffer = on_add_buffer,
	                                                   .remove_buffer = on_remove_buffer,
	                                                   .state_changed = on_state_changed };

static BOOL rdpsnd_pipewire_initialize(rdpsndPipewirePlugin* pipewire)
{
	WINPR_ASSERT(pipewire);

	pw_init(NULL, NULL);

	pipewire->mainloop = pw_main_loop_new(NULL);

	if (!pipewire->mainloop)
		goto fail;

	struct pw_loop* loop = pw_main_loop_get_loop(pipewire->mainloop);
	if (!loop)
		goto fail;

	//	pw_loop_add_signal(loop, SIGINT, do_quit, pipewire);
	//	pw_loop_add_signal(loop, SIGTERM, do_quit, pipewire);

	struct pw_properties* props =
	    pw_properties_new(PW_KEY_MEDIA_TYPE, "Audio", PW_KEY_MEDIA_CATEGORY, "Playback",
	                      PW_KEY_MEDIA_ROLE, "Music", NULL);

	pipewire->stream = pw_stream_new_simple(loop, "freerdp", props, &stream_events, pipewire);
	if (!pipewire->stream)
		goto fail;

	return TRUE;

fail:
	rdpsnd_pipewire_cleanup(pipewire);
	return FALSE;
}

static DWORD WINAPI play_thread(void* arg)
{
	rdpsndPipewirePlugin* pipewire = arg;
	WINPR_ASSERT(pipewire);

	if (!rdpsnd_pipewire_initialize(pipewire))
		goto fail;

	uint8_t buffer[1024] = { 0 };
	struct spa_pod_builder b = SPA_POD_BUILDER_INIT(buffer, sizeof(buffer));
	const struct spa_pod* params =
	    spa_format_audio_raw_build(&b, SPA_PARAM_EnumFormat, &pipewire->format);
	const int rc = pw_stream_connect(pipewire->stream, PW_DIRECTION_OUTPUT, PW_ID_ANY,
	                                 PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS |
	                                     PW_STREAM_FLAG_RT_PROCESS,
	                                 &params, 1);
	if (rc < 0)
		goto fail;

	SetEvent(pipewire->started);
	pw_main_loop_run(pipewire->mainloop);

fail:
	SetEvent(pipewire->started);
	rdpsnd_pipewire_cleanup(pipewire);
	return 0;
}

static BOOL rdpsnd_pipewire_connect(rdpsndDevicePlugin* device)
{
	rdpsndPipewirePlugin* pipewire = (rdpsndPipewirePlugin*)device;

	if (!rdpsnd_check_pipewire(pipewire, FALSE))
		return FALSE;

	ResetEvent(pipewire->started);
	pipewire->thread = CreateThread(NULL, 0, play_thread, pipewire, 0, NULL);

	rdpContext* context = freerdp_rdpsnd_get_context(device->rdpsnd);
	HANDLE handles[] = { freerdp_abort_event(context), pipewire->started };

	WaitForMultipleObjects(ARRAYSIZE(handles), handles, FALSE, INFINITE);
	return TRUE;
}

static void rdpsnd_pipewire_close(rdpsndDevicePlugin* device)
{
	rdpsndPipewirePlugin* pipewire = (rdpsndPipewirePlugin*)device;

	WINPR_ASSERT(pipewire);

	if (!rdpsnd_check_pipewire(pipewire, FALSE))
		return;

	do_quit(pipewire, 0);
}

static BOOL rdpsnd_pipewire_set_format_spec(rdpsndPipewirePlugin* pipewire,
                                            const AUDIO_FORMAT* format)
{
	WINPR_ASSERT(format);

	if (!rdpsnd_check_pipewire(pipewire, FALSE))
		return FALSE;

	if (!rdpsnd_pipewire_format_supported(&pipewire->device, format))
		return FALSE;

	enum spa_audio_format fmt;
	switch (format->wFormatTag)
	{
		case WAVE_FORMAT_PCM:
			switch (format->wBitsPerSample)
			{
				case 8:
					fmt = SPA_AUDIO_FORMAT_U8;
					break;

				case 16:
					fmt = SPA_AUDIO_FORMAT_U16;
					break;

				default:
					return FALSE;
			}

			break;

		case WAVE_FORMAT_ALAW:
			fmt = SPA_AUDIO_FORMAT_ALAW;
			break;

		case WAVE_FORMAT_MULAW:
			fmt = SPA_AUDIO_FORMAT_ULAW;
			break;

		default:
			return FALSE;
	}

	pipewire->format = SPA_AUDIO_INFO_RAW_INIT(.format = fmt, .channels = format->nChannels,
	                                           .rate = format->nSamplesPerSec);
	return TRUE;
}

static BOOL rdpsnd_pipewire_open(rdpsndDevicePlugin* device, const AUDIO_FORMAT* format,
                                 UINT32 latency)
{
	rdpsndPipewirePlugin* pipewire = (rdpsndPipewirePlugin*)device;

	WINPR_ASSERT(format);

	if (!rdpsnd_check_pipewire(pipewire, FALSE))
		return TRUE;

	if (!rdpsnd_pipewire_set_format_spec(pipewire, format))
		return FALSE;

	pipewire->latency = latency;

	return rdpsnd_pipewire_connect(&pipewire->device);
}

static void rdpsnd_pipewire_free(rdpsndDevicePlugin* device)
{
	rdpsndPipewirePlugin* pipewire = (rdpsndPipewirePlugin*)device;

	if (!pipewire)
		return;

	rdpsnd_pipewire_close(device);

	CloseHandle(pipewire->started);
	CloseHandle(pipewire->available);
	free(pipewire->device_name);
	free(pipewire);
}

static BOOL rdpsnd_pipewire_default_format(rdpsndDevicePlugin* device, const AUDIO_FORMAT* desired,
                                           AUDIO_FORMAT* defaultFormat)
{
	rdpsndPipewirePlugin* pipewire = (rdpsndPipewirePlugin*)device;

	if (!pipewire || !defaultFormat)
		return FALSE;

	*defaultFormat = *desired;
	defaultFormat->data = NULL;
	defaultFormat->cbSize = 0;
	defaultFormat->wFormatTag = WAVE_FORMAT_PCM;
	if ((defaultFormat->nChannels < 1) || (defaultFormat->nChannels > SPA_AUDIO_MAX_CHANNELS))
		defaultFormat->nChannels = 2;
	if ((defaultFormat->nSamplesPerSec < 1) || (defaultFormat->nSamplesPerSec > 48000))
		defaultFormat->nSamplesPerSec = 44100;
	if ((defaultFormat->wBitsPerSample != 8) && (defaultFormat->wBitsPerSample != 16))
		defaultFormat->wBitsPerSample = 16;

	defaultFormat->nBlockAlign = defaultFormat->nChannels * defaultFormat->wBitsPerSample / 8;
	defaultFormat->nAvgBytesPerSec = defaultFormat->nBlockAlign * defaultFormat->nSamplesPerSec;
	return TRUE;
}

BOOL rdpsnd_pipewire_format_supported(rdpsndDevicePlugin* device, const AUDIO_FORMAT* format)
{
	WINPR_ASSERT(device);
	WINPR_ASSERT(format);

	switch (format->wFormatTag)
	{
		case WAVE_FORMAT_PCM:
			if (format->cbSize == 0 && (format->nSamplesPerSec <= 48000) &&
			    (format->wBitsPerSample == 8 || format->wBitsPerSample == 16) &&
			    (format->nChannels >= 1 && format->nChannels <= SPA_AUDIO_MAX_CHANNELS))

			{
				return TRUE;
			}
			break;

		default:
			break;
	}

	return FALSE;
}

static UINT32 rdpsnd_pipewire_get_volume(rdpsndDevicePlugin* device)
{
	rdpsndPipewirePlugin* pipewire = (rdpsndPipewirePlugin*)device;

	if (!rdpsnd_check_pipewire(pipewire, FALSE))
		return 0;

	// TODO
	return pipewire->volume;
}

static BOOL rdpsnd_pipewire_set_volume(rdpsndDevicePlugin* device, UINT32 value)
{
	rdpsndPipewirePlugin* pipewire = (rdpsndPipewirePlugin*)device;

	if (!rdpsnd_check_pipewire(pipewire, TRUE))
	{
		WLog_WARN(TAG, "%s called before pipewire backend was initialized");
		return FALSE;
	}

	// TODO
	return TRUE;
}

static UINT rdpsnd_pipewire_play(rdpsndDevicePlugin* device, const BYTE* data, size_t size)
{
	rdpsndPipewirePlugin* pipewire = (rdpsndPipewirePlugin*)device;

	if (!rdpsnd_check_pipewire(pipewire, TRUE) || !data)
		return 0;

#if 0
	if (!wait_for_buffer(pipewire))
		return ERROR_INTERNAL_ERROR;

	if (!queue_buffer(pipewire, data, size))
		return ERROR_INTERNAL_ERROR;
#endif

	return 0;
}

static UINT rdpsnd_pipewire_parse_addin_args(rdpsndDevicePlugin* device, const ADDIN_ARGV* args)
{
	int status;
	DWORD flags;
	const COMMAND_LINE_ARGUMENT_A* arg;
	rdpsndPipewirePlugin* pipewire = (rdpsndPipewirePlugin*)device;
	COMMAND_LINE_ARGUMENT_A rdpsnd_pipewire_args[] = {
		{ "dev", COMMAND_LINE_VALUE_REQUIRED, "<device>", NULL, NULL, -1, NULL, "device" },
		{ NULL, 0, NULL, NULL, NULL, -1, NULL, NULL }
	};
	flags =
	    COMMAND_LINE_SIGIL_NONE | COMMAND_LINE_SEPARATOR_COLON | COMMAND_LINE_IGN_UNKNOWN_KEYWORD;

	WINPR_ASSERT(pipewire);
	WINPR_ASSERT(args);

	status = CommandLineParseArgumentsA(args->argc, args->argv, rdpsnd_pipewire_args, flags,
	                                    pipewire, NULL, NULL);

	if (status < 0)
		return ERROR_INVALID_DATA;

	arg = rdpsnd_pipewire_args;

	do
	{
		if (!(arg->Flags & COMMAND_LINE_VALUE_PRESENT))
			continue;

		CommandLineSwitchStart(arg) CommandLineSwitchCase(arg, "dev")
		{
			pipewire->device_name = _strdup(arg->Value);

			if (!pipewire->device_name)
				return ERROR_OUTOFMEMORY;
		}
		CommandLineSwitchEnd(arg)
	} while ((arg = CommandLineFindNextArgumentA(arg)) != NULL);

	return CHANNEL_RC_OK;
}

UINT pipewire_freerdp_rdpsnd_client_subsystem_entry(
    PFREERDP_RDPSND_DEVICE_ENTRY_POINTS pEntryPoints)
{
	const ADDIN_ARGV* args;
	rdpsndPipewirePlugin* pipewire;
	UINT ret;

	WINPR_ASSERT(pEntryPoints);

	pipewire = (rdpsndPipewirePlugin*)calloc(1, sizeof(rdpsndPipewirePlugin));

	if (!pipewire)
		return CHANNEL_RC_NO_MEMORY;

	pipewire->log = freerdp_rdpsnd_get_log(pEntryPoints->rdpsnd);
	pipewire->device.Open = rdpsnd_pipewire_open;
	pipewire->device.FormatSupported = rdpsnd_pipewire_format_supported;
	pipewire->device.GetVolume = rdpsnd_pipewire_get_volume;
	pipewire->device.SetVolume = rdpsnd_pipewire_set_volume;
	pipewire->device.Play = rdpsnd_pipewire_play;
	pipewire->device.Close = rdpsnd_pipewire_close;
	pipewire->device.Free = rdpsnd_pipewire_free;
	pipewire->device.DefaultFormat = rdpsnd_pipewire_default_format;
	args = pEntryPoints->args;

	if (args->argc > 1)
	{
		ret = rdpsnd_pipewire_parse_addin_args(&pipewire->device, args);

		if (ret != CHANNEL_RC_OK)
		{
			WLog_ERR(TAG, "error parsing arguments");
			goto error;
		}
	}

	ret = CHANNEL_RC_NO_MEMORY;
	pipewire->started = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!pipewire->started)
		goto error;
	pipewire->available = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!pipewire->available)
		goto error;
	pEntryPoints->pRegisterRdpsndDevice(pEntryPoints->rdpsnd, &pipewire->device);
	return CHANNEL_RC_OK;
error:
	rdpsnd_pipewire_free(&pipewire->device);
	return ret;
}
