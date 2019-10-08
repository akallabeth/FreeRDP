/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Signal handling
 *
 * Copyright 2011 Shea Levy <shea@shealevy.com>
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

#include <stddef.h>
#include <errno.h>

#include <winpr/crt.h>
#include <winpr/debug.h>

#include <freerdp/utils/signal.h>
#include <freerdp/log.h>

#define TAG FREERDP_TAG("utils")

#ifdef _WIN32

int freerdp_handle_signals(void)
{
	errno = ENOSYS;
	return -1;
}

#else

#include <pthread.h>

volatile sig_atomic_t terminal_needs_reset = 0;
int terminal_fildes = 0;
struct termios orig_flags;
struct termios new_flags;

static int print_stack(char** buffer, size_t* size, const char* fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = vsnprintf(*buffer, *size, fmt, ap);
	va_end(ap);

	WLog_ERR(TAG, "%s", *buffer);
	if ((rc >= 0) && ((size_t)rc < *size))
	{
		*size -= (size_t)rc;

		*buffer = &((*buffer)[rc]);
		(*buffer)[-1] = '\n';
	}

	return rc;
}

#if defined(ANDROID)
#include <jni.h>
static JavaVM* jniVm = NULL;

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
	jniVm = vm;
	return JNI_VERSION_1_6;
}


static void throw(JNIEnv* env, const char* msg)
{
	jclass jcls = env->FindClass("java/lang/RuntimeException");
	env->ThrowNew(jcls, msg);
}

static void throwWithEnv(const char* msg)
{
	JNIEnv * env;

	int getEnvStat = jniVm->GetEnv((void **)&env, JNI_VERSION_1_6);
	if (getEnvStat == JNI_EDETACHED) {
		if (jniVm->AttachCurrentThread((void **) &env, NULL) != 0)
		{
			WLog_DBG(TAG, "Attached to JVM");
		}
	} else if (getEnvStat == JNI_OK) {
		WLog_DBG(TAG, "Already attached to JVM");
	} else if (getEnvStat == JNI_EVERSION) {
		WLog_WARN(TAG, "Trying to attach with unsupported JVM version");
		return;
	}

	throw(env, msg);

	jniVm->DetachCurrentThread();
}
#endif

static char trace[0x10000] = { 0 };

static void fatal_handler(int signum)
{
	void* bt;
	char** msg;
	size_t used, x;
	struct sigaction default_sigaction;
	sigset_t this_mask;
	size_t size = sizeof(trace);

	char* out = trace;

	print_stack(&out, &size, "%s: signum=%d", __FUNCTION__, signum);

	bt = winpr_backtrace(10);
	if (bt)
	{
		msg = winpr_backtrace_symbols(bt, &used);

		if (msg)
		{
			print_stack(&out, &size, "------- begin backtrace ------------");
			for (x = 0; x < used; x++)
				print_stack(&out, &size, "%"PRIuz": %s", x, msg[x]);
			print_stack(&out, &size, "------- end backtrace   ------------");
		}
		winpr_backtrace_free(bt);
	}

#if defined(ANDROID)
	throwWithEnv(trace);
#endif

	if (terminal_needs_reset)
		tcsetattr(terminal_fildes, TCSAFLUSH, &orig_flags);

	default_sigaction.sa_handler = SIG_DFL;
	sigfillset(&(default_sigaction.sa_mask));
	default_sigaction.sa_flags = 0;
	sigaction(signum, &default_sigaction, NULL);
	sigemptyset(&this_mask);
	sigaddset(&this_mask, signum);
	pthread_sigmask(SIG_UNBLOCK, &this_mask, NULL);
	raise(signum);
}

static const int fatal_signals[] =
{
	SIGABRT,
	SIGALRM,
	SIGBUS,
	SIGFPE,
	SIGHUP,
	SIGILL,
	SIGINT,
	SIGKILL,
	SIGQUIT,
	SIGSEGV,
	SIGSTOP,
	SIGTERM,
	SIGTSTP,
	SIGTTIN,
	SIGTTOU,
	SIGUSR1,
	SIGUSR2,
#ifdef SIGPOLL
	SIGPOLL,
#endif
#ifdef SIGPROF
	SIGPROF,
#endif
#ifdef SIGSYS
	SIGSYS,
#endif
	SIGTRAP,
#ifdef SIGVTALRM
	SIGVTALRM,
#endif
	SIGXCPU,
	SIGXFSZ
};

int freerdp_handle_signals(void)
{
	size_t signal_index;
	sigset_t orig_set;
	struct sigaction orig_sigaction;
	struct sigaction fatal_sigaction;
	WLog_DBG(TAG, "Registering signal hook...");
	sigfillset(&(fatal_sigaction.sa_mask));
	sigdelset(&(fatal_sigaction.sa_mask), SIGCONT);
	pthread_sigmask(SIG_BLOCK, &(fatal_sigaction.sa_mask), &orig_set);
	fatal_sigaction.sa_handler = fatal_handler;
	fatal_sigaction.sa_flags  = 0;

	for (signal_index = 0; signal_index < ARRAYSIZE(fatal_signals); signal_index++)
	{
		if (sigaction(fatal_signals[signal_index], NULL, &orig_sigaction) == 0)
		{
			if (orig_sigaction.sa_handler != SIG_IGN)
			{
				sigaction(fatal_signals[signal_index], &fatal_sigaction, NULL);
			}
		}
	}

	pthread_sigmask(SIG_SETMASK, &orig_set, NULL);
	/* Ignore SIGPIPE signal. */
	signal(SIGPIPE, SIG_IGN);
	return 0;
}

#endif
