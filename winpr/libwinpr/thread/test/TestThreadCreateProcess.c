
#include <stdio.h>
#include <errno.h>

#include <winpr/crt.h>
#include <winpr/debug.h>
#include <winpr/tchar.h>
#include <winpr/synch.h>
#include <winpr/thread.h>
#include <winpr/environment.h>
#include <winpr/pipe.h>
#include <winpr/stream.h>

typedef struct
{
	const char* app;
	const char* command;
	int expected;
	const char* output;
} test_case_t;

static BOOL WrapCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
                               LPSECURITY_ATTRIBUTES lpProcessAttributes,
                               LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
                               DWORD dwCreationFlags, LPVOID lpEnvironment,
                               LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
                               LPPROCESS_INFORMATION lpProcessInformation)
{
	WCHAR* cmd = nullptr;
	if (lpCommandLine)
		cmd = _wcsdup(lpCommandLine);
	const BOOL rc = CreateProcessW(lpApplicationName, cmd, lpProcessAttributes, lpThreadAttributes,
	                               bInheritHandles, dwCreationFlags, lpEnvironment,
	                               lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	free(cmd);
	return rc;
}
static BOOL testNoPipes(const WCHAR* lpApplicationName, const WCHAR* lpCommandLine, int expected,
                        const char* expectedOutput)
{
	// LPTSTR lpCommandLine;
	LPSECURITY_ATTRIBUTES lpProcessAttributes = nullptr;
	LPSECURITY_ATTRIBUTES lpThreadAttributes = nullptr;
	BOOL bInheritHandles = FALSE;
	DWORD dwCreationFlags = 0;
	LPCWSTR lpCurrentDirectory = nullptr;
	STARTUPINFOW StartupInfo = WINPR_C_ARRAY_INIT;
	PROCESS_INFORMATION ProcessInformation = WINPR_C_ARRAY_INIT;
	BOOL res = FALSE;

	LPWCH lpszEnvironmentBlock = GetEnvironmentStringsW();

#ifdef _UNICODE
	dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
#endif
	LPVOID lpEnvironment = lpszEnvironmentBlock;
	StartupInfo.cb = sizeof(STARTUPINFOW);

	BOOL status = WrapCreateProcessW(
	    lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
	    dwCreationFlags, lpEnvironment, lpCurrentDirectory, &StartupInfo, &ProcessInformation);

	if (!status)
	{
		printf("CreateProcess failed. error=%" PRIu32 "\n", GetLastError());
		goto fail;
	}

	if (WaitForSingleObject(ProcessInformation.hProcess, 5000) != WAIT_OBJECT_0)
	{
		printf("Failed to wait for first process. error=%" PRIu32 "\n", GetLastError());
		goto fail;
	}

	DWORD exitCode = 0;
	status = GetExitCodeProcess(ProcessInformation.hProcess, &exitCode);

	printf("GetExitCodeProcess status: %" PRId32 "\n", status);
	printf("Process exited with code: 0x%08" PRIX32 "\n", exitCode);

	if (exitCode != expected)
		goto fail;

	res = TRUE;
fail:
	(void)CloseHandle(ProcessInformation.hProcess);
	(void)CloseHandle(ProcessInformation.hThread);
	FreeEnvironmentStringsW(lpszEnvironmentBlock);
	return res;
}

static BOOL testStdOutPipes(const WCHAR* lpApplicationName, const WCHAR* lpCommandLine,
                            int expected, const char* expectedOutput)
{
	BOOL res = FALSE;
	// LPTSTR lpCommandLine;
	LPSECURITY_ATTRIBUTES lpProcessAttributes = nullptr;
	LPSECURITY_ATTRIBUTES lpThreadAttributes = nullptr;
	BOOL bInheritHandles = TRUE;
	DWORD dwCreationFlags = 0;
	LPVOID lpEnvironment = nullptr;
	LPCWSTR lpCurrentDirectory = nullptr;
	STARTUPINFOW StartupInfo = WINPR_C_ARRAY_INIT;
	PROCESS_INFORMATION ProcessInformation = WINPR_C_ARRAY_INIT;
	HANDLE pipe_read = nullptr;
	HANDLE pipe_write = nullptr;

#ifdef _UNICODE
	dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
#endif

	/* Test stdin,stdout,stderr redirection */

	SECURITY_ATTRIBUTES saAttr = { .nLength = sizeof(SECURITY_ATTRIBUTES),
		                           .bInheritHandle = TRUE,
		                           .lpSecurityDescriptor = nullptr };

	if (!CreatePipe(&pipe_read, &pipe_write, &saAttr, 0))
	{
		printf("Pipe creation failed. error=%" PRIu32 "\n", GetLastError());
		return FALSE;
	}

	wStream* s = Stream_New(nullptr, 1024);
	if (!s)
		goto fail;

	StartupInfo.cb = sizeof(STARTUPINFOW);
	StartupInfo.hStdOutput = pipe_write;
	StartupInfo.hStdError = pipe_write;
	StartupInfo.dwFlags = STARTF_USESTDHANDLES;

	LPWCH lpszEnvironmentBlock = GetEnvironmentStringsW();
	if (!lpszEnvironmentBlock)
		goto fail;

	BOOL status = WrapCreateProcessW(
	    lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
	    dwCreationFlags, lpEnvironment, lpCurrentDirectory, &StartupInfo, &ProcessInformation);

	if (!status)
	{
		printf("CreateProcess failed. error=%" PRIu32 "\n", GetLastError());
		goto fail;
	}

	bool running = true;
	while (running)
	{
		HANDLE hdl[] = { ProcessInformation.hProcess, pipe_read };
		const DWORD wstatus = WaitForMultipleObjects(ARRAYSIZE(hdl), hdl, FALSE, 0);
		switch (wstatus)
		{
			case WAIT_OBJECT_0:
				running = false;
				break;
			default:
			{
				char buf[2] = WINPR_C_ARRAY_INIT;
				DWORD read_bytes = 0;

				if (WAIT_OBJECT_0 == WaitForSingleObject(pipe_read, 0))
				{
					if (!ReadFile(pipe_read, buf, sizeof(buf) - 1, &read_bytes, nullptr))
					{
						printf("ReadFile: No or unexpected data read from pipe\n");
						goto fail;
					}

					if (!Stream_EnsureRemainingCapacity(s, read_bytes))
						goto fail;
					Stream_Write(s, buf, read_bytes);
					if (read_bytes == 0)
						running = false;
				}
			}
			    break;
		}
	}

	if (WaitForSingleObject(ProcessInformation.hProcess, 5000) != WAIT_OBJECT_0)
	{
		printf("Failed to wait for second process. error=%" PRIu32 "\n", GetLastError());
		goto fail;
	}

	DWORD exitCode = 0;
	status = GetExitCodeProcess(ProcessInformation.hProcess, &exitCode);
	if (!status)
		goto fail;

	if (exitCode != expected)
		goto fail;

	Stream_SealLength(s);

	if (expectedOutput)
	{
		const size_t elen = strlen(expectedOutput);
		if (elen != Stream_Length(s))
		{
			printf("Data sizes read do not match expectations: got %" PRIuz ", expected %" PRIuz
			       "\n",
			       elen, Stream_Length(s));
			goto fail;
		}

		if (strncmp(expectedOutput, Stream_BufferAs(s, char), elen))
		{
			printf("Data read does not match expectations\n");
			goto fail;
		}
	}

	printf("GetExitCodeProcess status: %" PRId32 "\n", status);
	printf("Process exited with code: 0x%08" PRIX32 "\n", exitCode);

	res = TRUE;
fail:
	(void)CloseHandle(ProcessInformation.hProcess);
	(void)CloseHandle(ProcessInformation.hThread);
	FreeEnvironmentStringsW(lpszEnvironmentBlock);
	Stream_Free(s, TRUE);
	return res;
}

static int testcommand_buffer(const WCHAR* lpApplicationName, const WCHAR* command, int expected,
                              const char* expectedOutput)
{
	if (!testNoPipes(lpApplicationName, command, expected, expectedOutput))
		return -1;
	if (!testStdOutPipes(lpApplicationName, command, expected, expectedOutput))
		return -2;
	return 0;
}

static int testcommand(const char* lpApplicationName, const char* command, int expected,
                       const char* expectedOutput)
{
	printf("testing: %s [expect %d]\n\n", command, expected);

	WCHAR* lpAppW = nullptr;
	WCHAR* lpCmdW = nullptr;

	if (lpApplicationName)
		lpAppW = ConvertUtf8ToWCharAlloc(lpApplicationName, nullptr);
	if (command)
		lpCmdW = ConvertUtf8ToWCharAlloc(command, nullptr);

	const int rc = testcommand_buffer(lpAppW, lpCmdW, expected, expectedOutput);
	free(lpAppW);
	free(lpCmdW);
	return rc;
}

int TestThreadCreateProcess(WINPR_ATTR_UNUSED int argc, WINPR_ATTR_UNUSED char* argv[])
{
	const test_case_t commands[] = {
#if defined(_WIN32)
		{ nullptr, "cmd /C set", 0, nullptr }
#else
		{ "find", "-fadsjsd", 1, "find: unknown predicate `-fadsjsd'\n" },
		{ "find", ".", 0, nullptr },
		{ nullptr, "echo foobar", 0, "foobar\n" }
#endif
	};

	if (argc > 1)
	{
		if ((argc % 3) != 1)
		{
			(void)fprintf(
			    stderr,
			    "usage: %s <comand> <args> <return code> [<command2> <args> <return code2> ...]\n",
			    argv[0]);
			return -1;
		}

		for (int x = 1; x < argc; x += 3)
		{
			long val = strtol(argv[x + 2], nullptr, 0);
			if (errno)
			{
				char buffer[128] = WINPR_C_ARRAY_INIT;
				(void)fprintf(stderr, "failed to convert argv[%d]=%s %s : %s\n", x + 1, argv[x + 1],
				              argv[x + 2], winpr_strerror(errno, buffer, sizeof(buffer)));
			}
			const int res = testcommand(argv[x], argv[x + 1], (int)val, nullptr);
			if (res != 0)
				return res;
		}
		return 0;
	}

	for (size_t x = 0; x < ARRAYSIZE(commands); x++)
	{
		const test_case_t* cur = &commands[x];
		const int res1 = testcommand(cur->app, cur->command, cur->expected, cur->output);
		if (res1 != 0)
			return res1;
	}
	return 0;
}
