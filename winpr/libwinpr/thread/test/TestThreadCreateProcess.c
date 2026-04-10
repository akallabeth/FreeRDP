
#include <stdio.h>
#include <errno.h>

#include <winpr/crt.h>
#include <winpr/debug.h>
#include <winpr/tchar.h>
#include <winpr/synch.h>
#include <winpr/thread.h>
#include <winpr/environment.h>
#include <winpr/pipe.h>

typedef struct
{
	const char* command;
	int expected;
	const char* output;
} test_case_t;

static int testB(const char* lpApplicationName, const char* command, int expected,
                 const char* expectedOutput)
{
	int rc = -1;

	LPSECURITY_ATTRIBUTES lpProcessAttributes = nullptr;
	LPSECURITY_ATTRIBUTES lpThreadAttributes = nullptr;
	BOOL bInheritHandles = TRUE;
	DWORD dwCreationFlags = 0;
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

	LPWSTR lpApplicationNameW = nullptr;
	LPWSTR commandW = nullptr;
	if (lpApplicationName)
		lpApplicationNameW = ConvertUtf8ToWCharAlloc(lpApplicationName, nullptr);
	if (command)
		commandW = ConvertUtf8ToWCharAlloc(command, nullptr);

	LPTCH lpszEnvironmentBlock = GetEnvironmentStrings();
	LPVOID lpEnvironment = lpszEnvironmentBlock;
	if (!lpEnvironment)
	{
		printf("Failed to allocate environment buffer. error=%" PRIu32 "\n", GetLastError());
		goto fail;
	}
	rc--;

	if (!CreatePipe(&pipe_read, &pipe_write, &saAttr, 0))
	{
		printf("Pipe creation failed. error=%" PRIu32 "\n", GetLastError());
		goto fail;
	}
	rc--;

	StartupInfo.cb = sizeof(STARTUPINFOW);
	StartupInfo.hStdOutput = pipe_write;
	StartupInfo.hStdError = pipe_write;
	StartupInfo.dwFlags = STARTF_USESTDHANDLES;

	const BOOL status = CreateProcessW(
	    lpApplicationNameW, commandW, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
	    dwCreationFlags, lpEnvironment, lpCurrentDirectory, &StartupInfo, &ProcessInformation);

	if (!status)
	{
		printf("CreateProcess failed. error=%" PRIu32 "\n", GetLastError());
		goto fail;
	}
	rc--;

	const DWORD wstatus = WaitForSingleObject(ProcessInformation.hProcess, 5000);
	if (wstatus != WAIT_OBJECT_0)
	{
		printf("Failed to wait [0x%08" PRIx32 "] for second process. error=%" PRIu32 "\n", wstatus,
		       GetLastError());
		goto fail;
	}
	rc--;

	DWORD read_bytes = 0;
	char buf[1024] = WINPR_C_ARRAY_INIT;
	if (!ReadFile(pipe_read, buf, sizeof(buf) - 1, &read_bytes, nullptr))
		goto fail;
	rc--;

	if (expectedOutput)
	{
		const size_t len = strlen(expectedOutput);
		if (read_bytes != len)
		{
			(void)fprintf(stderr,
			              "expected output length does not match data read: %" PRIuz " vs %" PRIu32
			              "\n",
			              len, read_bytes);
			goto fail;
		}
		rc--;
		if (strncmp(buf, expectedOutput, read_bytes) != 0)
		{
			(void)fprintf(stderr, "expected output does not match data read:\n%s\n%s\n",
			              expectedOutput, buf);
			goto fail;
		}
		rc--;
	}
	DWORD exitCode = 0;
	if (!GetExitCodeProcess(ProcessInformation.hProcess, &exitCode))
		goto fail;
	rc--;

	printf("GetExitCodeProcess status: %" PRId32 "\n", status);
	printf("Process exited with code: 0x%08" PRIX32 "\n", exitCode);

	if (exitCode != expected)
		goto fail;
	rc = 0;

fail:
	FreeEnvironmentStrings(lpszEnvironmentBlock);
	if (pipe_read)
		(void)CloseHandle(pipe_read);
	if (pipe_write)
		(void)CloseHandle(pipe_write);
	if (ProcessInformation.hProcess)
		(void)CloseHandle(ProcessInformation.hProcess);
	if (ProcessInformation.hThread)
		(void)CloseHandle(ProcessInformation.hThread);
	free(commandW);
	free(lpApplicationNameW);
	return rc;
}

static int testA(const char* lpApplicationName, const char* command, int expected)
{
	int rc = -1;

	LPSECURITY_ATTRIBUTES lpProcessAttributes = nullptr;
	LPSECURITY_ATTRIBUTES lpThreadAttributes = nullptr;
	BOOL bInheritHandles = 0;
	DWORD dwCreationFlags = 0;
	LPCWSTR lpCurrentDirectory = nullptr;
	STARTUPINFOW StartupInfo = WINPR_C_ARRAY_INIT;
	PROCESS_INFORMATION ProcessInformation = WINPR_C_ARRAY_INIT;

	LPTCH lpszEnvironmentBlock = GetEnvironmentStrings();

#ifdef _UNICODE
	dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
#endif
	LPVOID lpEnvironment = lpszEnvironmentBlock;
	StartupInfo.cb = sizeof(STARTUPINFOW);

	LPWSTR lpApplicationNameW = nullptr;
	LPWSTR commandW = nullptr;
	if (lpApplicationName)
		lpApplicationNameW = ConvertUtf8ToWCharAlloc(lpApplicationName, nullptr);
	if (command)
		commandW = ConvertUtf8ToWCharAlloc(command, nullptr);

	const BOOL status = CreateProcessW(
	    lpApplicationNameW, commandW, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
	    dwCreationFlags, lpEnvironment, lpCurrentDirectory, &StartupInfo, &ProcessInformation);

	if (!status)
	{
		printf("CreateProcess failed. error=%" PRIu32 "\n", GetLastError());
		goto fail;
	}
	rc--;

	if (WaitForSingleObject(ProcessInformation.hProcess, 5000) != WAIT_OBJECT_0)
	{
		printf("Failed to wait for first process. error=%" PRIu32 "\n", GetLastError());
		goto fail;
	}
	rc--;

	DWORD exitCode = 0;
	if (!GetExitCodeProcess(ProcessInformation.hProcess, &exitCode))
		goto fail;
	rc--;
	printf("GetExitCodeProcess status: %" PRId32 "\n", status);
	printf("Process exited with code: 0x%08" PRIX32 "\n", exitCode);

	if (exitCode != expected)
		goto fail;

	rc = 0;

fail:
	if (ProcessInformation.hProcess)
		(void)CloseHandle(ProcessInformation.hProcess);
	if (ProcessInformation.hThread)
		(void)CloseHandle(ProcessInformation.hThread);
	FreeEnvironmentStrings(lpszEnvironmentBlock);
	free(commandW);
	free(lpApplicationNameW);
	return rc;
}

static int testcommand(const char* lpApplicationName, const char* command, int expected,
                       const char* expectedOutput)
{
	printf("testing: %s [expect %d]\n\n", command, expected);
	const int rc1 = testA(lpApplicationName, command, expected);
	const int rc2 = testB(lpApplicationName, command, expected, expectedOutput);
	if (rc1 != 0)
		return rc1;
	if (rc2 != 0)
		return rc2 - 0x100;
	return 0;
}

int TestThreadCreateProcess(WINPR_ATTR_UNUSED int argc, WINPR_ATTR_UNUSED char* argv[])
{
	const test_case_t commands[] = {
#if defined(_WIN32)
		{ "cmd /C set", 0, nullptr }
#else
		{ "find -fadsjsd", 1, nullptr }, { "find .", 0, nullptr }, { "echo foobar", 0, "foobar\n" }
#endif
	};

	if (argc > 1)
	{
		if ((argc % 2) == 0)
		{
			(void)fprintf(stderr,
			              "usage: %s <comand> <return code> [<command2> <return code2> ...]\n",
			              argv[0]);
			return -1;
		}

		for (int x = 1; x < argc; x += 2)
		{
			long val = strtol(argv[x + 1], nullptr, 0);
			if (errno)
			{
				char buffer[128] = WINPR_C_ARRAY_INIT;
				(void)fprintf(stderr, "failed to convert argv[%d]=%s : %s\n", x + 1, argv[x + 1],
				              winpr_strerror(errno, buffer, sizeof(buffer)));
			}
			const int res = testcommand(argv[0], argv[x], (int)val, nullptr);
			if (res != 0)
				return res;
		}
		return 0;
	}

	for (size_t x = 0; x < ARRAYSIZE(commands); x++)
	{
		const test_case_t* cur = &commands[x];
		const int res1 = testcommand(nullptr, cur->command, cur->expected, cur->output);
		if (res1 != 0)
			return res1;

		char* app = strdup(cur->command);
		if (!app)
			return -1;
		char* command = strchr(app, ' ');
		if (!command)
		{
			free(app);
			return -1;
		}
		*command++ = '\0';

		const int res2 = testcommand(app, command, cur->expected, cur->output);
		free(app);
		if (res2 != 0)
			return res2;
	}
	return 0;
}
