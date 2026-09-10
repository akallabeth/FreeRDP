
#include <stdio.h>
#include <winpr/wtypes.h>
#include <winpr/crt.h>
#include <winpr/assert.h>
#include <winpr/error.h>
#include <winpr/print.h>
#include <winpr/windows.h>

#define TESTCASE_BUFFER_SIZE 8192

#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

typedef struct
{
	const char* utf8;
	size_t utf8len;
	const WCHAR* utf16;
	size_t utf16len;
} testcase_t;

// TODO: The unit tests do not check for valid code points, so always end the test
// strings with a simple ASCII symbol for now.
static const testcase_t unit_testcases[] = {
	{ "foo", 3, (const WCHAR*)"f\x00o\x00o\x00\x00\x00", 3 },
	{ "foo", 4, (const WCHAR*)"f\x00o\x00o\x00\x00\x00", 4 },
	{ "✊🎅ęʥ꣸𑗊a", 19,
	  (const WCHAR*)"\x0a\x27\x3c\xd8\x85\xdf\x19\x01\xa5\x02\xf8\xa8\x05\xd8\xca\xdd\x61\x00\x00"
	                "\x00",
	  9 }
};

static void create_prefix(char* prefix, size_t prefixlen, size_t buffersize, SSIZE_T rc,
                          SSIZE_T inputlen, const testcase_t* test, const char* fkt, size_t line)
{
	(void)_snprintf(prefix, prefixlen,
	                "[%s:%" PRIuz "] '%s' [utf8: %" PRIuz ", utf16: %" PRIuz "] buffersize: %" PRIuz
	                ", rc: %" PRIdz ", inputlen: %" PRIdz ":: ",
	                fkt, line, test->utf8, test->utf8len, test->utf16len, buffersize, rc, inputlen);
}

static BOOL check_short_buffer(const char* prefix, int rc, size_t buffersize,
                               const testcase_t* test, BOOL utf8)
{
	if ((rc > 0) && ((size_t)rc <= buffersize))
		return TRUE;

	size_t len = test->utf8len;
	if (!utf8)
		len = test->utf16len;

	if (buffersize > len)
	{
		(void)fprintf(stderr,
		              "%s length does not match buffersize: %" PRId32 " != %" PRIuz
		              ",but is large enough to hold result\n",
		              prefix, rc, buffersize);
		return FALSE;
	}
	const DWORD err = GetLastError();
	if (err != ERROR_INSUFFICIENT_BUFFER)
	{

		(void)fprintf(stderr,
		              "%s length does not match buffersize: %" PRId32 " != %" PRIuz
		              ", unexpected GetLastError() 0x08%" PRIx32 "\n",
		              prefix, rc, buffersize, err);
		return FALSE;
	}
	else
		return TRUE;
}

#define compare_utf16(what, buffersize, rc, inputlen, test) \
	compare_utf16_int((what), (buffersize), (rc), (inputlen), (test), __func__, __LINE__)
static BOOL compare_utf16_int(const WCHAR* what, size_t buffersize, SSIZE_T rc, SSIZE_T inputlen,
                              const testcase_t* test, const char* fkt, size_t line)
{
	char prefix[8192] = WINPR_C_ARRAY_INIT;
	create_prefix(prefix, ARRAYSIZE(prefix), buffersize, rc, inputlen, test, fkt, line);

	WINPR_ASSERT(what || (buffersize == 0));
	WINPR_ASSERT(test);

	const size_t welen = _wcsnlen(test->utf16, test->utf16len);
	if (buffersize > welen)
	{
		if ((rc < 0) || ((size_t)rc != welen))
		{
			(void)fprintf(stderr,
			              "%s length does not match expectation: %" PRIdz " != %" PRIuz "\n",
			              prefix, rc, welen);
			return FALSE;
		}
	}
	else
	{
		if (!check_short_buffer(prefix, WINPR_ASSERTING_INT_CAST(SSIZE_T, rc), buffersize, test,
		                        FALSE))
			return FALSE;
	}

	if ((rc > 0) && (buffersize > (size_t)rc))
	{
		const size_t wlen = _wcsnlen(what, buffersize);
		if ((rc < 0) || (wlen > (size_t)rc))
		{
			(void)fprintf(stderr, "%s length does not match wcslen: %" PRIdz " < %" PRIuz "\n",
			              prefix, rc, wlen);
			return FALSE;
		}
	}

	if (rc >= 0)
	{
		if (memcmp(test->utf16, what, rc * sizeof(WCHAR)) != 0)
		{
			(void)fprintf(stderr, "%s contents does not match expectations: TODO '%s' != '%s'\n",
			              prefix, test->utf8, test->utf8);
			return FALSE;
		}
	}

	printf("%s success\n", prefix);

	return TRUE;
}

#define compare_utf8(what, buffersize, rc, inputlen, test) \
	compare_utf8_int((what), (buffersize), (rc), (inputlen), (test), __func__, __LINE__)
static BOOL compare_utf8_int(const char* what, size_t buffersize, SSIZE_T rc, SSIZE_T inputlen,
                             const testcase_t* test, const char* fkt, size_t line)
{
	char prefix[8192] = WINPR_C_ARRAY_INIT;
	create_prefix(prefix, ARRAYSIZE(prefix), buffersize, rc, inputlen, test, fkt, line);

	WINPR_ASSERT(what || (buffersize == 0));
	WINPR_ASSERT(test);

	const size_t slen = strnlen(test->utf8, test->utf8len);
	if (buffersize > slen)
	{
		if ((rc < 0) || ((size_t)rc != slen))
		{
			(void)fprintf(stderr,
			              "%s length does not match expectation: %" PRIdz " != %" PRIuz "\n",
			              prefix, rc, slen);
			return FALSE;
		}
	}
	else
	{
		if (!check_short_buffer(prefix, WINPR_ASSERTING_INT_CAST(SSIZE_T, rc), buffersize, test,
		                        TRUE))
			return FALSE;
	}

	if ((rc > 0) && (buffersize > (size_t)rc))
	{
		const size_t wlen = strnlen(what, buffersize);
		if (wlen != (size_t)rc)
		{
			(void)fprintf(stderr, "%s length does not match strnlen: %" PRIdz " != %" PRIuz "\n",
			              prefix, rc, wlen);
			return FALSE;
		}
	}

	if (rc >= 0)
	{
		if (memcmp(test->utf8, what, rc) != 0)
		{
			(void)fprintf(stderr, "%s contents does not match expectations: '%s' != '%s'\n", prefix,
			              what, test->utf8);
			return FALSE;
		}
	}

	printf("%s success\n", prefix);

	return TRUE;
}

static BOOL test_convert_to_utf16(const testcase_t* test)
{
	const size_t len[] = { TESTCASE_BUFFER_SIZE, test->utf16len, test->utf16len + 1,
		                   test->utf16len - 1 };
	const size_t max = test->utf16len > 0 ? ARRAYSIZE(len) : ARRAYSIZE(len) - 1;

	const SSIZE_T rc2 = ConvertUtf8ToWChar(test->utf8, nullptr, 0);
	const size_t wlen = _wcsnlen(test->utf16, test->utf16len);
	if ((rc2 < 0) || ((size_t)rc2 != wlen))
	{
		char prefix[8192] = WINPR_C_ARRAY_INIT;
		create_prefix(prefix, ARRAYSIZE(prefix), 0, rc2, -1, test, __func__, __LINE__);
		(void)fprintf(stderr,
		              "%s ConvertUtf8ToWChar(%s, nullptr, 0) expected %" PRIuz ", got %" PRIdz "\n",
		              prefix, test->utf8, wlen, rc2);
		return FALSE;
	}
	for (size_t x = 0; x < max; x++)
	{
		WCHAR buffer[TESTCASE_BUFFER_SIZE] = WINPR_C_ARRAY_INIT;
		const SSIZE_T rc = ConvertUtf8ToWChar(test->utf8, buffer, len[x]);
		if (!compare_utf16(buffer, len[x], rc, -1, test))
			return FALSE;
	}

	return TRUE;
}

static BOOL test_convert_to_utf16_n(const testcase_t* test)
{
	const size_t len[] = { TESTCASE_BUFFER_SIZE, test->utf16len, test->utf16len + 1,
		                   test->utf16len - 1 };
	const size_t max = test->utf16len > 0 ? ARRAYSIZE(len) : ARRAYSIZE(len) - 1;

	const SSIZE_T rc2 = ConvertUtf8NToWChar(test->utf8, test->utf8len, nullptr, 0);
	const size_t wlen = _wcsnlen(test->utf16, test->utf16len);
	if ((rc2 < 0) || ((size_t)rc2 != wlen))
	{
		char prefix[8192] = WINPR_C_ARRAY_INIT;
		create_prefix(prefix, ARRAYSIZE(prefix), 0, rc2,
		              WINPR_ASSERTING_INT_CAST(SSIZE_T, test->utf8len), test, __func__, __LINE__);
		(void)fprintf(stderr,
		              "%s ConvertUtf8NToWChar(%s, %" PRIuz ", nullptr, 0) expected %" PRIuz
		              ", got %" PRIdz "\n",
		              prefix, test->utf8, test->utf8len, wlen, rc2);
		return FALSE;
	}

	for (size_t x = 0; x < max; x++)
	{
		const size_t ilen[] = { TESTCASE_BUFFER_SIZE, test->utf8len, test->utf8len + 1,
			                    test->utf8len - 1 };
		const size_t imax = test->utf8len > 0 ? ARRAYSIZE(ilen) : ARRAYSIZE(ilen) - 1;

		for (size_t y = 0; y < imax; y++)
		{
			WCHAR buffer[TESTCASE_BUFFER_SIZE] = WINPR_C_ARRAY_INIT;
			SSIZE_T rc = ConvertUtf8NToWChar(test->utf8, ilen[x], buffer, len[x]);
			if (!compare_utf16(buffer, len[x], rc, ilen[x], test))
				return FALSE;
		}
	}
	return TRUE;
}

static BOOL test_convert_to_utf8(const testcase_t* test)
{
	const size_t len[] = { TESTCASE_BUFFER_SIZE, test->utf8len, test->utf8len + 1,
		                   test->utf8len - 1 };
	const size_t max = test->utf8len > 0 ? ARRAYSIZE(len) : ARRAYSIZE(len) - 1;

	const SSIZE_T rc2 = ConvertWCharToUtf8(test->utf16, nullptr, 0);
	const size_t wlen = strnlen(test->utf8, test->utf8len);
	if ((rc2 < 0) || ((size_t)rc2 != wlen))
	{
		char prefix[8192] = WINPR_C_ARRAY_INIT;
		create_prefix(prefix, ARRAYSIZE(prefix), 0, rc2, -1, test, __func__, __LINE__);
		(void)fprintf(stderr,
		              "%s ConvertWCharToUtf8(%s, nullptr, 0) expected %" PRIuz ", got %" PRIdz "\n",
		              prefix, test->utf8, wlen, rc2);
		return FALSE;
	}

	for (size_t x = 0; x < max; x++)
	{
		char buffer[TESTCASE_BUFFER_SIZE] = WINPR_C_ARRAY_INIT;
		SSIZE_T rc = ConvertWCharToUtf8(test->utf16, buffer, len[x]);
		if (!compare_utf8(buffer, len[x], rc, -1, test))
			return FALSE;
	}

	return TRUE;
}

static BOOL test_convert_to_utf8_n(const testcase_t* test)
{
	const size_t len[] = { TESTCASE_BUFFER_SIZE, test->utf8len, test->utf8len + 1,
		                   test->utf8len - 1 };
	const size_t max = test->utf8len > 0 ? ARRAYSIZE(len) : ARRAYSIZE(len) - 1;

	const SSIZE_T rc2 = ConvertWCharNToUtf8(test->utf16, test->utf16len, nullptr, 0);
	const size_t wlen = strnlen(test->utf8, test->utf8len);
	if ((rc2 < 0) || ((size_t)rc2 != wlen))
	{
		char prefix[8192] = WINPR_C_ARRAY_INIT;
		create_prefix(prefix, ARRAYSIZE(prefix), 0, rc2,
		              WINPR_ASSERTING_INT_CAST(SSIZE_T, test->utf16len), test, __func__, __LINE__);
		(void)fprintf(stderr,
		              "%s ConvertWCharNToUtf8(%s, %" PRIuz ", nullptr, 0) expected %" PRIuz
		              ", got %" PRIdz "\n",
		              prefix, test->utf8, test->utf16len, wlen, rc2);
		return FALSE;
	}

	for (size_t x = 0; x < max; x++)
	{
		const size_t ilen[] = { TESTCASE_BUFFER_SIZE, test->utf16len, test->utf16len + 1,
			                    test->utf16len - 1 };
		const size_t imax = test->utf16len > 0 ? ARRAYSIZE(ilen) : ARRAYSIZE(ilen) - 1;

		for (size_t y = 0; y < imax; y++)
		{
			char buffer[TESTCASE_BUFFER_SIZE] = WINPR_C_ARRAY_INIT;
			SSIZE_T rc = ConvertWCharNToUtf8(test->utf16, ilen[x], buffer, len[x]);
			if (!compare_utf8(buffer, len[x], rc, ilen[x], test))
				return FALSE;
		}
	}

	return TRUE;
}

static BOOL test_conversion(const testcase_t* testcases, size_t count)
{
	WINPR_ASSERT(testcases || (count == 0));
	for (size_t x = 0; x < count; x++)
	{
		const testcase_t* test = &testcases[x];

		printf("Running test case %" PRIuz " [%s]\n", x, test->utf8);
		if (!test_convert_to_utf16(test))
			return FALSE;
		if (!test_convert_to_utf16_n(test))
			return FALSE;
		if (!test_convert_to_utf8(test))
			return FALSE;
		if (!test_convert_to_utf8_n(test))
			return FALSE;
	}
	return TRUE;
}

int TestUnicodeConversion(int argc, char* argv[])
{
	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);

	if (!test_conversion(unit_testcases, ARRAYSIZE(unit_testcases)))
		return -1;

	/*

	    printf("----------------------------------------------------------\n\n");

	    if (0)
	    {
	        BYTE src[] = { 'R',0,'I',0,'C',0,'H',0,' ',0, 'T',0,'E',0,'X',0,'T',0,'
	   ',0,'F',0,'O',0,'R',0,'M',0,'A',0,'T',0,'@',0,'@',0 };
	        //BYTE src[] = { 'R',0,'I',0,'C',0,'H',0,' ',0,  0,0,  'T',0,'E',0,'X',0,'T',0,'
	   ',0,'F',0,'O',0,'R',0,'M',0,'A',0,'T',0,'@',0,'@',0 };
	        //BYTE src[] = { 0,0,'R',0,'I',0,'C',0,'H',0,' ',0, 'T',0,'E',0,'X',0,'T',0,'
	   ',0,'F',0,'O',0,'R',0,'M',0,'A',0,'T',0,'@',0,'@',0 }; char* dst = nullptr; int num; num =
	   ConvertFromUnicode(CP_UTF8, 0, (WCHAR*) src, 16, &dst, 0, nullptr, nullptr);
	        printf("ConvertFromUnicode returned %d dst=[%s]\n", num, dst);
	        string_hexdump((BYTE*)dst, num+1);
	    }
	    if (1)
	    {
	        char src[] = "RICH TEXT FORMAT@@@@@@";
	        WCHAR *dst = nullptr;
	        int num;
	        num = ConvertToUnicode(CP_UTF8, 0, src, 16, &dst, 0);
	        printf("ConvertToUnicode returned %d dst=%p\n", num, (void*) dst);
	        string_hexdump((BYTE*)dst, num * 2 + 2);

	    }
	*/

	return 0;
}
