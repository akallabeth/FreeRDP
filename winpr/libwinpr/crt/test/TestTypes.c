
#include <stdio.h>
#include <winpr/crt.h>
#include <winpr/windows.h>

#define EXPECTED_SIZEOF_BYTE 1
#define EXPECTED_SIZEOF_BOOLEAN 1
#define EXPECTED_SIZEOF_CHAR 1
#define EXPECTED_SIZEOF_UCHAR 1
#define EXPECTED_SIZEOF_INT8 1
#define EXPECTED_SIZEOF_UINT8 1
#define EXPECTED_SIZEOF_INT16 2
#define EXPECTED_SIZEOF_UINT16 2
#define EXPECTED_SIZEOF_WORD 2
#define EXPECTED_SIZEOF_WCHAR 2
#define EXPECTED_SIZEOF_SHORT 2
#define EXPECTED_SIZEOF_USHORT 2
#define EXPECTED_SIZEOF_BOOL 4
#define EXPECTED_SIZEOF_INT 4
#define EXPECTED_SIZEOF_UINT 4
#define EXPECTED_SIZEOF_INT32 4
#define EXPECTED_SIZEOF_UINT32 4
#define EXPECTED_SIZEOF_DWORD 4
#define EXPECTED_SIZEOF_DWORD32 4
#define EXPECTED_SIZEOF_LONG 4
#define EXPECTED_SIZEOF_LONG32 4
#define EXPECTED_SIZEOF_INT64 8
#define EXPECTED_SIZEOF_UINT64 8
#define EXPECTED_SIZEOF_DWORD64 8
#define EXPECTED_SIZEOF_DWORDLONG 8
#define EXPECTED_SIZEOF_LONG64 8
#define EXPECTED_SIZEOF_ULONGLONG 8
#define EXPECTED_SIZEOF_LUID 8
#define EXPECTED_SIZEOF_FILETIME 8
#define EXPECTED_SIZEOF_LARGE_INTEGER 8
#define EXPECTED_SIZEOF_ULARGE_INTEGER 8
#define EXPECTED_SIZEOF_GUID 16
#define EXPECTED_SIZEOF_SYSTEMTIME 16
#define EXPECTED_SIZEOF_SIZE_T sizeof(void*)
#define EXPECTED_SIZEOF_INT_PTR sizeof(void*)
#define EXPECTED_SIZEOF_UINT_PTR sizeof(void*)
#define EXPECTED_SIZEOF_DWORD_PTR sizeof(void*)
#define EXPECTED_SIZEOF_LONG_PTR sizeof(void*)
#define EXPECTED_SIZEOF_ULONG_PTR sizeof(void*)

#define TEST_SIZEOF_TYPE(_name)                                                                    \
	if (sizeof(_name) != EXPECTED_SIZEOF_##_name)                                                  \
	{                                                                                              \
		fprintf(stderr, "sizeof(%s) mismatch: Actual: %" PRIuz ", Expected: %" PRIuz "\n", #_name, \
		        sizeof(_name), (size_t)EXPECTED_SIZEOF_##_name);                                   \
		status = -1;                                                                               \
	}

int TestTypes(int argc, char* argv[])
{
	int status = 0;

	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);

	TEST_SIZEOF_TYPE(INT8)
	TEST_SIZEOF_TYPE(UINT8)

	TEST_SIZEOF_TYPE(BYTE)
	TEST_SIZEOF_TYPE(BOOLEAN)
	TEST_SIZEOF_TYPE(CHAR)
	TEST_SIZEOF_TYPE(UCHAR)

	TEST_SIZEOF_TYPE(INT16)
	TEST_SIZEOF_TYPE(UINT16)

	TEST_SIZEOF_TYPE(WORD)
	TEST_SIZEOF_TYPE(WCHAR)
	TEST_SIZEOF_TYPE(SHORT)
	TEST_SIZEOF_TYPE(USHORT)

	/* fails on OS X */
	// TEST_SIZEOF_TYPE(BOOL)

	TEST_SIZEOF_TYPE(INT)
	TEST_SIZEOF_TYPE(UINT)
	TEST_SIZEOF_TYPE(DWORD)
	TEST_SIZEOF_TYPE(DWORD32)
	TEST_SIZEOF_TYPE(LONG)
	TEST_SIZEOF_TYPE(LONG32)

	TEST_SIZEOF_TYPE(INT32)
	TEST_SIZEOF_TYPE(UINT32)

	TEST_SIZEOF_TYPE(INT64)
	TEST_SIZEOF_TYPE(UINT64)

	TEST_SIZEOF_TYPE(DWORD64)
	TEST_SIZEOF_TYPE(DWORDLONG)

	TEST_SIZEOF_TYPE(LONG64)
	TEST_SIZEOF_TYPE(ULONGLONG)

	TEST_SIZEOF_TYPE(LUID)
	TEST_SIZEOF_TYPE(FILETIME)
	TEST_SIZEOF_TYPE(LARGE_INTEGER)
	TEST_SIZEOF_TYPE(ULARGE_INTEGER)

	TEST_SIZEOF_TYPE(GUID)
	TEST_SIZEOF_TYPE(SYSTEMTIME)

	TEST_SIZEOF_TYPE(SIZE_T)
	TEST_SIZEOF_TYPE(INT_PTR)
	TEST_SIZEOF_TYPE(UINT_PTR)
	TEST_SIZEOF_TYPE(DWORD_PTR)
	TEST_SIZEOF_TYPE(LONG_PTR)
	TEST_SIZEOF_TYPE(ULONG_PTR)

	return status;
}
