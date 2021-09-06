#include <winpr/assert.h>
#include <winpr/wlog.h>
#include <freerdp/scancode.h>

int TestScancodes(int argc, char* argv[])
{
	UINT16 x;
	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);

	for (x = 0; x < 0x200; x++)
	{
		size_t l;
		const char* name = freerdp_scancode_to_string(x);
		WINPR_ASSERT(name);

		l = strnlen(name, 64);
		WINPR_ASSERT(l > 0);
		WINPR_ASSERT(l < 64);

		WLog_INFO(__FUNCTION__, "0x%04" PRIxz " -> %s", x, name);
	}
	return 0;
}
