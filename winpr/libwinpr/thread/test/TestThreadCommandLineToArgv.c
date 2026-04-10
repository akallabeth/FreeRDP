
#include <stdio.h>
#include <winpr/crt.h>
#include <winpr/thread.h>

#include "../thread.h"

static const char* test_args_line_1 = "app.exe abc d e";

static const char* test_args_list_1[] = { "app.exe", "abc", "d", "e" };

static const char* test_args_line_2 = "app.exe abc  \t   def";

static const char* test_args_list_2[] = { "app.exe", "abc", "def" };

static const char* test_args_line_3 = "app.exe \"abc\" d e";

static const char* test_args_list_3[] = { "app.exe", "abc", "d", "e" };

static const char* test_args_line_4 = "app.exe a\\\\b d\"e f\"g h";

static const char* test_args_list_4[] = { "app.exe", "a\\\\b", "de fg", "h" };

static const char* test_args_line_5 = "app.exe a\\\\\\\"b c d";

static const char* test_args_list_5[] = { "app.exe", "a\\\"b", "c", "d" };

static const char* test_args_line_6 = "app.exe a\\\\\\\\\"b c\" d e";

static const char* test_args_list_6[] = { "app.exe", "a\\\\b c", "d", "e" };

static const char* test_args_line_7 = "app.exe a\\\\\\\\\"b c\" d e f\\\\\\\\\"g h\" i j";

static const char* test_args_list_7[] = { "app.exe", "a\\\\b c", "d", "e", "f\\\\g h", "i", "j" };

static const char* test_args_line_8 = "app.exe arg1 \"arg2\"";

static const char* test_args_list_8[] = { "app.exe", "arg1", "arg2" };

static BOOL check_test_result(const char* what, const void* pArgs, const char* line, int numArgs,
                              size_t expect)
{
	if (numArgs < 0)
	{
		(void)fprintf(stderr, "[%s] expected %" PRIuz " arguments, got %d return\n", what, expect,
		              numArgs);
		return FALSE;
	}
	if (numArgs != expect)
	{
		(void)fprintf(stderr, "[%s] expected %" PRIuz " arguments, got %d from '%s'\n", what,
		              expect, numArgs, line);
		return FALSE;
	}

	if ((numArgs > 0) && !pArgs)
	{
		(void)fprintf(stderr, "[%s] expected %d arguments, got nullptr return\n", what, numArgs);
		return FALSE;
	}

	printf("[%s] pNumArgs: %d\n", what, numArgs);
	return TRUE;
}

static BOOL check_test_result_and_free_a(const char* what, LPSTR* pArgs, const char* line,
                                         const char** list, int numArgs, size_t expect)
{
	BOOL rc = check_test_result(what, pArgs, line, numArgs, expect);
	if (!rc)
		goto fail;

	for (int i = 0; i < numArgs; i++)
	{
		printf("[%s] argv[%d] = %s\n", what, i, pArgs[i]);
		if (strcmp(pArgs[i], list[i]) != 0)
		{
			(void)fprintf(stderr, "[%s] failed at argument %d: got '%s' but expected '%s'\n", what,
			              i, pArgs[i], list[i]);
			goto fail;
		}
	}

	rc = TRUE;
fail:
	free((void*)pArgs);

	return rc;
}

static BOOL test_command_line_parsing_case(const char* line, const char** list, size_t expect)
{
	BOOL rc = FALSE;
	int numArgs = 0;

	printf("Parsing: %s\n", line);

	if (strchr(line, ' '))
	{
		char* str = _strdup(line);
		if (!line)
			return FALSE;
		BOOL rc = FALSE;
		char* cmd = strchr(str, ' ');
		if (cmd)
		{
			*cmd++ = '\0';
			LPSTR* pArgs = CommandLineToArgvExA(str, cmd, &numArgs);
			rc = check_test_result_and_free_a("CommandLineToArgvExA(program, line)", pArgs, line,
			                                  list, numArgs, expect);
		}
		free(str);
		if (!rc)
			return rc;
	}

	{
		LPSTR* pArgs = CommandLineToArgvA(line, &numArgs);
		if (!check_test_result_and_free_a("CommandLineToArgvA", pArgs, line, list, numArgs, expect))
			return FALSE;
	}
	{
		LPSTR* pArgs = CommandLineToArgvExA(nullptr, line, &numArgs);
		if (!check_test_result_and_free_a("CommandLineToArgvExA(nullptr, line)", pArgs, line, list,
		                                  numArgs, expect))
			return FALSE;
	}
	{
		LPSTR* pArgs = CommandLineToArgvExA(line, nullptr, &numArgs);
		if (!check_test_result_and_free_a("CommandLineToArgvExA(line, nullptr)", pArgs, line, list,
		                                  numArgs, expect))
			return FALSE;
	}
	return TRUE;
}

int TestThreadCommandLineToArgv(int argc, char* argv[])
{

	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);

	if (!test_command_line_parsing_case(test_args_line_1, test_args_list_1,
	                                    ARRAYSIZE(test_args_list_1)))
		return -1;
	if (!test_command_line_parsing_case(test_args_line_2, test_args_list_2,
	                                    ARRAYSIZE(test_args_list_2)))
		return -1;
	if (!test_command_line_parsing_case(test_args_line_3, test_args_list_3,
	                                    ARRAYSIZE(test_args_list_3)))
		return -1;
	if (!test_command_line_parsing_case(test_args_line_4, test_args_list_4,
	                                    ARRAYSIZE(test_args_list_4)))
		return -1;
	if (!test_command_line_parsing_case(test_args_line_5, test_args_list_5,
	                                    ARRAYSIZE(test_args_list_5)))
		return -1;
	if (!test_command_line_parsing_case(test_args_line_6, test_args_list_6,
	                                    ARRAYSIZE(test_args_list_6)))
		return -1;
	if (!test_command_line_parsing_case(test_args_line_7, test_args_list_7,
	                                    ARRAYSIZE(test_args_list_7)))
		return -1;
	if (!test_command_line_parsing_case(test_args_line_8, test_args_list_8,
	                                    ARRAYSIZE(test_args_list_8)))
		return -1;

	return 0;
}
