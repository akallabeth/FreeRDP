#include <stdio.h>
#include <stdlib.h>

#include "font_writer.h"
#include "opensans_variable_font.h"

char* create_and_return_temorary_font(void)
{
	static int initial = 1;
	static char template[] = "/tmp/opensans-variable-font_XXXXXX";
	if (initial != 0)
	{
		int fd = mkstemp(template);
		if (fd < 0)
			return NULL;

		FILE* fp = fdopen(fd, "w");
		if (!fp)
			return NULL;

		fwrite(font_buffer, 1, sizeof(font_buffer), fp);
		fclose(fp);
		initial = 0;
	}
	return template;
}
