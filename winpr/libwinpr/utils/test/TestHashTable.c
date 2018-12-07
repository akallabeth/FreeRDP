
#include <winpr/crt.h>
#include <winpr/tchar.h>
#include <winpr/collections.h>

static char* key1 = "key1";
static char* key2 = "key2";
static char* key3 = "key3";

static char* val1 = "val1";
static char* val2 = "val2";
static char* val3 = "val3";

static int test_hash_table_pointer(void)
{
	int rc = -1;
	size_t count;
	char* value;
	wHashTable* table;
	table = HashTable_New(TRUE);

	if (!table)
		return -1;

	if (!HashTable_Add(table, key1, val1) ||
	    !HashTable_Add(table, key2, val2) ||
	    !HashTable_Add(table, key3, val3))
		goto fail;

	count = HashTable_Count(table);

	if (count != 3)
	{
		printf("HashTable_Count: Expected : 3, Actual: %"PRIdz"\n", count);
		goto fail;
	}

	if (!HashTable_Remove(table, key2))
		goto fail;

	count = HashTable_Count(table);

	if (count != 2)
	{
		printf("HashTable_Count: Expected : 2, Actual: %"PRIdz"\n", count);
		goto fail;
	}

	if (!HashTable_Remove(table, key3))
		goto fail;

	count = HashTable_Count(table);

	if (count != 1)
	{
		printf("HashTable_Count: Expected : 1, Actual: %"PRIdz"\n", count);
		goto fail;
	}

	if (!HashTable_Remove(table, key1))
		goto fail;

	count = HashTable_Count(table);

	if (count != 0)
	{
		printf("HashTable_Count: Expected : 0, Actual: %"PRIdz"\n", count);
		goto fail;
	}

	if (!HashTable_Add(table, key1, val1) ||
	    !HashTable_Add(table, key2, val2) ||
	    !HashTable_Add(table, key3, val3))
		goto fail;

	count = HashTable_Count(table);

	if (count != 3)
	{
		printf("HashTable_Count: Expected : 3, Actual: %"PRIdz"\n", count);
		goto fail;
	}

	value = (char*) HashTable_GetItemValue(table, key1);

	if (strcmp(value, val1) != 0)
	{
		printf("HashTable_GetItemValue: Expected : %s, Actual: %s\n", val1, value);
		goto fail;
	}

	value = (char*) HashTable_GetItemValue(table, key2);

	if (strcmp(value, val2) != 0)
	{
		printf("HashTable_GetItemValue: Expected : %s, Actual: %s\n", val2, value);
		goto fail;
	}

	value = (char*) HashTable_GetItemValue(table, key3);

	if (strcmp(value, val3) != 0)
	{
		printf("HashTable_GetItemValue: Expected : %s, Actual: %s\n", val3, value);
		goto fail;
	}

	if (!HashTable_SetItemValue(table, key2, "apple"))
		goto fail;

	value = (char*) HashTable_GetItemValue(table, key2);

	if (strcmp(value, "apple") != 0)
	{
		printf("HashTable_GetItemValue: Expected : %s, Actual: %s\n", "apple", value);
		goto fail;
	}

	if (!HashTable_Contains(table, key2))
	{
		printf("HashTable_Contains: Expected : TRUE, Actual: FALSE\n");
		goto fail;
	}

	if (!HashTable_Remove(table, key2))
	{
		printf("HashTable_Remove: Expected : TRUE, Actual: FALSE\n");
		goto fail;
	}

	if (HashTable_Remove(table, key2))
	{
		printf("HashTable_Remove: Expected : FALSE, Actual: TRUE\n");
		goto fail;
	}

	HashTable_Clear(table);
	count = HashTable_Count(table);

	if (count != 0)
	{
		printf("HashTable_Count: Expected : 0, Actual: %"PRIdz"\n", count);
		goto fail;
	}

	rc = 1;
fail:
	HashTable_Free(table);
	return rc;
}

static int test_hash_table_string(void)
{
	int rc = -1;
	size_t count;
	char* value;
	wHashTable* table;
	wObject* keyObj;
	wObject* valObj;
	table = HashTable_New(TRUE);

	if (!table)
		return -1;

	keyObj = HashTable_KeyObject(table);
	valObj = HashTable_KeyObject(table);

	if (!keyObj || !valObj || !HashTable_SetHashFunction(table, HashTable_StringHash))
		goto fail;

	keyObj->fnObjectEquals = HashTable_StringCompare;
	keyObj->fnObjectNew = HashTable_StringClone;
	keyObj->fnObjectFree = HashTable_StringFree;
	valObj->fnObjectEquals = HashTable_StringCompare;
	valObj->fnObjectNew = HashTable_StringClone;
	valObj->fnObjectFree = HashTable_StringFree;
	HashTable_Add(table, key1, val1);
	HashTable_Add(table, key2, val2);
	HashTable_Add(table, key3, val3);
	count = HashTable_Count(table);

	if (count != 3)
	{
		printf("HashTable_Count: Expected : 3, Actual: %"PRIdz"\n", count);
		goto fail;
	}

	if (!HashTable_Remove(table, key2))
		goto fail;

	count = HashTable_Count(table);

	if (count != 2)
	{
		printf("HashTable_Count: Expected : 3, Actual: %"PRIdz"\n", count);
		goto fail;
	}

	if (!HashTable_Remove(table, key3))
		goto fail;

	count = HashTable_Count(table);

	if (count != 1)
	{
		printf("HashTable_Count: Expected : 1, Actual: %"PRIdz"\n", count);
		goto fail;
	}

	if (!HashTable_Remove(table, key1))
		goto fail;

	count = HashTable_Count(table);

	if (count != 0)
	{
		printf("HashTable_Count: Expected : 0, Actual: %"PRIdz"\n", count);
		goto fail;
	}

	HashTable_Add(table, key1, val1);
	HashTable_Add(table, key2, val2);
	HashTable_Add(table, key3, val3);
	count = HashTable_Count(table);

	if (count != 3)
	{
		printf("HashTable_Count: Expected : 3, Actual: %"PRIdz"\n", count);
		goto fail;
	}

	value = (char*) HashTable_GetItemValue(table, key1);

	if (strcmp(value, val1) != 0)
	{
		printf("HashTable_GetItemValue: Expected : %s, Actual: %s\n", val1, value);
		goto fail;
	}

	value = (char*) HashTable_GetItemValue(table, key2);

	if (strcmp(value, val2) != 0)
	{
		printf("HashTable_GetItemValue: Expected : %s, Actual: %s\n", val2, value);
		goto fail;
	}

	value = (char*) HashTable_GetItemValue(table, key3);

	if (strcmp(value, val3) != 0)
	{
		printf("HashTable_GetItemValue: Expected : %s, Actual: %s\n", val3, value);
		goto fail;
	}

	HashTable_SetItemValue(table, key2, "apple");
	value = (char*) HashTable_GetItemValue(table, key2);

	if (strcmp(value, "apple") != 0)
	{
		printf("HashTable_GetItemValue: Expected : %s, Actual: %s\n", "apple", value);
		goto fail;
	}

	if (!HashTable_Contains(table, key2))
	{
		printf("HashTable_Contains: Expected : TRUE, Actual: FALSE\n");
		goto fail;
	}

	if (!HashTable_Remove(table, key2))
	{
		printf("HashTable_Remove: Expected : TRUE, Actual: FALSE\n");
		goto fail;
	}

	if (HashTable_Remove(table, key2))
	{
		printf("HashTable_Remove: Expected : FALSE, Actual: TRUE\n");
		goto fail;
	}

	HashTable_Clear(table);
	count = HashTable_Count(table);

	if (count != 0)
	{
		printf("HashTable_Count: Expected : 0, Actual: %"PRIdz"\n", count);
		goto fail;
	}

	rc = 1;
fail:
	HashTable_Free(table);
	return rc;
}

int TestHashTable(int argc, char* argv[])
{
	if (test_hash_table_pointer() < 0)
		return 1;

	if (test_hash_table_string() < 0)
		return 1;

	return 0;
}
