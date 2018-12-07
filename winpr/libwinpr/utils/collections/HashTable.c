/**
 * WinPR: Windows Portable Runtime
 * System.Collections.Hashtable
 *
 * Copyright 2014 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

#include <winpr/crt.h>

#include <winpr/collections.h>

/**
 * This implementation is based on the public domain
 * hash table implementation made by Keith Pomakis:
 *
 * http://www.pomakis.com/hashtable/hashtable.c
 * http://www.pomakis.com/hashtable/hashtable.h
 */

struct _wHashTable
{
	BOOL synchronized;
	CRITICAL_SECTION lock;

	size_t numOfBuckets;
	size_t numOfElements;
	float idealRatio;
	float lowerRehashThreshold;
	float upperRehashThreshold;
	wKeyValuePair** bucketArray;

	HASH_TABLE_HASH_FN hash;
	wObject keyObject;
	wObject valueObject;
};

wObject* HashTable_KeyObject(wHashTable* table)
{
	if (!table)
		return NULL;

	return &table->keyObject;
}

wObject* HashTable_ValueObject(wHashTable* table)
{
	if (!table)
		return NULL;

	return &table->valueObject;
}

BOOL HashTable_SetHashFunction(wHashTable* table, HASH_TABLE_HASH_FN fkt)
{
	if (!table || !fkt)
		return FALSE;

	table->hash = fkt;
	return TRUE;
}

BOOL HashTable_PointerCompare(const void* pointer1, const void* pointer2)
{
	return (pointer1 == pointer2);
}

UINT32 HashTable_PointerHash(const void* pointer)
{
	return ((UINT32)(UINT_PTR) pointer) >> 4;
}

BOOL HashTable_StringCompare(const void* string1, const void* string2)
{
	if (!string1 || !string2)
		return (string1 == string2);

	return (strcmp((const char*) string1, (const char*) string2) == 0);
}

UINT32 HashTable_StringHash(const void* key)
{
	UINT32 c;
	UINT32 hash = 5381;
	const BYTE* str = (const BYTE*) key;

	/* djb2 algorithm */
	while ((c = *str++) != '\0')
		hash = (hash * 33) + c;

	return hash;
}

void* HashTable_StringClone(const void* str)
{
	return _strdup((const char*) str);
}

void HashTable_StringFree(void* str)
{
	free(str);
}

static size_t HashTable_IsProbablePrime(size_t oddNumber)
{
	size_t i;

	for (i = 3; i < 51; i += 2)
	{
		if (oddNumber == i)
			return 1;
		else if (oddNumber % i == 0)
			return 0;
	}

	return 1; /* maybe */
}

static size_t HashTable_CalculateIdealNumOfBuckets(wHashTable* table)
{
	size_t idealNumOfBuckets = table->numOfElements / ((size_t) table->idealRatio);

	if (idealNumOfBuckets < 5)
		idealNumOfBuckets = 5;
	else
		idealNumOfBuckets |= 0x01;

	while (!HashTable_IsProbablePrime(idealNumOfBuckets))
		idealNumOfBuckets += 2;

	return idealNumOfBuckets;
}

static void HashTable_Rehash(wHashTable* table, size_t numOfBuckets)
{
	int index;
	UINT32 hashValue;
	wKeyValuePair* pair;
	wKeyValuePair* nextPair;
	wKeyValuePair** newBucketArray;

	if (numOfBuckets == 0)
		numOfBuckets = HashTable_CalculateIdealNumOfBuckets(table);

	if (numOfBuckets == table->numOfBuckets)
		return; /* already the right size! */

	newBucketArray = (wKeyValuePair**) calloc(numOfBuckets, sizeof(wKeyValuePair*));

	if (!newBucketArray)
	{
		/*
		 * Couldn't allocate memory for the new array.
		 * This isn't a fatal error; we just can't perform the rehash.
		 */
		return;
	}

	for (index = 0; index < table->numOfBuckets; index++)
	{
		pair = table->bucketArray[index];

		while (pair)
		{
			nextPair = pair->next;
			hashValue = table->hash(pair->key) % numOfBuckets;
			pair->next = newBucketArray[hashValue];
			newBucketArray[hashValue] = pair;
			pair = nextPair;
		}
	}

	free(table->bucketArray);
	table->bucketArray = newBucketArray;
	table->numOfBuckets = numOfBuckets;
}

static void HashTable_SetIdealRatio(wHashTable* table, float idealRatio,
                                    float lowerRehashThreshold, float upperRehashThreshold)
{
	table->idealRatio = idealRatio;
	table->lowerRehashThreshold = lowerRehashThreshold;
	table->upperRehashThreshold = upperRehashThreshold;
}

static wKeyValuePair* HashTable_Get(wHashTable* table, const void* key)
{
	UINT32 hashValue;
	wKeyValuePair* pair;
	hashValue = table->hash(key) % table->numOfBuckets;
	pair = table->bucketArray[hashValue];

	while (pair && !table->keyObject.fnObjectEquals(key, pair->key))
		pair = pair->next;

	return pair;
}

/**
 * C equivalent of the C# Hashtable Class:
 * http://msdn.microsoft.com/en-us/library/system.collections.hashtable.aspx
 */

/**
 * Properties
 */

/**
 * Gets the number of key/value pairs contained in the HashTable.
 */

size_t HashTable_Count(wHashTable* table)
{
	return table->numOfElements;
}

/**
 * Methods
 */

/**
 * Adds an element with the specified key and value into the HashTable.
 */

BOOL HashTable_Add(wHashTable* table, const void* key, const void* value)
{
	BOOL status = TRUE;
	UINT32 hashValue;
	wKeyValuePair* pair;
	wKeyValuePair* newPair;
	void* ckey;
	void* cvalue;

	if (!key || !value || !table || !table->keyObject.fnObjectNew || !table->valueObject.fnObjectNew)
		return FALSE;

	ckey = table->keyObject.fnObjectNew(key);
	cvalue = table->valueObject.fnObjectNew(value);

	if (!ckey || !cvalue)
		return FALSE;

	if (table->synchronized)
		EnterCriticalSection(&table->lock);

	hashValue = table->hash(key) % table->numOfBuckets;
	pair = table->bucketArray[hashValue];

	while (pair && !table->keyObject.fnObjectEquals(key, pair->key))
		pair = pair->next;

	if (pair)
	{
		if (pair->key != ckey)
		{
			if (table->keyObject.fnObjectFree)
				table->keyObject.fnObjectFree(pair->key);

			pair->key = ckey;
		}

		if (pair->value != cvalue)
		{
			if (table->valueObject.fnObjectFree)
				table->valueObject.fnObjectFree(pair->value);

			pair->value = cvalue;
		}
	}
	else
	{
		newPair = (wKeyValuePair*) malloc(sizeof(wKeyValuePair));

		if (!newPair)
		{
			status = FALSE;
		}
		else
		{
			newPair->key = ckey;
			newPair->value = cvalue;
			newPair->next = table->bucketArray[hashValue];
			table->bucketArray[hashValue] = newPair;
			table->numOfElements++;

			if (table->upperRehashThreshold > table->idealRatio)
			{
				float elementToBucketRatio = (float) table->numOfElements / (float) table->numOfBuckets;

				if (elementToBucketRatio > table->upperRehashThreshold)
					HashTable_Rehash(table, 0);
			}
		}
	}

	if (table->synchronized)
		LeaveCriticalSection(&table->lock);

	return status;
}

/**
 * Removes the element with the specified key from the HashTable.
 */

BOOL HashTable_Remove(wHashTable* table, const void* key)
{
	UINT32 hashValue;
	BOOL status = TRUE;
	wKeyValuePair* pair = NULL;
	wKeyValuePair* previousPair = NULL;

	if (table->synchronized)
		EnterCriticalSection(&table->lock);

	hashValue = table->hash(key) % table->numOfBuckets;
	pair = table->bucketArray[hashValue];

	while (pair && !table->keyObject.fnObjectEquals(key, pair->key))
	{
		previousPair = pair;
		pair = pair->next;
	}

	if (!pair)
	{
		status = FALSE;
	}
	else
	{
		table->keyObject.fnObjectFree(pair->key);
		table->valueObject.fnObjectFree(pair->value);

		if (previousPair)
			previousPair->next = pair->next;
		else
			table->bucketArray[hashValue] = pair->next;

		free(pair);
		table->numOfElements--;

		if (table->lowerRehashThreshold > 0.0)
		{
			float elementToBucketRatio = (float) table->numOfElements / (float) table->numOfBuckets;

			if (elementToBucketRatio < table->lowerRehashThreshold)
				HashTable_Rehash(table, 0);
		}
	}

	if (table->synchronized)
		LeaveCriticalSection(&table->lock);

	return status;
}

/**
 * Get an item value using key
 */

void* HashTable_GetItemValue(wHashTable* table, const void* key)
{
	void* value = NULL;
	wKeyValuePair* pair;

	if (table->synchronized)
		EnterCriticalSection(&table->lock);

	pair = HashTable_Get(table, key);

	if (pair)
		value = pair->value;

	if (table->synchronized)
		LeaveCriticalSection(&table->lock);

	return value;
}

/**
 * Set an item value using key
 */

BOOL HashTable_SetItemValue(wHashTable* table, const void* key, const void* value)
{
	BOOL status = TRUE;
	wKeyValuePair* pair;

	if (table->synchronized)
		EnterCriticalSection(&table->lock);

	pair = HashTable_Get(table, key);

	if (!pair)
		status = FALSE;
	else
	{
		table->valueObject.fnObjectFree(pair->value);
		pair->value = table->valueObject.fnObjectNew(value);
	}

	if (table->synchronized)
		LeaveCriticalSection(&table->lock);

	return status;
}

/**
 * Removes all elements from the HashTable.
 */

void HashTable_Clear(wHashTable* table)
{
	size_t index;
	wKeyValuePair* pair;
	wKeyValuePair* nextPair;

	if (table->synchronized)
		EnterCriticalSection(&table->lock);

	for (index = 0; index < table->numOfBuckets; index++)
	{
		pair = table->bucketArray[index];

		while (pair)
		{
			nextPair = pair->next;
			table->keyObject.fnObjectFree(pair->key);
			table->valueObject.fnObjectFree(pair->value);
			free(pair);
			pair = nextPair;
		}

		table->bucketArray[index] = NULL;
	}

	table->numOfElements = 0;
	HashTable_Rehash(table, 5);

	if (table->synchronized)
		LeaveCriticalSection(&table->lock);
}

/**
 * Gets the list of keys as an array
 */

size_t HashTable_GetKeys(wHashTable* table, ULONG_PTR** ppKeys)
{
	size_t iKey;
	size_t count;
	size_t index;
	ULONG_PTR* pKeys;
	wKeyValuePair* pair;
	wKeyValuePair* nextPair;

	if (table->synchronized)
		EnterCriticalSection(&table->lock);

	iKey = 0;
	count = table->numOfElements;

	if (count < 1)
	{
		if (table->synchronized)
			LeaveCriticalSection(&table->lock);

		return 0;
	}

	pKeys = (ULONG_PTR*) calloc(count, sizeof(ULONG_PTR));

	if (!pKeys)
	{
		if (table->synchronized)
			LeaveCriticalSection(&table->lock);

		return 0;
	}

	for (index = 0; index < table->numOfBuckets; index++)
	{
		pair = table->bucketArray[index];

		while (pair)
		{
			nextPair = pair->next;
			pKeys[iKey++] = (ULONG_PTR) pair->key;
			pair = nextPair;
		}
	}

	if (table->synchronized)
		LeaveCriticalSection(&table->lock);

	*ppKeys = pKeys;
	return count;
}

/**
 * Determines whether the HashTable contains a specific key.
 */

BOOL HashTable_Contains(wHashTable* table, const void* key)
{
	BOOL status;

	if (table->synchronized)
		EnterCriticalSection(&table->lock);

	status = (HashTable_Get(table, key) != NULL) ? TRUE : FALSE;

	if (table->synchronized)
		LeaveCriticalSection(&table->lock);

	return status;
}

/**
 * Determines whether the HashTable contains a specific key.
 */

BOOL HashTable_ContainsKey(wHashTable* table, const void* key)
{
	BOOL status;

	if (table->synchronized)
		EnterCriticalSection(&table->lock);

	status = (HashTable_Get(table, key) != NULL) ? TRUE : FALSE;

	if (table->synchronized)
		LeaveCriticalSection(&table->lock);

	return status;
}

/**
 * Determines whether the HashTable contains a specific value.
 */

BOOL HashTable_ContainsValue(wHashTable* table, const void* value)
{
	size_t index;
	BOOL status = FALSE;
	wKeyValuePair* pair;

	if (table->synchronized)
		EnterCriticalSection(&table->lock);

	for (index = 0; index < table->numOfBuckets; index++)
	{
		pair = table->bucketArray[index];

		while (pair)
		{
			if (table->valueObject.fnObjectEquals(value, pair->value))
			{
				status = TRUE;
				break;
			}

			pair = pair->next;
		}

		if (status)
			break;
	}

	if (table->synchronized)
		LeaveCriticalSection(&table->lock);

	return status;
}

static void* HashTable_NoCopy(const void* value)
{
	return value;
}

/**
 * Construction, Destruction
 */

wHashTable* HashTable_New(BOOL synchronized)
{
	wHashTable* table;
	table = (wHashTable*) calloc(1, sizeof(wHashTable));

	if (table)
	{
		table->synchronized = synchronized;
		InitializeCriticalSectionAndSpinCount(&(table->lock), 4000);
		table->numOfBuckets = 64;
		table->numOfElements = 0;
		table->bucketArray = (wKeyValuePair**) calloc(table->numOfBuckets, sizeof(wKeyValuePair*));

		if (!table->bucketArray)
		{
			free(table);
			return NULL;
		}

		table->idealRatio = 3.0;
		table->lowerRehashThreshold = 0.0;
		table->upperRehashThreshold = 15.0;
		table->hash = HashTable_PointerHash;
		table->keyObject.fnObjectEquals = HashTable_PointerCompare;
		table->keyObject.fnObjectNew = HashTable_NoCopy;
		table->valueObject.fnObjectEquals = HashTable_PointerCompare;
		table->valueObject.fnObjectNew = HashTable_NoCopy;
	}

	return table;
}

void HashTable_Free(wHashTable* table)
{
	size_t index;
	wKeyValuePair* pair;
	wKeyValuePair* nextPair;

	if (table)
	{
		for (index = 0; index < table->numOfBuckets; index++)
		{
			pair = table->bucketArray[index];

			while (pair)
			{
				nextPair = pair->next;

				if (table->keyObject.fnObjectFree)
					table->keyObject.fnObjectFree(pair->key);

				if (table->valueObject.fnObjectFree)
					table->valueObject.fnObjectFree(pair->value);

				free(pair);
				pair = nextPair;
			}
		}

		DeleteCriticalSection(&(table->lock));
		free(table->bucketArray);
		free(table);
	}
}
