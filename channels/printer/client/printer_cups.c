/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Print Virtual Channel - CUPS driver
 *
 * Copyright 2010-2011 Vic Lee
 * Copyright 2015 Thincast Technologies GmbH
 * Copyright 2015 DI (FH) Martin Haimberger <martin.haimberger@thincast.com>
 * Copyright 2016 Armin Novak <armin.novak@gmail.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <time.h>
#include <cups/cups.h>

#include <winpr/crt.h>
#include <winpr/string.h>

#include <freerdp/channels/rdpdr.h>

#include "printer_main.h"

#include "printer_cups.h"

typedef struct rdp_cups_printer_driver rdpCupsPrinterDriver;
typedef struct rdp_cups_printer rdpCupsPrinter;
typedef struct rdp_cups_print_job rdpCupsPrintJob;

#ifndef _CUPS_API_1_4
#define LEGACY_CUPS_API
#endif

struct rdp_cups_printer_driver
{
	rdpPrinterDriver driver;

	int id_sequence;
};

struct rdp_cups_printer
{
	rdpPrinter printer;
};

struct rdp_cups_print_job
{
	rdpPrintJob printjob;

#if defined(LEGACY_CUPS_API)
	FILE* cups;
#else
	http_t* cups;
#endif
};

static void printer_cups_get_printjob_name(char* buf, size_t size)
{
	time_t tt;
	struct tm* t;
	tt = time(NULL);
	t = localtime(&tt);
	sprintf_s(buf, size - 1, "FreeRDP Job %d%02d%02d%02d%02d%02d",
	          t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
	          t->tm_hour, t->tm_min, t->tm_sec);
}

#if defined(LEGACY_CUPS_API)
static UINT printer_cups_print_file(rdpCupsPrintJob* job, FILE* file)
{
	http_t* cups;
	rdpCupsPrinter* printer;
	int id;
	UINT result = ERROR_INTERNAL_ERROR;
	ipp_status_t status;
	http_status_t http;
	size_t pos, x;
	int nrOptions = 0;
	cups_option_t* options = NULL;
	char jobtitle[100];
	printer = (rdpCupsPrinter*) job->printjob.printer;
	pos = _ftelli64(file);
	cups = httpConnectEncrypt(cupsServer(), ippPort(), HTTP_ENCRYPT_IF_REQUESTED);

	if (!cups)
		return ERROR_INTERNAL_ERROR;

	printer_cups_get_printjob_name(jobtitle, sizeof(jobtitle));
	id = cupsCreateJob(cups, printer->printer.name, jobtitle, nrOptions, options);

	if (id == 0)
		goto fail;

	x = 0;
	_fseeki64(file, 0, SEEK_SET);
	http = cupsStartDocument(cups, printer->printer.name, id, jobtitle, CUPS_FORMAT_AUTO, 1);

	while ((http == HTTP_STATUS_CONTINUE) && (x < pos))
	{
		char buffer[1000];
		size_t read = fread(buffer, 1, sizeof(buffer), file);

		if ((read == 0) && (!feof(file)))
			goto fail2;
		else
			http = cupsWriteRequestData(cups, buffer, read);

		x += read;
	}

	if (http != HTTP_STATUS_CONTINUE)
	{
	fail2:
		cupsFinishDocument(cups, printer->printer.name);
		cupsCancelJob2(cups, printer->printer.name, id, 0);
		goto fail;
	}
	else
	{
		status = cupsFinishDocument(cups, printer->printer.name);

		if (status != IPP_OK)
			goto fail;
	}

	result = CHANNEL_RC_OK;
fail:
	cupsFreeOptions(nrOptions, options);
	httpClose(cups);
	return result;
}
#endif

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT printer_cups_write_printjob(rdpPrintJob* printjob, const BYTE* data, size_t size)
{
#if !defined(LEGACY_CUPS_API)
	http_status_t http;
#endif
	rdpCupsPrinter* printer;
	rdpCupsPrintJob* cups_printjob = (rdpCupsPrintJob*) printjob;

	if (!cups_printjob || !cups_printjob->cups)
		return ERROR_INTERNAL_ERROR;

	printer = (rdpCupsPrinter*) printjob->printer;
#if !defined(LEGACY_CUPS_API)
	http = cupsWriteRequestData(cups_printjob->cups, (const char*)data, size);

	if (http != HTTP_STATUS_CONTINUE)
	{
		cupsCancelJob2(cups_printjob->cups, printer->printer.name, printjob->id, 0);
		return ERROR_INTERNAL_ERROR;
	}

#else

	if (fwrite(data, 1, size, cups_printjob->cups) != size)
		return ERROR_INTERNAL_ERROR;

#endif
	return CHANNEL_RC_OK;
}

static void printer_cups_free_printjob(rdpPrintJob* printjob)
{
	rdpCupsPrintJob* cups_printjob = (rdpCupsPrintJob*) printjob;

	if (cups_printjob && cups_printjob->cups)
	{
#if !defined(LEGACY_CUPS_API)
		rdpCupsPrinter* printer = (rdpCupsPrinter*) printjob->printer;

		if (printer->printer.id != 0)
			cupsFinishDocument(cups_printjob->cups, printer->printer.name);

		httpClose(cups_printjob->cups);
#else
		printer_cups_print_file(cups_printjob, cups_printjob->cups);
		fclose(cups_printjob->cups);
#endif
	}

	free(cups_printjob);
}

static rdpPrintJob* printer_cups_create_printjob(rdpPrinter* printer, UINT32 id)
{
	rdpCupsPrinter* cups_printer = (rdpCupsPrinter*) printer;
	rdpCupsPrintJob* cups_printjob;
#if !defined(LEGACY_CUPS_API)
	char jobtitle[100];
	http_status_t http;
#endif

	if (!cups_printer)
		return NULL;

	cups_printjob = (rdpCupsPrintJob*) calloc(1, sizeof(rdpCupsPrintJob));

	if (!cups_printjob)
		return NULL;

	cups_printjob->printjob.id = id;
	cups_printjob->printjob.printer = printer;
	cups_printjob->printjob.Write = printer_cups_write_printjob;
#if !defined(LEGACY_CUPS_API)
	cups_printjob->cups = httpConnectEncrypt(cupsServer(), ippPort(), HTTP_ENCRYPT_IF_REQUESTED);

	if (!cups_printjob->cups)
		goto fail;

	printer_cups_get_printjob_name(jobtitle, sizeof(jobtitle));
	printer->id = cupsCreateJob(cups_printjob->cups, printer->name, jobtitle, 0, NULL);

	if (printer->id <= 0)
		goto fail;

	http = cupsStartDocument(cups_printjob->cups, printer->name, printer->id, jobtitle,
	                         CUPS_FORMAT_AUTO, 1);

	if (http != HTTP_STATUS_CONTINUE)
		goto fail;

#else
	cups_printjob->cups = tmpfile();

	if (!cups_printjob->cups)
		goto fail;

#endif
	return &cups_printjob->printjob;
fail:
	printer_cups_free_printjob((rdpPrintJob*) cups_printjob);
	return NULL;
}

static void printer_cups_free_printer(rdpPrinter* printer)
{
	rdpCupsPrinter* cups_printer = (rdpCupsPrinter*) printer;

	if (cups_printer)
	{
		free(printer->name);
		free(printer->driver);
		free(printer);
	}
}

static rdpPrinter* printer_cups_new_printer(rdpCupsPrinterDriver* cups_driver,
        const char* name, const char* driverName, BOOL is_default)
{
	rdpCupsPrinter* cups_printer = (rdpCupsPrinter*) calloc(1, sizeof(rdpCupsPrinter));

	if (!cups_printer)
		return NULL;

	cups_printer->printer.id = cups_driver->id_sequence++;
	cups_printer->printer.name = _strdup(name);

	if (!cups_printer->printer.name)
		goto fail;

	if (driverName)
		cups_printer->printer.driver = _strdup(driverName);
	else
		cups_printer->printer.driver = _strdup("MS Publisher Imagesetter");

	if (!cups_printer->printer.driver)
		goto fail;

	cups_printer->printer.is_default = is_default;
	cups_printer->printer.CreatePrintJob = printer_cups_create_printjob;
	cups_printer->printer.DestroyPrintJob = printer_cups_free_printjob;
	cups_printer->printer.Free = printer_cups_free_printer;
	return &cups_printer->printer;
fail:
	printer_cups_free_printer(&cups_printer->printer);
	return NULL;
}

static rdpPrinter** printer_cups_enum_printers(rdpPrinterDriver* driver)
{
	rdpPrinter** printers;
	int num_printers;
	cups_dest_t* dests;
	cups_dest_t* dest;
	int num_dests;
	int i;
	num_dests = cupsGetDests(&dests);
	printers = (rdpPrinter**) calloc(num_dests + 1, sizeof(rdpPrinter*));

	if (!printers)
		return NULL;

	num_printers = 0;

	for (i = 0, dest = dests; i < num_dests; i++, dest++)
	{
		if (dest->instance == NULL)
		{
			printers[num_printers++] = printer_cups_new_printer((rdpCupsPrinterDriver*) driver,
			                           dest->name, NULL, dest->is_default);
		}
	}

	cupsFreeDests(num_dests, dests);
	return printers;
}

static rdpPrinter* printer_cups_get_printer(rdpPrinterDriver* driver,
        const char* name, const char* driverName)
{
	rdpCupsPrinterDriver* cups_driver = (rdpCupsPrinterDriver*) driver;
	return printer_cups_new_printer(cups_driver, name, driverName,
	                                cups_driver->id_sequence == 1 ? TRUE : FALSE);
}

static rdpCupsPrinterDriver* cups_driver = NULL;

rdpPrinterDriver* printer_cups_get_driver(void)
{
	if (cups_driver == NULL)
	{
		cups_driver = (rdpCupsPrinterDriver*) calloc(1, sizeof(rdpCupsPrinterDriver));

		if (!cups_driver)
			return NULL;

		cups_driver->driver.EnumPrinters = printer_cups_enum_printers;
		cups_driver->driver.GetPrinter = printer_cups_get_printer;
		cups_driver->id_sequence = 1;
	}

	return &cups_driver->driver;
}

