
#include <stdio.h>
#include <winpr/crt.h>
#include <winpr/sspi.h>
#include <winpr/winpr.h>

static const char* test_User = "User";
static const char* test_Domain = "Domain";
static const char* test_Password = "Password";

int TestAcquireCredentialsHandle(int argc, char* argv[])
{
	int rc = -1;
	SECURITY_STATUS status;
	CredHandle credentials = { 0 };
	TimeStamp expiration;
	PSEC_WINNT_AUTH_IDENTITY_OPAQUE identity = NULL;
	SecurityFunctionTable* table;
	SecPkgCredentials_Names credential_names;
	sspi_GlobalInit();
	table = InitSecurityInterface();

	if (sspi_SetAuthIdentity(&identity, test_User, test_Domain, test_Password) != SEC_E_OK)
		goto fail;

	status = table->AcquireCredentialsHandle(NULL, NTLM_SSP_NAME,
	         SECPKG_CRED_OUTBOUND, NULL, &identity, NULL, NULL, &credentials, &expiration);

	if (status != SEC_E_OK)
		goto fail;

	status = table->QueryCredentialsAttributes(&credentials, SECPKG_CRED_ATTR_NAMES, &credential_names);

	if (status != SEC_E_OK)
		goto fail;

	rc = 0;
fail:

	if (SecIsValidHandle(&credentials))
		table->FreeCredentialsHandle(&credentials);

	sspi_FreeAuthIdentity(identity);
	sspi_GlobalFinish();
	return rc;
}

