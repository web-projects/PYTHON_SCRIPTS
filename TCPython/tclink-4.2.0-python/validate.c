/*
COPYRIGHT AND PERMISSION NOTICE
 
Copyright (c) 1996 - 2010, Daniel Stenberg, <daniel@haxx.se>.
 
All rights reserved.
 
Permission to use, copy, modify, and distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright
notice and this permission notice appear in all copies.
 
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.
 
Except as contained in this notice, the name of a copyright holder shall not
be used in advertising or otherwise to promote the sale, use or other dealings
in this Software without prior written authorization of the copyright holder.
*/
/* simplified to a basic host name check */
#include <string.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#define bool int
#define false 0
#define true 1
/** @fn static bool cert_hostcheck(const char *hostname, char *pattern)
  * Verifies that the hostname matches against the pattern specified.
  * Handles wildcard patterns and ignores the distinction between upper and lower case letters.
  * Note: Ported over from ssluse.c in curl (7.1.16) lib
  * Note: Explicit pattern match disabled as we do not use that for processing node certificate.
  * Note: No longer ignores the distinction between upper and lower case letters.  Our certificate is generated with lowercase letters.
  * @return true if matches, false otherwise
  * @param hostname The hostname we want to check. e.g: vault.trustcommerce.com
  * @param pattern The pattern we wish to match against. e.g: *.trustcommerce.com
  */
bool cert_hostcheck(const char *pattern, const char *hostname)
{
	if (!hostname || !pattern || !*hostname || !*pattern) return false;
	if (!strcmp(hostname,pattern)) return true;
	return false;
}
/** @fn static bool checkCertificate(X509 *cert, char *host)
  * Provides validation of the hostname associated with a certificate.
  * See RFC2818 - Server Identity for an overview of the concept.
  * This implementation is based off the one found in curl-7.16.1: ssluse.c
  * but we treat the subjectAltName as a recommendation... so if it fails, 
  * we will proceed to the CN check.
  * The rationale for this is that we are not always using HTTP (over SSL)
  * and its more of a certification generation / CA issue and we want
  * maximum interoperability (as opposed to strict compliance). 
  * @param cert The X509 certificate in question.
  * @param host The hostname or ip we wish to check.
  * @return true if matches, false otherwise
  */
static bool checkCertificate(X509 * cert, const char *host)
{
	int i,j;
	bool matched = false;
	STACK_OF(GENERAL_NAME) * altnames;
	unsigned char *nulstr = { '\0' };
	unsigned char *peer_CN = nulstr;
	X509_NAME *name;
	ASN1_STRING * tmp;
	bool status = false;

	if (!cert || !host) return false;

	altnames = (STACK_OF(GENERAL_NAME) *)(X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL));

	if (altnames != NULL)
	{
		int numalts = sk_GENERAL_NAME_num(altnames);
		for (i=0; (i<numalts) && (matched == false); i++)
		{
			const GENERAL_NAME *check = sk_GENERAL_NAME_value(altnames, i);
			const char *altptr = (char *)(ASN1_STRING_data(check->d.ia5));
			size_t altlen;
			switch (check->type)
			{
				case GEN_DNS: 
					altlen = ASN1_STRING_length(check->d.ia5);
					if (altlen == strlen(host) && cert_hostcheck(altptr, host))
						matched = true;
					break;
				case GEN_IPADD:
					altlen = ASN1_STRING_length(check->d.ia5);
					if (altlen == strlen(host) && !memcmp(altptr, host, altlen))
						matched = true;
					break;
			}
		}
		GENERAL_NAMES_free(altnames);
		if (matched != false) return true;
	}
	
	i = j = -1;


	name = X509_get_subject_name(cert);
	if (!name) return false;


	// get the last CN found in the subject (supposedly its the most distinguished one)
	while ((j=X509_NAME_get_index_by_NID(name,NID_commonName,i))>=0)
		i=j;

	if (i<0) return false;

	tmp = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, i));
	/* workaround for version of openssl < 0.9.7d */
	if (tmp && ASN1_STRING_type(tmp) == V_ASN1_UTF8STRING)
	{
		j = ASN1_STRING_length(tmp);
		if (j >= 0) {
			peer_CN = (unsigned char *)(OPENSSL_malloc(j+1));
			if (peer_CN)
			{
				memcpy(peer_CN, ASN1_STRING_data(tmp), j);
				peer_CN[j] = '\0';
			}
		}
	}
	else
	{
		j = ASN1_STRING_to_UTF8(&peer_CN, tmp);
	}

	if (peer_CN == nulstr)
		peer_CN = NULL;

	if (peer_CN == NULL)
		return false; // the cn isnt missing in virtually all cases
	else if(!cert_hostcheck((char *)(peer_CN), host))
		status = false;
	else 
		status = true;

	if (peer_CN)
		OPENSSL_free(peer_CN);
	return status;
}

int TCLinkDefaultValidate(int x, void * cert)
{
	if (x != 0 || cert == NULL) return 0;
	return !checkCertificate((X509 *)cert, "pgw1.trustcommerce.com");

}
