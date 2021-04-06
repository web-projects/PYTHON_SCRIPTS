/*
 * =====================================================================================
 *
 *       Filename:  gvrsimmodule.c
 *
 *    Description:  GVR sim module python interface
 *
 *        Version:  1.0
 *        Created:  20.10.2014 09:21:17
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Lucjan Bryndza (LB), lucck
 *   Organization:  
 *
 * =====================================================================================
 */
//export PYTHONPATH=$PYTHONPATH:/home/lucck/workspace/testharness/plugins/gvrsim/test/usr/lib/python3.4/site-packages
//python setup.py install --root $(pwd)/test
#include <Python.h>
#include "upm_vault.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
/* ------------------------------------------------------------------ */
static PyObject* gvr_error;
/* ------------------------------------------------------------------ */
// Print SSL error
static void _gvr_exception_( const char *function, int code ) {
	 int err = ERR_get_error();
	 char edesc[256];
	 PyErr_Format( gvr_error, "%s: error %i: %s", function, code, ERR_error_string( err , edesc ) );
}
#define gvr_exception( code ) _gvr_exception_( __PRETTY_FUNCTION__,  code )
/* ------------------------------------------------------------------ */
//! Convert Pylist to gvr buf
static struct gvr_buf* pylist_to_gvr_buf( PyObject *object, size_t* len )
{
	if( !len ) {
		return NULL;
	}
	int res = PyTuple_Size( object );
	if( res != 1 ) {
		PyErr_SetString( gvr_error, "to_gvr_buf: Object is not a tuple or len !=1" );
		return NULL;
	}
	PyObject *list = PyTuple_GetItem( object, 0 );
	res = PyList_Size( list );
	if( res < 0 ) {
		*len = 0;
		PyErr_SetString( gvr_error, "to_gvr_buf: Object is not a list" );
		return NULL;
	} else {
		*len = res;
	}
	struct gvr_buf* buf = calloc( *len, sizeof(struct gvr_buf) );
	size_t i;
	for( i=0; i<*len; ++i ) {
		const void* tbuf; Py_ssize_t tlen;
		PyObject* item =  PyList_GetItem( list, i );
		if( PyObject_AsReadBuffer( item, &tbuf, &tlen ) < 0 ) {
			free( buf ); 
			*len = 0;
			return NULL;
		}
		buf[i].cert = tbuf;
		buf[i].len = tlen;
	}
	return buf;
}
/* ------------------------------------------------------------------ */
//! Read UPM keys
PyDoc_STRVAR( doc_read_upm_pubkey,
"read_upm_pubkey() -> (pkeyexp, pkeymod )\n\
Get public key from library\n\
pkeyexp - Public exponent\n\
pkeymod - Public key modulus" );
static PyObject* read_upm_pubkey( PyObject *self, PyObject *args ) 
{
	unsigned char pmod[4096];
	int mod_len = 0;
	int exp = 0;
	if( !PyArg_ParseTuple( args, "" ) ) {
		return NULL;
	}
	int ret = gvr_readUPMpubkey( pmod, &mod_len, &exp );
	if( ret ) {
		gvr_exception( ret );
		return NULL;
	}
	return Py_BuildValue("iy#", exp, pmod, mod_len );
}
/* ------------------------------------------------------------------ */
//! Initialize NS
PyDoc_STRVAR( doc_initialize_ns,
"initialize_ns( listcerts ) -> crypto1\n\
Initialize Needham-Schroeder session\n\
listcert - List of certificates in byte buffer\n\
Return: crypto1 - Output cryptogram" );
static PyObject* initialize_ns( PyObject *self, PyObject *args ) 
{
	size_t n_certs = 0;
	struct gvr_buf* gvr_buf = pylist_to_gvr_buf( args, &n_certs );
	if( !gvr_buf ) {
		return NULL;
	}
	unsigned char crypto1[256];
	if(0)
	{
		int i, j ;
		printf("NCERTS=%lu\n", n_certs );
		for( i=0; i<n_certs; ++i ) {
			printf("LEN=%u %p\n", gvr_buf[i].len, gvr_buf[i].cert );
			for( j=0; j< gvr_buf[i].len; ++j ) {
				printf("%02x ", gvr_buf[i].cert[j] );
			}
			printf("\n");
		}
	}
	int ret = gvr_initiateNS( crypto1, gvr_buf, n_certs );
	if( ret ) {
		gvr_exception( ret );
		free( gvr_buf );
		return NULL;
	}
	free( gvr_buf );
	return Py_BuildValue( "y#", crypto1, sizeof(crypto1) );
}
/* ------------------------------------------------------------------ */
//! Initialize NS
PyDoc_STRVAR( doc_update_dev_certificate_chain,
"update_dev_certificate_chain( listcerts ) -> None\n\
Update certificate chain and read it from device\n\
listcert - List of certificates in byte buffer" );
static PyObject* update_dev_certificate_chain( PyObject *self, PyObject *args ) 
{
	size_t n_certs = 0;
	struct gvr_buf* gvr_buf = pylist_to_gvr_buf( args, &n_certs );
	if( !gvr_buf ) {
		return NULL;
	}
	int ret = gvr_readUX300CertificateChain( gvr_buf, n_certs );
	if( ret ) {
		gvr_exception(ret);
		free( gvr_buf );
		return NULL;
	}
	free( gvr_buf );
	Py_INCREF(Py_None);
	return Py_None;
}
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
//! Finalize NS
PyDoc_STRVAR( doc_finalize_ns,
"finalize_ns(crypto2) -> crypto3\n\
Finalize Needham-Schroeder session\n\
modulus - Input modulus\n\
crypto2 - Input cryptogram\n\
Return: crypto3 - Output cryptogram" );
static PyObject* finalize_ns( PyObject *self, PyObject *args )
{
	int crypto2len=0; unsigned char* crypto2 = NULL; 
	size_t modlen = 0; unsigned char* mod = NULL;
	unsigned char crypto3[16];
	if( !PyArg_ParseTuple( args, "y#y#", &mod, &modlen, &crypto2, &crypto2len ) ) {
		return NULL;
	}
	if( crypto2 == NULL ) {
		PyErr_SetString( gvr_error, "Crypto2 is empty" );
		return NULL;
	}
	int ret = gvr_finalizeNS( 0, modlen, mod, crypto2, crypto3 );
	if( ret ) {
		gvr_exception( ret );
		return NULL;
	}
	return Py_BuildValue("y#", crypto3, sizeof(crypto3) );
}
/* ------------------------------------------------------------------ */
//! Encrypt PIN
PyDoc_STRVAR( doc_encrypt_pin,
"encrypt_pin(sessionkey) -> encpin\n\
Encrypt and return pin\n\
sessionkey - Input sesssion key\n\
Return: encpin - Output encrypted pin" );
static PyObject* encrypt_pin( PyObject *self, PyObject *args ) 
{
	int sesslen=0; unsigned char* sesskey = NULL; 
	unsigned char pin[8];
	memset( pin, 0, sizeof pin );
	if( !PyArg_ParseTuple( args, "y#", &sesskey, &sesslen ) ) {
		return NULL;
	}
	if( sesskey == NULL ) {
		PyErr_SetString( gvr_error, "Session key is empty" );
		return NULL;
	}
	//!NOTE: This stupid library assume 16 bytes session len
	if( sesslen != 16 ) {
		PyErr_SetString( gvr_error, "Invalid session length must be equal 16" );
		return NULL;
	}
	int ret = gvr_encryptPin( sesskey, pin );
	if( ret ) {
		gvr_exception( ret );
		return NULL;
	}
	return Py_BuildValue("y#", pin, sizeof(pin) );
}
/* ------------------------------------------------------------------ */
//! Encrypt PIN
PyDoc_STRVAR( doc_encrypt_password,
"encrypt_password(sessionkey, password) -> encpasswd\n\
Encrypt and return pin\n\
sessionkey - Input sesssion key\n\
password - Input password to encrypt\n\
Return: encpasswd - Output encrypted password" );
static PyObject* encrypt_password( PyObject *self, PyObject *args )
{
	int sesslen=0; unsigned char* sesskey = NULL; 
	char* ipwd = NULL;
	if( !PyArg_ParseTuple( args, "y#s", &sesskey, &sesslen, &ipwd ) ) {
		return NULL;
	}
	if( sesskey == NULL ) {
		PyErr_SetString( gvr_error, "Session key is empty" );
		return NULL;
	}
	//!NOTE: This stupid library assume 16 bytes session len
	if( sesslen != 16 ) {
		PyErr_SetString( gvr_error, "Invalid session length must be equal 16" );
		return NULL;
	}
	if( !ipwd ) {
		PyErr_SetString( gvr_error, "Password not provided");
	}
	if( strlen( ipwd ) > 8 ) {
		PyErr_SetString( gvr_error, "Maximum password length > 8" );
		return NULL;
	}
	unsigned char opwd[8];
	int ret = gvr_encryptPassword( sesskey, ipwd, opwd );
	if( ret ) {
		gvr_exception( ret );
		return NULL;
	}
	return Py_BuildValue("y#", opwd, sizeof(opwd) );
}
/* ------------------------------------------------------------------ */
//! GVR method definitions
static PyMethodDef gvr_methods[] = {
    {"read_upm_pubkey",  read_upm_pubkey, METH_VARARGS, doc_read_upm_pubkey },
    {"initiate_ns",  initialize_ns, METH_VARARGS, doc_initialize_ns },
    {"finalize_ns",  finalize_ns, METH_VARARGS, doc_finalize_ns },
    {"encrypt_pin",  encrypt_pin, METH_VARARGS, doc_encrypt_pin },
    {"encrypt_password", encrypt_password, METH_VARARGS, doc_encrypt_password },
    {"update_dev_certificate_chain", update_dev_certificate_chain, METH_VARARGS, doc_update_dev_certificate_chain },
    {NULL, NULL, 0, NULL}        /* Final nothing else */
};
//! Gvr sim module definition
PyDoc_STRVAR( doc_gvrsim, "UX pinpand encryption API" );
static PyModuleDef gvrsim_module = {
	PyModuleDef_HEAD_INIT,
	"gvrsim",
	doc_gvrsim,
	-1,
	gvr_methods
};
/* ------------------------------------------------------------------ */
//Initialize openssl
static void openssl_init(void)
{
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_CRYPTO_strings();
	OpenSSL_add_all_algorithms();
}
/* ------------------------------------------------------------------ */
PyMODINIT_FUNC PyInit_gvrsim(void) 
{
	PyObject *m = PyModule_Create( &gvrsim_module );
	if( m == NULL ) {
		return NULL;
	}   
	openssl_init();
	gvr_error = PyErr_NewException("gvrsim.error", NULL, NULL);
    Py_INCREF(gvr_error);
    PyModule_AddObject(m, "error", gvr_error);
	return m;
}
/* ------------------------------------------------------------------ */
