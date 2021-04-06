"""
Python Distutils Script for TCLink

distutils documentation
http://www.python.org/doc/current/dist

TClink
http://www.trustcommerce.com/tclink.html

"""

import os, sys, re
import string
from distutils.core import setup, Extension


# if you have ssl/crypto libraries installed in non standard
# locations you may need to specify their location here
include_dirs = ['/usr/local/ssl', '/usr/local/openssl'] 


tclink_version="4.2.0"
machine_info = "%s %s"%( os.uname()[0], # sysname
                         os.uname()[-1] # machine
                         )

machine_info = string.replace(machine_info, ' ', '-')
pytclink_version = '"%s-Python-%s"'%(tclink_version,machine_info)

for item in sys.argv:
	m = re.match("--ca-path=(.*)", item)
	if m:
		pytclink_ca_path = m.group(1)
		sys.argv.remove(item)
		break
else:
	# --ca-path wasn't specified; let's figure out what to use
	# as default
	locations = [
		'/etc/pki/tls/certs/ca-bundle.crt',
		'/etc/ssl/certs/ca-certificates.crt',
		'/etc/pki/tls/certs/ca-bundle.trust.crt',
		'/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',
		'/etc/ssl/certs']
	openssl_ca_path = os.popen('openssl version -d').read() \
		.split('\n')[0];	# grab the first line
	m = re.match('[^"]*"(.*)"', openssl_ca_path)
	if m:
		openssl_ca_path = "%s/certs" % m.group(1)
		print "openssl CA path: %s" % openssl_ca_path
		# append to the front
		locations = [
			'%s/ca-bundle.crt'			% openssl_ca_path,
			'%s/ca-certificates.crt'	% openssl_ca_path,
			'%s/ca-bundle.trust.crt'	% openssl_ca_path,
			'%s/tls-ca-bundle.pem'		% openssl_ca_path,
			'%s'						% openssl_ca_path
			] + locations
	for item in locations:
		if os.path.exists(item):
			pytclink_ca_path = item
			break
	else:	
		print "error: Cannot determine CA path. Please use --ca-path=<path> to specify ca-bundle file or CA directory."
		sys.exit()

print "CA path: %s" % pytclink_ca_path

tclink_extension = Extension("tclink",
                             ["py_tclink.c", "tclink.c", "mem.c", "validate.c"],
                             libraries=["ssl", "crypto"],
                             define_macros=[('TCLINK_VERSION', pytclink_version),
                                            ('TCLINK_CA_PATH', '"{0}"'.format(pytclink_ca_path))],
                             include_dirs = include_dirs
                             )


setup(
    name="TCLink",
    version=tclink_version,
    description="TrustCommerce Transaction Client Library",
    author="TrustCommerce",
    author_email="techsupport@trustcommerce.com",
    url="http://www.trustcommerce.com/",
    ext_modules=[ tclink_extension ]
    )
    
