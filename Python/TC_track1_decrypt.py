from testharness import *
from testharness.tlvparser import TLVParser
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from binascii import hexlify, unhexlify

#
# BDK: This is an acronym for Base Derivation Key. This key is known only to the manufacturer and #      the software developer interfacing with the magstripe scanner.

# IPEK: This is an acronym for Initial Pin Encryption Key. This key is derived from the BDK. This #       key is injected onto the device by the manufacturer and is used to derive future keys. 
#       Compromising the IPEK does not compromise the BDK.
# IPEK is derived using TripleDES encryption

# KSN: This is an acronym for Key Serial Number. The KSN is a combo of the serial number of the 
#      magstripe scanner and a counter representing the number of swipes that have taken place on
#      the device.
#

BDK = b'0123456789ABCDEFFEDCBA9876543210'
KSN = b'FFFF9876543211000620'
KEY = b'AC2B83C506DEC9D5E27D51E1D70559E7'


def track1_decrypt():
  # -----------------------------------------------------------------
  # SRED ENCRYPTED TAG FF7F
  # -----------------------------------------------------------------
  #
  # DFDB0F: ENCRYPTION STATUS
  # Last transaction encryption status. 0=successful encryption, any other value
  # indicates an error.
  #dfdb0f-04-00000000
  
  # DFDF10: ENCRYPTED DATA  #dfdf10-50-87a73106f57b8fbdd383a257ed8c713a62bfae83e9b0d202c50fe1f7da8739338c768ba61506c1d3404191c7c8c3016929a0cce6621b95191d5a006382605fb0c17963725b548abc37ffda146e0429e7
  
  # DFDF11: KSN
  #dfdf11-0a-ffff9876543211000620
  
  # DFDF12: IV DATA
  #dfdf12-08-a79ddd0ff736b32b
  
  # -----------------------------------------------------------------
  # ALGORITHM
  # -----------------------------------------------------------------
  
  # TAG DFDF11
  ksn = b'FFFF9876543211000620'
  
  # TAG DFDF10
  encrypted_data = b'87a73106f57b8fbdd383a257ed8c713a62bfae83e9b0d202c50fe1f7da8739338c768ba61506c1d3404191c7c8c3016929a0cce6621b95191d5a006382605fb0c17963725b548abc37ffda146e0429e7'
  
  # SS = %
  # FC = FORMAT CODE
  # FC = ^
  # ES = ?
  # LRC = 8000
  decrypted_data = b'7846D845D274861F32343138303030313233343536335E4644435320544553542043415244202F4D4153544552434152445E32353132313031303030313131313132333435363738393031323F438000'
  
  
  # REPLACING FIELD SEPARATORS 46 ('^') WITH 2A ('*')
  #     D8  D2  86 ... 80
  #data = b'78462A452A742A1F32343138303030313233343536335E4644435320544553542043415244202F4D4153544552434152445E32353132313031303030313131313132333435363738393031323F432A00'
  
  data = b'753ACB9CADC3DD3E3935333139323335313030343D323530323130313130303831323334353030303F35800000000000'
  
  # DERIVED KEY: AC2B83C506DEC9D5E27D51E1D70559E7
  
  bytes_object = bytes.fromhex(data.decode('ascii'))
  log.log('DATA', bytes_object.decode('ascii'))

  # OUTPUT: xF*E*t*24180001234563^FDCS TEST CARD /MASTERCARD^25121010001111123456789012?C*

if __name__ == '__main__':
	log = getSyslog()
	conn = connection.Connection();
	utility.register_testharness_script( track1_decrypt )
	utility.do_testharness()
