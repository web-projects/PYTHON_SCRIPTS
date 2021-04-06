from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from binascii import hexlify, unhexlify


''' How to create example scripts '''
def demo_function():
	''' First create connection '''
	req_unsolicited = conn.connect()
	''' If unsolicited read it'''
	if req_unsolicited:
		status, buf, uns = conn.receive()
		check_status_error( status )
	''' Reset display '''
	conn.send([0xD2, 0x01, 0x01, 0x00])
	status, buf, uns = conn.receive()
	check_status_error( status )

	''' Send data '''
	conn.send_rawhex('010036DD210100B2E0B0DF831308D202964900000000DF831A203030203030203030203030203030203030203030203030203030203030203036')

	''' Check for status '''
	status, buf, uns = conn.receive()
	check_status_error( status )

if __name__ == '__main__':
	log = getSyslog()
	conn = connection.Connection();
	utility.register_testharness_script( demo_function )
	utility.do_testharness()
