from testharness import *
from testharness.tlvparser import TLVParser
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error

ENTRY_MIXED = 0x01
ENTRY_UPPER = 0x02
ENTRY_LOWER = 0x04
ENTRY_NUMERIC = 0x08
ENTRY_ALPHA = 0x10

def password_entry():
	req_unsolicited = conn.connect()
	if req_unsolicited:
		status, buf, uns = conn.receive()
		check_status_error(status)

	conn.send([0xD2, 0x01, 0x01, 0x00])  # Reset display
	status, buf, uns = conn.receive(3)
	check_status_error( status )

	conn.send( [0xD2, 0xF3, 0x00, 0x04], (0xE0, [
		[(0xDF, 0xB0, 0x05), (ENTRY_UPPER | ENTRY_LOWER).to_bytes(4, byteorder='big')],  # entry modes
		[(0xDF, 0xB0, 0x06), (ENTRY_UPPER).to_bytes(4, byteorder='big')],  # initial entry mode
	]))
	status, buf, uns = conn.receive()
	check_status_error( status )

	tlv = TLVParser(buf)
	password = tlv.getTag((0xDF, 0x83, 0x01))[0].decode('utf-8')
	log.log('Password entered:', password)


if __name__ == '__main__':
	log = getSyslog()
	conn = connection.Connection();
	utility.register_testharness_script(password_entry)
	utility.do_testharness()
