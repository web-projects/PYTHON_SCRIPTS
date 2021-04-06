from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error

ENTRY_PAN = 1 << 0
ENTRY_EXPIRY_DATE = 1 << 1
ENTRY_EFFECTIVE_DATE = 1 << 2
ENTRY_CVV2 = 1 << 3

def entry():
	req_unsolicited = conn.connect()
	if req_unsolicited:
		status, buf, uns = conn.receive()
		check_status_error(status)

	conn.send([0xD2, 0x01, 0x01, 0x00])  # Reset display
	status, buf, uns = conn.receive()
	check_status_error(status)

	p1 = ENTRY_PAN | ENTRY_EXPIRY_DATE
	conn.send( [0xD2, 0x14, p1, 0x03], [
		[(0xDF, 0xAA, 0x02), b'TEMPLATE_INPUT_TYPE'], [(0xDF, 0xAA, 0x03), b'number'],
		[(0xDF, 0xAA, 0x02), b'input_precision'], [(0xDF, 0xAA, 0x03), b'0'],
		[(0xDF, 0xAA, 0x02), b'entry_mode_visibility'], [(0xDF, 0xAA, 0x03), b'hidden'],
		[(0xDF, 0xAA, 0x02), b'timeout'], [(0xDF, 0xAA, 0x03), b'30'],

		[(0xDF, 0xAA, 0x01), b'mapp/alphanumeric_entry.html'],
		[(0xDF, 0xAA, 0x02), b'title_text'], [(0xDF, 0xAA, 0x03), b'Enter PAN'],

		[(0xDF, 0xAA, 0x01), b'mapp/alphanumeric_entry.html'],
		[(0xDF, 0xAA, 0x02), b'title_text'], [(0xDF, 0xAA, 0x03), b'Enter Exp'],

		[(0xDF, 0x83, 0x05), 0x10 ],
	])

	status, buf, uns = conn.receive()
	check_status_error(status)

if __name__ == '__main__':
	log = getSyslog()
	conn = connection.Connection();
	utility.register_testharness_script(entry)
	utility.do_testharness()
