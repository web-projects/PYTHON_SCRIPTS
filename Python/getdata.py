from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from sys import exit
from functools import partial
from binascii import hexlify, unhexlify

def getdata(tag):
	req_unsolicited = conn.connect()
	if req_unsolicited:
		status, buf, uns = conn.receive()
		check_status_error(status)

	conn.send([0x00, 0xCA, 0x00, 0x00], unhexlify(tag))
	status, buf, uns = conn.receive()
	check_status_error(status)

	tlv = TLVParser(buf)
	values = tlv.getTag(tuple(unhexlify(tag)))
	if len(values) == 0:
		log.logerr("No tag found:", tag)
		exit(1)

	log.log("Value for tag", tag, ":")
	log.log(" * hex:", hexlify(values[0]).decode('utf-8'))
	log.log(" * ascii:", values[0].decode('utf-8'))
	log.log(" * int:", int.from_bytes(values[0], byteorder='big', signed=True))

if __name__ == '__main__':
	utility.get_argparser().add_argument('tag', help='Tag to retrieve (e.g. "DF69")')
	args = utility.parse_args();
	log = getSyslog()
	conn = connection.Connection();
	utility.register_testharness_script(partial(getdata, args.tag))
	utility.do_testharness()
