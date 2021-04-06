from testharness import *
from testharness.tlvparser import TLVParser
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from sys import exit
from functools import partial
from binascii import hexlify

def get_certificates(is_return_file, level):
	req_unsolicited = conn.connect()
	if req_unsolicited:
		status, buf, uns = conn.receive()
		check_status_error(status)

	p1 = 0x01 if is_return_file else 0x00
	get_all_levels = level is None

	current_level = 0x00 if get_all_levels else level;
	while True:
		conn.send([0xC5, 0x06, p1, 0x00], (0xE0, [
			[(0xDF, 0x83, 0x10), current_level.to_bytes(4, byteorder='big')],
		]))
		status, buf, uns = conn.receive()
		if status == 0x9F13:
			log.log("No more certificates in the chain")
			break
		check_status_error(status)

		tlv = TLVParser(buf)
		certs = tlv.getTag((0xDF, 0x83, 0x12) if is_return_file else (0xDF, 0x83, 0x11))
		if len(certs) != 1:
			log.logerr("One return tag expected in response, got:", len(certs))
			exit(1)

		cert = certs[0].decode('utf-8')
		label = "file name: " if is_return_file else "content:\n"
		log.log("Certificate level %d %s%s" % (current_level, label, cert))

		if not get_all_levels: break
		current_level = current_level + 1

if __name__ == '__main__':
	parser = utility.get_argparser()
	parser.add_argument('--return-file', dest='is_return_file', action='store_true',
		help='Return certificate file name instead of contents')
	parser.add_argument('--level', default=None, type=int,
		help='Certificate level [default: gets whole chain]')
	args = utility.parse_args();
	log = getSyslog()
	conn = connection.Connection();
	utility.register_testharness_script(partial(get_certificates, args.is_return_file, args.level))
	utility.do_testharness()
