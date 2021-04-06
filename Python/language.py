from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from sys import exit
from functools import partial
from binascii import hexlify, unhexlify

def process_language(lang, is_list, is_user):
	req_unsolicited = conn.connect()
	if req_unsolicited:
		status, buf, uns = conn.receive()
		check_status_error(status)

	p1 = 0x00 if is_user else 0x01 if lang or is_list else 0x02
	p2 = 0x00 if is_list else 0x01
	conn.send([0xD2, 0xD0, p1, p2],
		[[(0xDF, 0xA2, 0x22), bytes(lang, encoding='utf-8')]] if lang else None)
	status, buf, uns = conn.receive()
	check_status_error(status)

	tlv = TLVParser(buf)
	languages = tlv.getTag((0xDF, 0xA2, 0x20))

	if lang: return

	if len(languages) == 0:
		log.logerr("No language returned")
		exit(1)

	log.log("Available languages:" if is_list
		else "User selected language:" if is_user
		else "Current language:",
		", ".join(l.decode('utf-8') for l in languages))

if __name__ == '__main__':
	parser = utility.get_argparser()
	group = parser.add_mutually_exclusive_group()
	group.add_argument('--select', dest='language', help='Language to select, e.g. POL')
	group.add_argument('--user', action='store_true', help='User (a.k.a. automatic) language selection')
	group.add_argument('--list', action='store_true', help='List available languages')
	args = utility.parse_args();
	log = getSyslog()
	conn = connection.Connection();
	utility.register_testharness_script(partial(process_language, args.language, args.list, args.user))
	utility.do_testharness()
