'''
Created on 28-03-2012

@author: Lucjan_B1
'''

from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog


def transtest_function():
	log = getSyslog()
	conn = connection.Connection();
	#Create ssl server
	#conn.connect_serial('COM1', 57600, timeout=2 );
	req_unsolicited = conn.connect()
	if req_unsolicited:
		#Receive unsolicited
		status, buf, uns = conn.receive()
		if status != 0x9000:
			log.logerr('Unsolicited fail')
			exit(-1)
		log.log('Unsolicited', TLVParser(buf) )
	#Send INIT contactless
	conn.send([0xc0, 0x01, 0x00, 0x00])
	status, buf, uns = conn.receive()
	if status != 0x9000:
		log.logerr('ctls init fail')
		exit(-1)

	#Create localtag for transaction
	start_trans_tag = [
		 [(0x9F, 0x02), b'\x00\x00\x00\x00\x04\x56' ],
		 [(0x9C), b'\x00'],
		 [(0x5F,0x2A), b'\x08\x26' ],
		 [(0x9F,0x1A), b'\x08\x26' ]
	]
	start_templ = ( 0xe0, start_trans_tag )
	print(start_templ)
	#Start transaction
	conn.send([0xc0, 0xa0, 0x01, 0x20], start_templ)
	status, buf, uns = conn.receive()
	if status != 0x9000:
		log.logerr('Start transaction fail', hex(status), buf)
		exit(-1)


	# Now wait for the user to CANCEL
	input("ENTER to CANCEL")

	conn.send([0xc0, 0xc0, 0x00, 0x00])
	status, buf, uns = conn.receive()
	if status != 0x9000:
		log.logerr('cancel fail!')
		exit(-1)

	status, buf, uns = conn.receive()
	if status != 0x9000:
		log.logerr('start txn fail!')
		exit(-1)



if __name__ == '__main__':
	utility.register_testharness_script(transtest_function)
	utility.do_testharness()
