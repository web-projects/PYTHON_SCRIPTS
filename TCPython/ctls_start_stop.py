#!/usr/bin/python3

'''
Created on 22-11-2012

@author: Tomasz_S1
'''

from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog


def transtest_function():
	log = getSyslog()
	conn = connection.Connection();
	prev_nad = conn.setnad(2)
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


	# Now wait for the user to send CLOSE
	input("[ENTER] to send 'close'")

	#Send CLOSE contactless
	conn.send([0xc0, 0x02, 0x00, 0x00])
	status, buf, uns = conn.receive()
	if status != 0x9000:
		log.logerr('ctls close fail')
		exit(-1)
	


if __name__ == '__main__':
	utility.register_testharness_script(transtest_function)
	utility.do_testharness()
