#!/usr/bin/python3

'''
Created on 15-11-2012

@author: Tomasz_S1
'''

import binascii

from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog

from testharness.tlvparser import TLVPrepare


def Tags2Array(tags):
	tlvp = TLVPrepare()
	arr = tlvp.prepare_packet_from_tags(tags)
	del arr[0]
	return arr

def Array2Tags(array):
	#array[0:0] = [0, 0]
	tlvp = TLVPrepare()
	tags = tlvp.parse_received_data( array )
	return tags
		
def SendPassThruPacket(conn, cmd, tags):
	tlvp = TLVPrepare()
	packet = tlvp.prepare_packet_from_tags(tags)
	packet[0] = cmd		# cmd code


	passThruTags = [
		[ (0xdf, 0x1f), [0x30] ],		# POS timeout		
		[ (0xdf, 0xc0, 0x59), packet ]
	]		
	passThruTmpl = ( 0xe0, passThruTags )

	# send pass thru packet
	conn.send([0xc0, 0xf8, 0x03, 0x00], passThruTmpl)


def transtest_function():
	log = getSyslog()
	conn = connection.Connection();
	
	#
	# !!! NOTE: Now you can set connection parameters from command line!
	#
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


	#####################################################
	# Get handle
	conn.send([0xc0, 0xf8, 0x01, 0x00])
	status, buf, uns = conn.receive()
	if status != 0x9000:
		log.logerr('Get handle fail', hex(status), buf)
		exit(-1)

	tlv = TLVParser(buf)
	cicappHandle = tlv.getTag((0xdf,0xc0,0x01), TLVParser.CONVERT_INT)[0]
	log.log('Handle=', hex(cicappHandle))

	#####################################################
	# Force proxy mode
	log.log('Force MAPP ctls proxy mode')
	conn.send([0xc0, 0xf8, 0x02, 0x01])
	status, buf, uns = conn.receive()
	if status != 0x9000:
		log.logerr('Control proxy mode fail', hex(status), buf)
		exit(-1)

	#####################################################
	# Send 'StartTxn' with MIFARE poll
	log.log('Sending StartTxn with MIFARE polling on');
	innerTags = [
		[(0x9F, 0x02), b'\x00\x00\x00\x00\x04\x56' ],
		[(0x9C), b'\x00'],
		[(0x5F,0x2A), b'\x08\x26' ],
		[(0x9F,0x1A), b'\x08\x26' ]
	]
		
	passThruCtlTags = [
		[ (0xdf, 0xc0, 0x01), [cicappHandle] ],
		[ (0xdf, 0x1f), [0x05] ],		# POS timeout
		[ (0xdf, 0xc0, 0x30), Tags2Array(innerTags) ],	# Transaction data
		[ (0xdf, 0xc0, 0x31), [0x01] ],	# Transaction result request
		[ (0xdf, 0xc0, 0x3d), [0x01] ]	# TransactionSelectionMask: PollForMIFARE
	]

	# 203 = StartTransaction
	SendPassThruPacket(conn, 203, passThruCtlTags)
	status, buf, uns = conn.receive()
	if status != 0x9000:
		log.logerr('Send pass-thru fail', hex(status), buf)
		exit(-1)
			

	log.log("Waiting for card tap");
	
	# Wait for unsolicited message
	transactionOutcome = -1
	while True:
		status, buf, uns = conn.receive()
		if status != 0x9000:
			log.logerr('Wait for card fail!')
			exit(-1)
		
		# Check the buffer for transaction outcome
		log.log('type(buf)=', type(buf));
		log.log('buf=', buf);
		tlv = TLVParser(buf)
		print('tlv=', tlv)
		
		rawCICAPPFrame = tlv.getTag((0xdf,0xc0,0x59))
		if len(rawCICAPPFrame) == 0:
			log.logerr('Unexpected frame received')
		else:
			# FULL CICAPP frame received
			frameData = rawCICAPPFrame[0]
			cmdCode = frameData.pop(0)
			log.log('Received response for command', hex(cmdCode), "=", cmdCode)

			tlv = TLVParser(Array2Tags(frameData))
			print('tlv=', tlv)
			transactionOutcome = tlv.getTag((0xdf,0xc0,0x36), TLVParser.CONVERT_INT)
			if (len(transactionOutcome) > 0):
				transactionOutcome = transactionOutcome[0]
				log.log('TransactionOutcome=', transactionOutcome)
				break
			
			resultCode = tlv.getTag((0xdf,0x30), TLVParser.CONVERT_INT)
			print('resultCodeLen=', len(resultCode))
			if (len(resultCode) > 0):
				resultCode = resultCode[0]
				log.log('resultCode=', resultCode)
				if resultCode != 250:
					break
				
	# TransactionOutcome::SwitchedToPassThru=50
	if transactionOutcome == 50:
		# Pass thru card - display serial number and type
		cardType = tlv.getTag((0xdf,0xc0,0x41), TLVParser.CONVERT_INT)
		if (len(cardType)): cardType = cardType[0]
		cardSerial = tlv.getTag((0xdf,0xc0,0x42), TLVParser.CONVERT_HEX_STR)
		if (len(cardSerial)): cardSerial = cardSerial[0]
		log.log('cardType=', cardType, ' cardSerial=', cardSerial);
		
		#####################################################
		# Send 'PassThruDisable'
		log.log('Disabling pass-thru');
		passThruCtlTags = [
			[ (0xdf, 0xc0, 0x01), [cicappHandle] ],
			[ (0xdf, 0x1f), [0x30] ],		# POS timeout
			[ (0xdf, 0xc0, 0x40), [0x00] ]
		]
		SendPassThruPacket(conn, 220, passThruCtlTags)
		status, buf, uns = conn.receive()
		if status != 0x9000:
			log.logerr('Send pass-thru fail', hex(status), buf)
			exit(-1)
				


if __name__ == '__main__':
	utility.register_testharness_script(transtest_function)
	utility.do_testharness()
