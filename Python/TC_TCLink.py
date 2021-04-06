#!/usr/bin/python3
'''
Created on 03-01-2020

@authors: Matthew_H
'''

from TC_testharness import *
import TC_testharness.utility as util
from functools import partial
from TC_testharness.tlvparser import TLVParser
from TC_testharness.tlvparser import TLVPrepare
from sys import exit
from TC_testharness.syslog import getSyslog
from TC_testharness.utility import getch, kbhit
from binascii import hexlify, unhexlify
from time import sleep
import traceback

''' install: pip install pywin32 '''
import win32com.client
tclink = win32com.client.Dispatch("TCLinkCOM.TClink")

ENCRYPTED_TRACK_IV = ''
ENCRYPTED_TRACK_KSN = ''
ENCRYPTED_TRACK_DATA = ''
DEVICE_SERIAL = ''
EMV_TAGS = { }


def setDeviceSerial(deviceSerial):
	global DEVICE_SERIAL
	DEVICE_SERIAL = deviceSerial

# Capture/update encrypted track values
def saveCardData(tlv):
	global ENCRYPTED_TRACK_IV, ENCRYPTED_TRACK_KSN, ENCRYPTED_TRACK_DATA
	#print(">>> saveCardData ff7f count", tlv.tagCount((0xFF,0x7F)))
	if tlv.tagCount((0xFF,0x7F)):
		#log.log('>>> vsp_tlv bytes', tlv.getTag((0xFF,0x7F))[0])
		tlvp = TLVPrepare()
		vsp_tlv_tags = tlvp.parse_received_data( tlv.getTag((0xFF,0x7F))[0] )
		vsp_tlv = TLVParser(vsp_tlv_tags)
		#vsp_tlv = TLVParser(tlv.getTag((0xFF,0x7F))[0])
		#log.log('>>> buf', buf)
		#log.log('>>> tlv', tlv)
		#log.log('>>> vsp_tlv_tags', vsp_tlv_tags)
		#log.log('>>> vsp_tlv', vsp_tlv)
		#if vsp_tlv.tagCount((0xDF,0xDF,0x10)):
		#	print(">>> saveCardData vsp_tlv DFDF10", hexlify(vsp_tlv.getTag((0xDF,0xDF,0x10))[0]))
		#if vsp_tlv.tagCount((0xDF,0xDF,0x11)):
		#	print(">>> saveCardData vsp_tlv DFDF11", hexlify(vsp_tlv.getTag((0xDF,0xDF,0x11))[0]))
		#if vsp_tlv.tagCount((0xDF,0xDF,0x12)):
		#	print(">>> saveCardData vsp_tlv DFDF12", hexlify(vsp_tlv.getTag((0xDF,0xDF,0x12))[0]))
		if vsp_tlv.tagCount((0xDF,0xDF,0x10)) and vsp_tlv.tagCount((0xDF,0xDF,0x11)) and vsp_tlv.tagCount((0xDF,0xDF,0x12)):
			print(">>> saveCardData save data")
			ENCRYPTED_TRACK_IV = vsp_tlv.getTag((0xDF,0xDF,0x12))[0].hex().upper()
			ENCRYPTED_TRACK_KSN = vsp_tlv.getTag((0xDF,0xDF,0x11))[0].hex().upper()
			ENCRYPTED_TRACK_DATA = vsp_tlv.getTag((0xDF,0xDF,0x10))[0].hex().upper()

def processMSRTransaction(custid, password, action):
	global DEVICE_SERIAL, ENCRYPTED_TRACK_IV, ENCRYPTED_TRACK_KSN, ENCRYPTED_TRACK_DATA
	#print(">>> processMSRTransaction id", custid, "pass", password, "act", action, "iv", ENCRYPTED_TRACK_IV)
	tclink.PushNameValue("custid="+str(custid))
	tclink.PushNameValue("password="+password)
	tclink.PushNameValue("action="+action)
	tclink.PushNameValue("amount=100")
	tclink.PushNameValue("emv_device_capable=n")
	tclink.PushNameValue("encryptedtrack="+"TVP|iv:"+ENCRYPTED_TRACK_IV+"|ksn:"+ENCRYPTED_TRACK_KSN+"|vipa:"+ENCRYPTED_TRACK_DATA)
	tclink.PushNameValue("aggregators=1")
	tclink.PushNameValue("aggregator1=L9XPR6")
	tclink.PushNameValue("device_serial="+DEVICE_SERIAL)
	#print("encryptedtrack="+"TVP|iv:"+ENCRYPTED_TRACK_IV+"|ksn:"+ENCRYPTED_TRACK_KSN+"|vipa:"+ENCRYPTED_TRACK_DATA)
	tclink.Submit()
	print("Status: ", tclink.GetResponse("status"))
	
def processEMVTransaction(custid, password, action):
	global DEVICE_SERIAL, ENCRYPTED_TRACK_IV, ENCRYPTED_TRACK_KSN, ENCRYPTED_TRACK_DATA, EMV_TAGS
	#print(">>> processEMVTransaction id", custid, "pass", password, "act", action, "iv", ENCRYPTED_TRACK_IV)
	tclink.PushNameValue("custid="+str(custid))
	tclink.PushNameValue("password="+password)
	tclink.PushNameValue("action="+action)
	tclink.PushNameValue("amount=100")
	tclink.PushNameValue("emv_device_capable=n")
	tclink.PushNameValue("encryptedtrack="+"TVP|iv:"+ENCRYPTED_TRACK_IV+"|ksn:"+ENCRYPTED_TRACK_KSN+"|vipa:"+ENCRYPTED_TRACK_DATA)
	tclink.PushNameValue("aggregators=1")
	tclink.PushNameValue("aggregator1=L9XPR6")
	tclink.PushNameValue("device_serial="+DEVICE_SERIAL)
	#print("encryptedtrack="+"TVP|iv:"+ENCRYPTED_TRACK_IV+"|ksn:"+ENCRYPTED_TRACK_KSN+"|vipa:"+ENCRYPTED_TRACK_DATA)
	tclink.Submit()
	print("Status: ", tclink.GetResponse("status"))