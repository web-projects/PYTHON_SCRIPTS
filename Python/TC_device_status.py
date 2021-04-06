#!/usr/bin/python3
'''
Created on 21-06-2012

@authors: Lucjan_B1, Kamil_P1
'''

from testharness import *
from testharness.tlvparser import TLVParser, tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import getch, kbhit, check_status_error
from binascii import hexlify, unhexlify
from time import sleep

# Finalise the script, clear the screen
def performCleanup():
    # Clear screen
    conn.send([0xD2, 0x01, 0x01, 0x01])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer(True, False)
    # Disconnect

# Gets answer from the device, optionally ignoring unsolicited and stopping on errors
def getAnswer(ignoreUnsolicited = True, stopOnErrors = True):
    while True:
        status, buf, uns = conn.receive()
        if uns and ignoreUnsolicited:
            log.log('Unsolicited packet detected: ', TLVParser(buf))
            continue
        if status != 0x9000:
            log.logerr('Pinpad reported error ', hex(status))
            if stopOnErrors:
                performCleanup()
                exit(-1)
        break
    return status, buf, uns
    
#
# Main function
def processReset():
   ''' First create connection '''
   req_unsolicited = conn.connect()
   ''' If unsolicited read it'''
   if req_unsolicited:
    status, buf, uns = conn.receive()
    check_status_error( status )
         
   # Abort Current Command
   conn.send([0xD0, 0xFF, 0x00, 0x00])
   log.log('*** ABORT CURRENT COMMAND ***')
   status, buf, uns = getAnswer()        
   
   # Send reset device
   # P2
   #    Bit 1 – PTID IN SERIAL RESPONSE
   #    Bit 4 - BEEP DURING RESET
   conn.send([0xD0, 0x00, 0x00, 0x09])
   status, buf, uns = getAnswer()
   tlv = TLVParser(buf)
   tid = tlv.getTag((0x9F, 0x1E))
   type = tlv.getTag((0xDF, 0x0D))
   
   # REPORT DEVICE TYPE
   display_message = ''
   if len(type): 
       type = str(type[0], 'iso8859-1')
       display_message = '\x0D\x09' + 'DEVICE: ' + type
   
   
   # REPORT TID
   if len(tid): 
       tid = str(tid[0], 'iso8859-1')
       display_message = display_message + '\x0D\x09' + 'TID: ' + tid
       log.log(display_message)
   else: 
       tid = ''
       display_message = 'Invalid TID (or cannot determine TID)!'
       log.logerr(display_message)

   # DISPLAY [D2, 01]
   conn.send([0xD2, 0x01, 0x00, 0x01], display_message)
   status, buf, uns = getAnswer()
   sleep(3.000)
        
   #Reset display - regardless of tx type
   conn.send([0xD2, 0x01, 0x01, 0x00])
   log.log('*** RESET DISPLAY ***')
   status, buf, uns = getAnswer()        

if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection()

    utility.register_testharness_script(processReset)
    utility.do_testharness()
