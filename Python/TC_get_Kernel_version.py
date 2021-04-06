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

CONVERT_INT = 1
CONVERT_STRING = 2

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
def processGetKernelVersion():
    req_unsolicited = conn.connect()
    if req_unsolicited:
        #Receive unsolicited
        log.log('Waiting for unsolicited')
        #status, buf, uns = getAnswer(False)
        #log.log('Unsolicited', TLVParser(buf) )

    # reset device: command response contains versions and device SN
    conn.send([0xD0, 0x00, 0x00, 0x01])
    status, buf, uns = getAnswer()
    tlv = TLVParser(buf)
    tid = tlv.getTag((0x9F, 0x1E))
    if len(tid): 
        tid = str(tid[0], 'iso8859-1')
        log.log('TID (S/N):', tid)
    else: 
        tid = ''
        log.logerr('Invalid TID (or cannot determine TID)!')

    # a000000003101001
    # a0 00 00 00 03 10 10
    aid = b'\xa0\x00\x00\x00\x03\x10\x10'
    #c_tag = tagStorage()
    #c_tag.store((0x9F, 0x06), aid)
    #c_tag.store((0x9F, 0x06, 0x0E), aid)
    tags = [
      [(0x9F, 0x06), aid ]
    ]
    e0_templ = ( 0xE0, tags )
   
    ''' 
    Main EMV parameters which affect kernel configuration checksum:
        1. Terminal Type (9F35)
        2. Terminal Capabilities (9F33)
        3. Terminal Additional Capabilities (9F40)
    '''
    #Send Get EMV Hash Values
    ''' iccdata.dat and icckeys.key required with RELEASE firmware '''
    #conn.send([0xDE, 0x01, 0x00, 0x00], c_tag.getTemplate(0xE0))
    conn.send([0xDE, 0x01, 0x00, 0x00], e0_templ)

    status, buf, uns = conn.receive()
    check_status_error( status )
    
    #tlv = TLVParser(buf)
    #tid = tlv.getTag((0x9F, 0x1E))
    #if len(tid): 
    #    tid = str(tid[0], 'iso8859-1')
    #    log.log('Terminal TID: ', tid)
    #else: 
    #    tid = ''
    #    log.logerr('Invalid TID (or cannot determine TID)!')

if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection()

    utility.register_testharness_script(processGetKernelVersion)
    utility.do_testharness()


