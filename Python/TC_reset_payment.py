#!/usr/bin/python3
'''
Created on 08-05-2020

@authors: Jon Bianco
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
def processReset():
    req_unsolicited = conn.connect()
    if req_unsolicited:
        #Receive unsolicited
        log.log('Waiting for unsolicited')
        #status, buf, uns = getAnswer(False)
        #log.log('Unsolicited', TLVParser(buf) )

    #Send abort command
    #conn.send([0xD0, 0xFF, 0x00, 0x00])
    #status, buf, uns = getAnswer()
    
    #Send device reset
    #conn.send([0xD0, 0x00, 0x00, 0x00])
    #status, buf, uns = getAnswer()

    #Send get card status
    conn.send([0xD0, 0x60, 0x3F, 0x00])
    status, buf, uns = conn.receive()
    
    tlv = TLVParser(buf)
     
    if tlv.tagCount((0x48)) == 1:
        reset_ans = tlv.getTag((0x48))[0]
        log.log("reset state: ", bytes(reset_ans))
        
    #Send get card status - disable ICC/MSR reader
    conn.send([0xD0, 0x60, 0xC0, 0x00])
    status, buf, uns = conn.receive()
    
    tlv = TLVParser(buf)

    if tlv.tagCount((0x48)) == 1:
        reset_ans = tlv.getTag((0x48))[0]
        log.log("reset state: ", bytes(reset_ans))
        
        
if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection()

    utility.register_testharness_script(processReset)
    utility.do_testharness()


