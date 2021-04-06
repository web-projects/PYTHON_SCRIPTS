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
def processGetSREDStatus():
    req_unsolicited = conn.connect()
    if req_unsolicited:
        #Receive unsolicited
        log.log('Waiting for unsolicited')
        #status, buf, uns = getAnswer(False)
        #log.log('Unsolicited', TLVParser(buf) )

    #Send command to device
    conn.send([0xDD, 0x20, 0x0F, 0x00])
    status, buf, uns = getAnswer()
    #tlv = TLVParser(buf)
    #tid = tlv.getTag((0x9F, 0x1e))
    #if len(tid): 
    #    tid = str(tid[0], 'iso8859-1')
    #    log.log('Terminal TID: ', tid)
    #else: 
    #    tid = ''
    #    log.logerr('Invalid TID (or cannot determine TID)!')

if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection()

    utility.register_testharness_script(processGetSREDStatus)
    utility.do_testharness()
