#!/usr/bin/python3
'''
Created on 23-07-2020

@authors: Jon_Bianco
'''

from testharness import *
from testharness.tlvparser import TLVParser, tagStorage
from sys import exit
from testharness.syslog import getSyslog

# BYTE 1
RETURN_SERIAL_NUMBER   = 1 << 0
RETURN_PIN_PAD_CONFIG  = 1 << 6
RETURN_VOS_INFORMATION = 1 << 7

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
def processExtendedReset():
    req_unsolicited = conn.connect()
    if req_unsolicited:
        #Receive unsolicited
        log.log('Waiting for unsolicited')
        #status, buf, uns = getAnswer(False)
        #log.log('Unsolicited', TLVParser(buf) )

    # BIT 0 - ReturnSerialNumber
    # BIT 6 - ReturnPinpadConfiguration
    # BIT 7 - AddVOSComponentsInformation
    P2 = RETURN_SERIAL_NUMBER | RETURN_PIN_PAD_CONFIG | RETURN_VOS_INFORMATION
    
    #Send extended software reset device
    conn.send([0xD0, 0x00, 0x00, P2])
    status, buf, uns = getAnswer()
    
    # search for terminal TID
    tlv = TLVParser(buf)
    tid = tlv.getTag((0x9F, 0x1e))
    if len(tid): 
        tid = str(tid[0], 'iso8859-1')
        log.log('Terminal TID: ', tid)
    else: 
        tid = ''
        log.logerr('Invalid TID (or cannot determine TID)!')

    # VIPA restart
    #P1 = 0x02 # VIPA restart
    #P2 = 0x08 # BEEP
    #conn.send([0xD0, 0x00, P1, P2])
    
    # wait for answer
    #status, buf, uns = getAnswer() 

    #Reset display - IDLE SCREEN, BACKLIGHT OFF
    #conn.send([0xD2, 0x01, 0x01, 0x00])
    #status, buf, uns = getAnswer()  
   
if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection()

    utility.register_testharness_script(processExtendedReset)
    utility.do_testharness()
