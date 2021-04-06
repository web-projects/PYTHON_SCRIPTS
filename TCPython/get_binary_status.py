
######  WARNING -  Be carerful about character encoding ######
###### First line instructs Python to us UTF-8 encoding ######
###### Default will be ASCII if the coding: line removed #####
# coding: utf-8

from testharness import *
from testharness.tlvparser import TLVParser, tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import getch, kbhit
from binascii import hexlify
from time import sleep


# Gets answer from the device, optionally ignoring unsolicited and stopping on errors
def getAnswer(ignoreUnsolicited = True, stopOnErrors = True, noErrors = False):
    while True:
        status, buf, uns = conn.receive()
        if uns and ignoreUnsolicited:
            log.log('Unsolicited packet detected: ', TLVParser(buf))
            continue
        if status != 0x9000 and (not noErrors):
            log.logerr('Pinpad reported error ', hex(status))
            if stopOnErrors:
                performCleanup()
                log.logerr('*** TEST BEING HALTED ABNORMALLY ***')
                exit(-1)
        break
    return status, buf, uns

#Get Binary Status    00 C0    Retrieve file information (e.g. file size)
def getBinaryStatus(filename):
    log.log ('getBinaryStatus')
    conn.send([0x00, 0xC0, 0x00, 0x00], filename)
    status, buf, uns = getAnswer()
    tlv = TLVParser(buf)

    if status==0x9000 and not (tlv.tagCount(0x80) and tlv.tagCount(0x88) and tlv.tagCount(0x89)):
        log.logerr('message had a missing expected tag or tags (80, 81, 82, 83, 87, 88 and 89)', buf)
        return -1, status, buf, uns

    if status==0x9000 and (tlv.tagCount(0x81) and tlv.tagCount(0x82) and tlv.tagCount(0x83) and tlv.tagCount(0x87)):
        log.logerr('message had unexpected tag or tags (81, 82, 83, 87)', buf)
        return -1, status, buf, uns
    return 0, status, buf, uns 


# Main function
def processTestCase():
    req_unsolicited = conn.connect()
    if req_unsolicited:
        #Receive unsolicited
        log.log('Waiting for unsolicited')
        status, buf, uns = getAnswer(False)
        log.log('Unsolicited', TLVParser(buf))
    
    testFile='i:guiapp.cfg'
    getBinaryStatus(testFile)


###########  Script entry point,  calls main test process ##########################
if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection()

    utility.register_testharness_script(processTestCase)
    utility.do_testharness()
