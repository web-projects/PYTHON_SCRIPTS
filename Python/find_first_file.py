from testharness import *
from testharness.tlvparser import TLVParser, tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import getch, kbhit
from binascii import hexlify
from time import sleep

# Finalise the script, clear the screen
def performCleanup():
    # Clear screen
    conn.send([0xD2, 0x01, 0x01, 0x01])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer(True, False)
    # Disconnect

# Gets answer from the device, optionally ignoring unsolicited and stopping on errors
#  Note: A few commands return codes other than 0x9000 which are not really errors, such as file not found
#        setting noError = True suppresses any confusing logerr entries 
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

#Find First File    00 C3    Find file using search string, first (search order not defined) matched file-name returned and file selected
def findFirstFile(filemask, IgnoreNoFile=False):

    req_unsolicited = conn.connect()
    if req_unsolicited:
        #Receive unsolicited
        log.log('Waiting for unsolicited')
        status, buf, uns = getAnswer(False)
        log.log('Unsolicited', TLVParser(buf))
    
    #filename format is '*.INI'
    log.log ('findFirstFile')
    conn.send([0x00, 0xC3, 0x00, 0x00], filemask)
    if IgnoreNoFile==True:
        status, buf, uns = getAnswer(True, False, True)
    else:
        status, buf, uns = getAnswer() #Stop & ErrLog
    if status==0x9000:
        tlv = TLVParser(buf)
        if not (tlv.tagCount(0x84)):
            log.logerr('message had a missing expected tag (84)', buf)
            return -1, status, buf, uns
    elif status==0x9F13:
        log.log('No file match found to supplied mask, not necessarily an error')
    else:
        log.logerr('Pinpad reported error ', hex(status))
        performCleanup()
        log.logerr('*** TEST BEING HALTED ABNORMALLY ***')
        exit(-1)
    return 0, status, buf, uns 


###########  Script entry point,  calls main test process ##########################
if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection()

    utility.register_testharness_script(findFirstFile('vipa_ver.txt'))
    utility.do_testharness()
