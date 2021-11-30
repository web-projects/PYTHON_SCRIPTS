
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

NO_TRUNCATE_FILE = 0x04
TRUNCATE_FILE = 0x05


#Find First File    00 C3    Find file using search string, first (search order not defined) matched file-name returned and file selected
def findFirstFile(filemask, IgnoreNoFile=False):
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


#Select File    00 A4    Select file for operations (optional truncate), create new if file does not exist.
#def selectFile(filename, P1=NO_TRUNCATE_FILE):
#    #filename format is 'FILENAME.OLD'
#    log.log ('selectFile')
#    conn.send([0x00, 0xA4, P1, 0x00], filename)
#    status, buf, uns = getAnswer()
#    return 0, status, buf, uns


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
                #performCleanup()
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


def getBinaryData(len):
    log.log ('getBinaryData')
    conn.send([0x00, 0xB0, 0x00, 0x00, len])
    status, buf, uns = getAnswer()
    tlv = TLVParser(buf)

    return buf, tlv


# Main function
def processTestCase():
    req_unsolicited = conn.connect()
    if req_unsolicited:
        #Receive unsolicited
        log.log('Waiting for unsolicited')
        status, buf, uns = getAnswer(False)
        log.log('Unsolicited', TLVParser(buf))
    
    # By default, files are set in RAM. To select a file in FLASH prefix filename with
    # “F:” (“F:guiapp.cfg” sets the current file to guiapp.cfg file in FLASH,
    # while “I:/2/test.dat” sets the current file to test.dat file in RAM, GID2)
    #testFile='i:guiapp.cfg'
    #testFile='i:guiapp.cfg'
    
    testFile='vipa_ver.txt'
    #testFile='emv_ver.txt'
    #testFile='idle_ver.txt'
    
    # find the file first
    code, status, buf, uns = findFirstFile(testFile)

    if status == 0x9000:
      # select for operations - will create a new file if it doesn't exist
      #code, status, buf, uns = selectFile(testFile)
      
      #if status == 0x9000:
      # STATUS=9f13 indicates file not accessible
      code, status, buf, uns = getBinaryStatus(testFile)
      
      # get file contents
      if status == 0x9000:
        tlv = TLVParser(buf)
        len = tlv.getTag(0x80)[0]
        if len[1] == 0:
          log.logerr('FILE REPORTED 0 LENGTH')
        else:
          log.log('len=', len[1])
          buf, tlv = getBinaryData(len[1])
          log.log('buf=', buf)


###########  Script entry point,  calls main test process ##########################
if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection()

    utility.register_testharness_script(processTestCase)
    utility.do_testharness()
