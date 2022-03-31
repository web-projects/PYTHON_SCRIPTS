from testharness import *
from testharness.tlvparser import TLVParser, tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from time import sleep
from binascii import hexlify, unhexlify

LIST_STYLE_SCROLL = 0x00
LIST_STYLE_NUMERIC = 0x01
LIST_STYLE_SCROLL_CIRCULAR = 0x02


# Gets answer from the device, optionally ignoring unsolicited and stopping on errors
def getAnswer(ignoreUnsolicited = True, stopOnErrors = True):
    while True:
        status, buf, uns = conn.receive()
        if uns and ignoreUnsolicited:
            log.log('Unsolicited packet detected: ', TLVParser(buf))
            continue
        if (status != 0x9000 and status != 0x9F0D and status != 0x9F36 and 
            status != 0x9F22 and status != 0x9F25 and status != 0x9F28 and 
            status != 0x9F31 and status != 0x9F33 and status != 0x9F34 and 
            status != 0x9F35 and status != 0x9F41 and status != 0x9F42 and 
            status != 0x9F43
        ):
            log.logerr('Pinpad reported error ', hex(status))
            #if stopOnErrors:
            #    performCleanup()
            #    exit(-1)
        break
    return status, buf, uns


def closeContactlessReader():
    # get current contactless status
    # P1
    # Bit 3 - Retrieve device initialization status (tag DFC023)
    conn.send([0xC0, 0x00, 0x08, 0x00])
    status, buf, uns = getAnswer(False)
    
    tlv = TLVParser(buf)
    if tlv.tagCount((0xDF, 0xC0, 0x23)) == 1:
      log.log('Closing Contactless reader')
      conn.send([0xC0, 0x02, 0x00, 0x00])
      status, buf, uns = getAnswer(False) # Get unsolicited


def startKeyboardReader():
    log.log("Start keyboard notifications ---------------------------------------")
    # collect response from user
    # Bit 0 - Enter, Cancel, Clear keys
    # Bit 1 - function keys
    # Bit 2 - numeric keys
    conn.send([0xD0, 0x61, 0x07, 0x00])
    status, buf, uns = conn.receive()

def stopKeyboardReader():
    log.log("Stop keyboard notifications ---------------------------------------")
    conn.send([0xD0, 0x61, 0x00, 0x00])
    status, buf, uns = conn.receive()


''' How to create example scripts '''
def request_choice_demo():
  ''' First create connection '''
  req_unsolicited = conn.connect()
  ''' If unsolicited read it'''
  if req_unsolicited:
          status, buf, uns = conn.receive()
          check_status_error( status )
          
  ''' Reset display '''
  conn.send([0xD2, 0x01, 0x01, 0x00])
  status, buf, uns = conn.receive()
  check_status_error( status )
  
  # keyboard reader
  #startKeyboardReader()
   
  ''' Set data for request '''
  c_tag = tagStorage()
  c_tag.store( (0xDF, 0xA2, 0x12), LIST_STYLE_SCROLL )
  #BUG: Unable to push the direct string not bytearray
  c_tag.store((0xDF,0xA2,0x11), 'PROCESS AS')
  c_tag.store((0xDF, 0xA2, 0x02), 0x01)
  c_tag.store((0xDF, 0xA2, 0x03), b'1. Debit')
  c_tag.store((0xDF, 0xA2, 0x02), 0x02)
  c_tag.store((0xDF, 0xA2, 0x03), b'2. Credit')
  # clear key inhibited
  #c_tag.store((0xDF, 0xA2, 0x15), 0x00)

  ''' Send request '''
  conn.send([0xD2, 0x03, 0x00, 0x01] , c_tag.get())
  
  is_unsolicited = True
  while is_unsolicited:  # unsolicited responses come when echo mode is on
      status, buf, is_unsolicited = conn.receive()
      check_status_error( status )

  tlv = TLVParser(buf)
  if tlv.tagCount((0xDF, 0xA2, 0x02)) == 1:
    selection = tlv.getTag((0xDF, 0xA2, 0x02))[0]
    log.log("USER SELECTED:", selection[0])

  print('')
    
  # keyboard reader
  #stopKeyboardReader()

  # close cless reader
  closeContactlessReader()

  #Reset display - regardless of tx type
  conn.send([0xD2, 0x01, 0x01, 0x00])
  log.log('*** RESET DISPLAY ***')
  status, buf, uns = conn.receive()


if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    ##utility.register_testharness_script( request_choice_on_pinpad_demo )
    utility.register_testharness_script( request_choice_demo )
    utility.do_testharness()
