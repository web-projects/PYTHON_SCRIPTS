from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from time import sleep

#
# putfile.py --file upload/html/verify_amount.html --rfile www/mapp/verify_amount.html --serial COM11
#

EMV_CARD_REMOVED = 0
EMV_CARD_INSERTED = 1
MAGSTRIPE_TRACKS_AVAILABLE = 2
ERROR_UNKNOWN_CARD = 3

# DISPLAY MESSAGES
REMOVECARD = 0x0E

USER_REMOVED_CARD = False


def AbortCurrentProcessing():
  log.log('Abort current processing')
  conn.send([0xD0, 0xFF, 0x00, 0x00])
  status, buf, uns = getAnswer()
  if status == 0x9000:
    log.logerr('All processing aborted')


def setupKeyboardReader():
  log.log("Setup keyboard reader")
  # P1: collect response from user
  # Bit 0 - Enter, Cancel, Clear keys
  # Bit 1 - function keys
  # Bit 2 - numeric keys
  conn.send([0xD0, 0x61, 0x07, 0x00])
  status, buf, uns = conn.receive()


def stopKeyboardReader():
  log.log("Terminate keyboard reader")
  # collect response from user
  # Bit 0 - Enter, Cancel, Clear keys
  # Bit 1 - function keys
  # Bit 2 - numeric keys
  conn.send([0xD0, 0x61, 0x00, 0x00])
  status, buf, uns = conn.receive()


def startCardAndKeyboardMonitoring():
  log.log("Start card/keyboard event monitoring")
  # P2: collect response from user
  # Bit 0 - Enter, Cancel, Clear keys
  # Bit 1 - function keys
  # Bit 2 - numeric keys
  conn.send([0xD0, 0x60, 0x01, 0x07])
  status, buf, uns = conn.receive()


def stopCardAndKeyboarddMonitoring():
  log.log("Stop card/keyboard event monitoring")
  # collect response from user
  # Bit 0 - Enter, Cancel, Clear keys
  # Bit 1 - function keys
  # Bit 2 - numeric keys
  conn.send([0xD0, 0x60, 0x01, 0x00])
  status, buf, uns = conn.receive()
  

def waitForKeyPress():
  global USER_REMOVED_CARD
  # wait for a key press
  exitKey = False
  keyPressed = 0x00
  while exitKey == False:
    status, buf, uns = conn.receive()
    check_status_error(status)
    tlv = TLVParser(buf)
    #log.log(tlv)
    if tlv.tagCount((0xDF, 0xA2, 0x05)):
      user_input = tlv.getTag((0xDF, 0xA2, 0x05))[0]
      #log.logwarning('USER INPUT:', user_input)
      #log.log('KEY PRESSED:', user_input[0])
      # YES: <1>, <X>
      # NO : <2>, <O>      
      if (user_input[0] == 0x20 or user_input[0] == 0x1B) or (user_input[0] == 0x1F or user_input[0] == 0x0D):
        exitKey = True
        keyPressed = user_input[0]
        # user selection   
        switcher = {
              0x20: "NO",
              0x1B: "NO",
              0x1F: "YES",
              0x0D: "YES"
        }
        user_choice = switcher.get(keyPressed, "UNKNOWN CHOICE")
        log.logerr('USER SELECTED:', user_choice)
    elif tlv.tagCount((0xDF, 0xAA, 0x05)):
      user_input = tlv.getTag((0xDF, 0xAA, 0x05))[0]
      #log.logwarning('USER INPUT:', user_input)
      if (user_input[3] == 0x01 or user_input[3] == 0x00):
        exitKey = True
        keyPressed = user_input[3]
        # user selection   
        switcher = {
              0x00: "NO",
              0x1B: "NO",
              0x01: "YES",
              0x0D: "YES"
        }
        user_choice = switcher.get(keyPressed, "UNKNOWN CHOICE")
        log.logerr('USER SELECTED:', user_choice)
    elif tlv.tagCount((0x48)):
      res = EMVCardState(tlv)
      if (res == EMV_CARD_REMOVED):
        log.logerr("CARD REMOVED !!!")
        exitKey = True
        USER_REMOVED_CARD = True


def performCleanup():
    # Clear screen
    conn.send([0xD2, 0x01, 0x01, 0x01])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer(True, False)


def getAnswer(ignoreUnsolicited = True, stopOnErrors = True):
    while True:
        status, buf, uns = conn.receive()
        if uns and ignoreUnsolicited:
            log.log('Unsolicited packet detected: ', TLVParser(buf))
            continue
        if status != 0x9000 and status != 0x9F36:
            log.logerr('Pinpad reported error ', hex(status))
            if stopOnErrors:
                performCleanup()
                exit(-1)
        break
    return status, buf, uns


def EMVCardState(tlv):
    res = -1
    # Check for card status
    if tlv.tagCount(0x48):
        ins_tag_val = tlv.getTag(0x48, TLVParser.CONVERT_INT)[0]
        ins_tag_val &= 0xFF00
        ins_tag_val >>= 8
        ##log.log('EMV STATUS:', ins_tag_val)
        if ins_tag_val == 3:
            log.log('EMV Card inserted!')
            res = EMV_CARD_INSERTED
        else:
            if ins_tag_val == 0:
                res = EMV_CARD_REMOVED
            else:
                res = ERROR_UNKNOWN_CARD
    return res
    
    
def removeEMVCard():
    # Display Remove card
    conn.send([0xD2, 0x01, 0x0E, 0x01])
    status, buf, uns = getAnswer(False)
    if status != 0x9000:
        log.logerr('Remove card', hex(status), buf)
        exit(-1)
    log.log('*** REMOVE CARD WAIT ***')
    while True:
        status, buf, uns = getAnswer(False)
        if uns:
            tlv = TLVParser(buf)
            cardState = EMVCardState(tlv)
            if cardState == EMV_CARD_REMOVED:
                break
        log.logerr('Bad packet ', tlv)
    return tlv


def DisplayMessage(message, beep = False):
    # DISPLAY [D2, 01]
    conn.send([0xD2, 0x01, message, 0x01, 0x01])
    status, buf, uns = getAnswer()
    sleep(2)


def htmlEntry():

    global USER_REMOVED_CARD

    req_unsolicited = conn.connect()
    if req_unsolicited:
        status, buf, uns = conn.receive()
        check_status_error(status)

    conn.send([0xD2, 0x01, 0x01, 0x00])  # Reset display
    status, buf, uns = conn.receive()
    check_status_error(status)
    
    # setup card movement handler
    #setupKeyboardReader()
    startCardAndKeyboardMonitoring()

    html_resource = b'mapp/verify_amount.html'
    
    title = b'Verify Amount'
    item1 = b'item 1 ..... $99989.00'
    
    # there's no current way to issue blank lines: use any single char, except a space
    item2 = b'Gratitude .. $___10.00'
    item2 = b'-'
    
    # there's no current way to issue blank lines: use any single char, except a space
    item3 = b'Tax ........ $____0.99'
    item3 = b'-'
    
    #total = b'Total ...... $99999.99'
    total = b'Total ...... $99989.00'
    
    html_tags = [
      [(0xDF, 0xAA, 0x01), html_resource],
      [(0xDF, 0xAA, 0x02), b'title'], [(0xDF, 0xAA, 0x03), title],
      [(0xDF, 0xAA, 0x02), b'item1'], [(0xDF, 0xAA, 0x03), item1],
      [(0xDF, 0xAA, 0x02), b'item2'], [(0xDF, 0xAA, 0x03), item2],
      [(0xDF, 0xAA, 0x02), b'item3'], [(0xDF, 0xAA, 0x03), item3],
      [(0xDF, 0xAA, 0x02), b'total'], [(0xDF, 0xAA, 0x03), total],
    ]
    html_templ = (0xE0, html_tags)
	
    # P1
    # Bit 0 - enable update events (echo mode, see Receiving echo mode data on POS)
    # P2
    # Backlight: 00 – off, 01 – on
    conn.send([0xD2, 0xE0, 0x00, 0x01], html_templ)
  
    ''' read user input on device '''
    status, buf, uns = conn.receive(30)
    check_status_error(status)

    # collect response from user
    waitForKeyPress()
    #sleep(2)

    if USER_REMOVED_CARD == True:
      AbortCurrentProcessing()
    else:
      # stop card/keyboard monitoring
      stopCardAndKeyboarddMonitoring()
      
      # check for card presence and ask to remove it
      conn.send([0xD0, 0x60, 0x01, 0x00])
      status, buf, uns = getAnswer(False) # Get unsolicited
      tlv = TLVParser(buf)
      if EMVCardState(tlv) == EMV_CARD_INSERTED:
          log.log("Card inserted, asking to remove it")
          DisplayMessage(REMOVECARD, True)
          removeEMVCard()

    # Reset display - regardless of tx type
    log.log('*** RESET DISPLAY ***')
    conn.send([0xD2, 0x01, 0x01, 0x00])
    status, buf, uns = conn.receive()
    
    
if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection()
    utility.register_testharness_script(htmlEntry)
    utility.do_testharness()
