from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
import sys
import linecache
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
NAD_PINPAD=2
NAD_TERMINAL=1

def waitForKeyPress():
  # collect response from user
  # Bit 0 - Enter, Cancel, Clear keys
  # Bit 1 - function keys
  # Bit 2 - numeric keys
  conn.send([0xD0, 0x61, 0x07, 0x00])
  status, buf, uns = conn.receive()

  # wait for a key press
  exitKey = False
  keyPressed = 0x00
  while exitKey == False:
    status, buf, uns = conn.receive()
    check_status_error( status )
    tlv = TLVParser(buf)
    if tlv.tagCount((0xDF, 0xA2, 0x05)):
      user_input = tlv.getTag((0xDF, 0xA2, 0x05))[0]
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
  
  
''' How to create example scripts '''
def verify_amount():

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
   
   amount = b'\tTotal....$99999.99'
   #amount = b'\tTotal....$9.99'
   
   text_tag = [
        [(0xDF, 0x81, 0x04), b'\tVERIFY AMOUNT'],
        [(0xDF, 0x81, 0x04), amount],
        [(0xDF, 0x81, 0x04), b' '],
        [(0xDF, 0x81, 0x04), b'\t1. YES'],
        [(0xDF, 0x81, 0x04), b'\t2. NO ']
   ]
   text_templ = (0xE0, text_tag)
   
   ''' Send data '''
   #conn.send([0xD2, 0x01, 0x00, 0x01], '\x08VERIFY AMOUNT\x0AAmount....$99999.99' )
   conn.send([0xD2, 0x02, 0x00, 0x01], text_templ)
   
   status, buf, uns = conn.receive()
   check_status_error( status )

   # collect response from user
   waitForKeyPress()
   
   #Reset display - regardless of tx type
   conn.send([0xD2, 0x01, 0x01, 0x00])
   log.log('*** RESET DISPLAY ***')
   status, buf, uns = conn.receive()

    
def demo_test_pp1000():
   ''' First create connection '''
   req_unsolicited = conn.connect()
   ''' If unsolicited read it'''
   if req_unsolicited:
         status, buf, uns = conn.receive()
         check_status_error( status )
   ''' Reset display '''
   prev_nad = conn.setnad(NAD_PINPAD)
   #conn.send([0xD2, 0x01, 0x01, 0x00])
   #status, buf, uns = conn.receive()
   #check_status_error( status )
   ''' Send data '''
   conn.send([0xD2, 0x01, 0x00, 0x01], '\cVERIFY AMOUNT\x0AAmount....$99999.99' )
   #sys.settrace(traceit)
   status, buf, uns = conn.receive()
   check_status_error( status )
   conn.setnad(prev_nad)

def demo_test_font_pp1000():
   ''' First create connection '''
   req_unsolicited = conn.connect()
   ''' If unsolicited read it'''
   if req_unsolicited:
         status, buf, uns = conn.receive()
         check_status_error( status )
#   ''' Reset display '''
   prev_nad = conn.setnad(NAD_PINPAD)
#   conn.send([0xD2, 0x01, 0x01, 0x00])
#   status, buf, uns = conn.receive()
#   check_status_error( status )
   ''' Send data '''
   tags = [
    [(0xDF, 0xA2, 0x10), b'M2.FON' ],
    [(0xDF, 0x81, 0x04), b'Tralalalala']
    ]
   start_templ = ( 0xE0, tags )
   conn.send([0xD2, 0x02, 0x00, 0x01], start_templ )
#   sys.settrace(traceit)
   status, buf, uns = conn.receive()
   check_status_error( status )
   conn.setnad(prev_nad)


def traceit(frame, event, arg):
    if event == "line":
        lineno = frame.f_lineno
        filename = frame.f_globals["__file__"]
        if (filename.endswith(".pyc") or
            filename.endswith(".pyo")):
            filename = filename[:-1]
        name = frame.f_globals["__name__"]
        line = linecache.getline(filename, lineno)
        print(name,":", lineno,": ", line.rstrip())
    return traceit

if __name__ == '__main__':
    log = getSyslog()
    
    conn = connection.Connection();
    utility.register_testharness_script( verify_amount )
    utility.do_testharness()
