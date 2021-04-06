from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error

import time

''' How to create example scripts '''
def demo_function():
   ''' First create connection '''
   req_unsolicited = conn.connect()
   ''' If unsolicited read it'''
   if req_unsolicited:
         status, buf, uns = conn.receive()
         check_status_error( status )

   ''' Store the tags for numeric entry '''
   c_tag = tagStorage()

   #index or text, one mandatory

   # index
   #c_tag.store( (0xDF, 0xA2, 0x06), [0x00, 0x0D] )  # enter card pan
   #c_tag.store( (0xDF, 0xA2, 0x06), [0x00, 0x57] )  # press enter

   # text
   c_tag.store( (0xDF, 0xA2, 0x13), [0x41, 0x42, 0x43, 0x44] )
   #c_tag.store( (0xDF, 0xA2, 0x13), [0x41, 0x42, 0x43, 0x44, 0x46, 0x47, 0x48, 0x49] )
   #c_tag.store( (0xDF, 0xA2, 0x13), [0x41, 0x42, 0x43, 0x44, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x41] )

   # max len
   c_tag.store( (0xDF, 0x83, 0x05), [0x0A] )

   ''' Send the message '''
   NAD_PINPAD=2
   conn.setnad(NAD_PINPAD)
   conn.send( [0xD2, 0xF1, 0x00, 0x00], c_tag.getTemplate( 0xE0 ) )

   #''' abort '''
   #time.sleep(7)
   #conn.send([0xD0, 0xFF, 0x00, 0x00])
   #time.sleep(5)
   #status, buf, uns = conn.receive(3)
   #check_status_error( status )
   #return

   ''' Receive and check '''
   status, buf, uns = conn.receive(30)
   check_status_error( status )
   '''print the buffer example '''
   '''print(buf) '''
   tlv = TLVParser(buf)
   user_input = tlv.getTag((0xDF, 0x83, 0x01))
   log.log('User enter [', str(user_input[0], 'iso8859-1'), ']') 
   
  
if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script( demo_function )
    utility.do_testharness()