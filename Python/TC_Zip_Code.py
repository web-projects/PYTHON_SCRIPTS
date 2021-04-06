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

   # TAGS TO REQUEST
   c_tag.store( (0xDF, 0xA2, 0x06), [0x00, 0x7E, 0x00, 0x00] )
   c_tag.store( (0xDF, 0xA2, 0x07), [0x05, 0X00] )
   c_tag.store( (0xDF, 0x83, 0x05), [0x05] )
   c_tag.store( (0xDF, 0x83, 0x06), [0x05] )
   c_tag.store( (0xDF, 0xB0, 0x05), [0x00, 0X00, 0x00, 0X08] )
   
   ''' Send the message '''
   conn.send( [0xD2, 0xF1, 0x00, 0x00], c_tag.getTemplate( 0xE0 ) )

   ''' Receive and check '''
   status, buf, uns = conn.receive(30)
   check_status_error( status )
   '''print the buffer example '''
   '''print(buf) '''
   tlv = TLVParser(buf)
   user_input = tlv.getTag((0xDF, 0x83, 0x01))
   log.log('User entered [', str(user_input[0], 'iso8859-1'), ']') 
   
  
if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script( demo_function )
    utility.do_testharness()