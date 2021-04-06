from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error


''' How to create example scripts '''
def demo_function():
   ''' First create connection '''
   req_unsolicited = conn.connect()
   ''' If unsolicited read it'''
   if req_unsolicited:
         status, buf, uns = conn.receive()
         check_status_error( status )
   ''' Reset display '''
   conn.send([0xD2, 0x01, 0x01, 0x00])
   status, buf, uns = conn.receive(3)
   check_status_error( status )
   ''' Store the tags for numeric entry '''
   c_tag = tagStorage()
   c_tag.store( (0xDF, 0xA2, 0x06), [0x00, 0x0D, 0x00, 0x57, 0x00, 0x00] )
   c_tag.store( (0xDF, 0xA2, 0x07), [0x30, 0x00] )
   c_tag.store( (0xDF, 0xA2, 0x08), b'123' )
   ''' Send the message '''
   conn.send( [0xD2, 0x04, 0x00, 0x01], c_tag.getTemplate( 0xE0 ) )
   ''' Receive and check '''
   status, buf, uns = conn.receive(30)
   check_status_error( status )
   '''print the buffer example '''
   '''print(buf) '''
   tlv = TLVParser(buf)
   user_input = tlv.getTag((0xDF, 0xA2, 0x08))
   log.log('User enter [', str(user_input[0], 'iso8859-1'), ']') 
   
  
if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script( demo_function )
    utility.do_testharness()