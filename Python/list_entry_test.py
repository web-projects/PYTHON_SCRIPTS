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
   c_tag.store( (0xDF, 0xA2, 0x11), b'SELECT CARD TYPE' )   # Menu Title
   c_tag.store( (0xDF, 0xA2, 0x02), [0x31] )                # Option ID#1
   c_tag.store( (0xDF, 0xA2, 0x03), b'Debit' )              # Option 1 
   c_tag.store( (0xDF, 0xA2, 0x02), [0x32] )                # Option ID#2
   c_tag.store( (0xDF, 0xA2, 0x03), b'Credit' )             # Option 2
   c_tag.store( (0xDF, 0xA2, 0x12), [0x01] )                # List type: numeric
   #c_tag.store( (0xDF, 0xA2, 0x15), [0x00] )                # Cleary key: Not inhibited
   
   ''' Send the message '''
   conn.send( [0xD2, 0x03, 0x00, 0x01], c_tag.get() )
   ''' Receive and check '''
   status, buf, uns = conn.receive(90)
   check_status_error( status )
   '''print the buffer example '''
   '''print(buf) '''
   tlv = TLVParser(buf)
   user_input = tlv.getTag((0xDF, 0xA2, 0x02))
   #log.log('User entered [', str(user_input[0], 'iso8859-1'), ']') 
   
   #Reset display
   conn.send([0xD2, 0x01, 0x01, 0x01])
   log.log('*** RESET DISPLAY ***')
   status, buf, uns = getAnswer()
        
if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script( demo_function )
    utility.do_testharness()