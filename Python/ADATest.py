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
   
   ''' Display Message '''
   c_tag = tagStorage()
   c_tag.store( (0xDF, 0x81, 0x04), b'Use Audio?' )
   conn.send([0xD2, 0x02, 0x00, 0x01], c_tag.getTemplate( 0xE0 ) )
   status, buf, uns = conn.receive(3)
   check_status_error( status )
   
   ''' START REPORTING KEY PRESSES '''
   # Bit 0 - report enter, cancel and clear key presses
   # Bit 1 - report function key presses
   # Bit 2 - report numeric key presses
   ######### Requires allow_numeric = 1 in section [keyboard_status] in mapp_prot.cfg.
   ######### Otherwise returns SW1SW2 9F10 (Invalid P1) or 6A88 (Invalid P2) if set from Card Status [D0, 60]
   conn.send( [0xD0, 0x61, 0x07, 0x00] )
   ''' Receive and check '''
   status, buf, uns = conn.receive(3)
   check_status_error( status )

   ''' WAIT FOR KEY PRESSES '''
   key_pressed = 0x00
   while (key_pressed != b'\x1b'):
    status, buf, uns = conn.receive()
    check_status_error( status )
    tlv = TLVParser(buf)
    user_input = tlv.getTag((0xDF, 0xA2, 0x05))
    key_pressed = user_input[0]
    log.log('User enter [', key_pressed, ']') 
   
   ''' STOP REPORTING KEY PRESSES '''
   conn.send( [0xD0, 0x61, 0x00, 0x00] )
   status, buf, uns = conn.receive()
   check_status_error( status )
  
   ''' SET DISPLAY TO IDLE '''
   conn.send([0xD2, 0x01, 0x01, 0x00])
   log.log('*** RESET DISPLAY ***')
   status, buf, uns = conn.receive()
   check_status_error( status )

if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script( demo_function )
    utility.do_testharness()