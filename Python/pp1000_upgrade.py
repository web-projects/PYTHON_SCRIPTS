from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
import sys
import linecache
from testharness.syslog import getSyslog
from testharness.utility import check_status_error

def demo_update_font():
   ''' First create connection '''
   req_unsolicited = conn.connect()
   ''' If unsolicited read it'''
   if req_unsolicited:
         status, buf, uns = conn.receive()
         check_status_error( status )
#   ''' Reset display '''
   ''' Send data '''
   tags = [
   [(0x84), b'fonts.pp1000' ]
   ]
   e0_temp = ( 0xE0, tags )
   conn.send([0xD2, 0x0A, 0x81, 0x00],e0_temp)

   status, buf, uns = conn.receive()
   check_status_error( status )
   conn.setnad(prev_nad)

if __name__ == '__main__':
    log = getSyslog()
    
    conn = connection.Connection();
    utility.register_testharness_script( demo_update_font )
    utility.do_testharness()