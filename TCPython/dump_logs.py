from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from functools import partial
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error

P2_VIPA_LOG = 0x01
P2_OS_LOG = 0x02

''' How to create example scripts '''
def dump_logs():
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

   ''' Dump logs '''
   conn.send( [0xD0, 0x05, 0x00, P2_VIPA_LOG])
   ''' Receive and check '''
   status, buf, uns = conn.receive(30)
   check_status_error( status )
   tlv = TLVParser(buf)
   template = tlv.getTag((0x6F))
   filename = TLVParser(template).getTag((0x84))[0].decode('utf-8')
   localfile = filename.split('/')[-1];
   log.log('Log file on terminal: %s, downloading as %s' % (filename, localfile))

   ''' Retrieve log file '''
   progress = partial(utility.display_console_progress_bar, utility.get_terminal_width())
   fileops.getfile(conn, log, filename, localfile, progress)

if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script( dump_logs )
    utility.do_testharness()
