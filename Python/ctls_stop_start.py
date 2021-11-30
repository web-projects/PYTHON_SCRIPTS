#!/usr/bin/python3

'''
Created on 22-11-2012

@author: Tomasz_S1
'''

from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog

# args support
from functools import partial
import testharness.utility as util


def transtest_function(args):
  
  log = getSyslog()
  conn = connection.Connection();
  
  # If PP1000SEV3 is attached to VIPA terminal and there is a will to perform
  # this command on PP1000SEV3 one need to send this command with NAD=2.
  #prev_nad = conn.setnad(2)
  
  #Create ssl server
  #conn.connect_serial('COM1', 57600, timeout=2 );
  req_unsolicited = conn.connect()
  if req_unsolicited:
    #Receive unsolicited
    status, buf, uns = conn.receive()
    if status != 0x9000:
      log.logerr('Unsolicited fail')
      exit(-1)

    log.log('Unsolicited', TLVParser(buf) )

  #Send CLOSE contactless
  conn.send([0xc0, 0x02, 0x00, 0x00])
  status, buf, uns = conn.receive()
  if status != 0x9000:
    log.logerr('ctls close fail')
  #  exit(-1)

  #Send INIT contactless
  if (args.option == 'start'):
    conn.send([0xc0, 0x01, 0x00, 0x00])
    status, buf, uns = conn.receive()
    if status != 0x9000:
      log.logerr('ctls init fail')
    # exit(-1)

  #Reset display - regardless of tx type
  conn.send([0xD2, 0x01, 0x01, 0x00])
  log.log('*** RESET DISPLAY ***')
  status, buf, uns = conn.receive()


if __name__ == '__main__':

  arg = util.get_argparser()
  # --option start
  arg.add_argument('--option', dest='option', default='',
    help='options')
  args = util.parse_args()
    
  utility.register_testharness_script(partial(transtest_function, args))
  utility.do_testharness()
