from testharness import *
from testharness.tlvparser import TLVParser
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
import testharness.utility as util
from binascii import hexlify, unhexlify
from functools import partial


def getPCIRebootTime():
    # GET PCI REBOOT
    conn.send( [0xD0, 0x24, 0x00, 0x00] )
    status, buf, uns = conn.receive()
    check_status_error( status )
   
    tlv = TLVParser(buf)
    if tlv.tagCount((0xDF, 0xA2, 0x42)):
      timestamp = tlv.getTag((0xDF, 0xA2, 0x42), TLVParser.CONVERT_HEX_STR)[0].upper()
      if len(timestamp):
        log.logerr('REBOOT TIME: ' + unhexlify(timestamp).decode())
      else:
        log.log('REBOOT NOT YET CONFIGURED')
    else:
      log.log('FAILED TO RETRIEVE REBOOT TIMESTAMP')


def setTerminalTime(timestamp):

    if len(timestamp) == 14:
      # SET TIME - ASCII format (YYYYMMDDHHMMSS)
      conn.send( [0xDD, 0x10, 0x00, 0x00], timestamp )
      status, buf, uns = conn.receive()
      check_status_error( status )
     

def getTerminalTime():
    # GET TIME - ASCII format (YYYYMMDDHHMMSS)
    conn.send( [0xDD, 0x10, 0x01, 0x00] )
    status, buf, uns = conn.receive()
    check_status_error( status )
   
    #log.log('BUF:', buf[0])
    timestamp = buf[0].decode()
    #log.log('TIMESTAMP:' + timestamp)
    log.logerr('TERMINAL TIME: ' + timestamp[8:])

def rebootDevice():
    # reset device: full reboot
    conn.send([0xD0, 0x00, 0x01, 0x00])
    status, buf, uns = conn.receive()
    check_status_error( status )  

    tlv = TLVParser(buf)
    tid = tlv.getTag((0x9F, 0x1E))

    if len(tid): 
      tid = str(tid[0], 'iso8859-1')
      log.log('Terminal TID: ', tid)
    else: 
      tid = ''
      log.logerr('Invalid TID (or cannot determine TID)!')
        
def SetPCIReboot(args):
    # -----------------------------------------------------------------
    # GET/SET PCI REBOOT
    # -----------------------------------------------------------------
    #
    ''' First create connection '''
    req_unsolicited = conn.connect()
    ''' If unsolicited read it'''
    if req_unsolicited:
      status, buf, uns = conn.receive()
      check_status_error( status )
 
    # set timestamp
    setTerminalTime(args.timestamp)
 
    # display reboot time
    getPCIRebootTime()
 
    # reboot command is hanging device on VIPA 6.8.2.11
    #deviceReboot = False
 
    # SET PCI REBOOT
    if len(args.time) == 6:
      log.log('SET TIME TO: ' + args.time)
      
      time2Reboot = bytearray()
      time2Reboot.extend(map(ord, args.time))
      time2Reboot_tag = [
          [ (0xDF, 0xA2, 0x42), time2Reboot ]
      ]
      
      # SET PCI REBOOT
      conn.send( [0xD0, 0x24, 0x00, 0x00], time2Reboot )
      status, buf, uns = conn.receive()
      check_status_error( status )
      #if status == 0x9000:
      #  deviceReboot = True
        
      # display reboot time
      getPCIRebootTime()

    # display Terminal time
    getTerminalTime()

    ''' Reset display '''
    conn.send( [0xD2, 0x01, 0x01, 0x00] )
    status, buf, uns = conn.receive()
    check_status_error( status )
   
    #if deviceReboot == True:
    #  rebootDevice()
      
   
# -----------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------
if __name__ == '__main__':
    # setup logger
    log = getSyslog()
  
    arg = util.get_argparser()
  
    # ASCII HHMMSS
    arg.add_argument('--time', dest='time', default='',
                     help='24-hour time notation')
    arg.add_argument('--timestamp', dest='timestamp', default='',
                     help='24-hour time notation')
     
    args = util.parse_args()
    
    # validate reboot time
    if len(args.time) != 6 and len(args.time) > 0:
      log.logerr('INVALID TIME VALUE: ' + args.time)
      log.log('DEFAULT TO: 140000')
      args.time = '140000'
      
    # validate timestamp
    if len(args.timestamp) != 14 and len(args.timestamp) > 0:
      log.logerr('INVALID TIME VALUE: ' + args.timestamp)
      log.log('DEFAULT TO: 20201215140000')
      args.timestamp = '20201215140000'
     
    conn = connection.Connection();
    utility.register_testharness_script( partial(SetPCIReboot, args) )
    utility.do_testharness()
