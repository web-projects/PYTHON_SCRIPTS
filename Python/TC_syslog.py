from testharness import *
from testharness.tlvparser import TLVParser
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
import testharness.utility as util
from binascii import hexlify, unhexlify, b2a_hex
from functools import partial

# VIPA COMMAND PARAMETER OPTIONS
# LOG_LEVEL
# NUMBER_OF_FILES
# MAX_LOGFILE_SIZE

def decodeLogLevel(byte):
    #log.log('Type :', type(byte))
    #log.log('Value:', byte)
    log.log('BYTE: ' + "0x%0*x" % (2, byte[0]))
          
    switcher = {
        8: "TRACE",
        7: "INFO",
        6: "NOTICE",
        5: "WARNING",
        4: "ERROR",
        3: "CRITICAL",
        2: "ALERT",
        1: "EMERGENCY",
        0: "LOGGING OFF"
    }
    logLevel = switcher.get( byte[0], "UNKNOWN LOG LEVEL")

    return logLevel

def getSystemLogLevel():
    loglevel = args.level
    conn.send( [0xD0, 0x64, 0xFF, 0x00] )
    status, buf, uns = conn.receive()
    check_status_error( status )
   
    tlv = TLVParser(buf)
    if tlv.tagCount((0xDF, 0xAC, 0x02)):
      logLevel = tlv.getTag((0xDF, 0xAC, 0x02))
      if len(logLevel):
        loglevel = logLevel[0][0]
        log.logerr('LOG LEVEL: ' + decodeLogLevel(logLevel[0]))
      else:
        log.log('UNABLE TO OBTAIN LOG LEVEL')
    else:
      log.log('FAILED TO RETRIEVE LOG LEVEL')

    return loglevel

def setSysLogConfiguration():
   # NUMBER_OF_FILES: number of files for logging
   #                  Limit: 00 - 99
   # MAX_LOGFILE_SIZE: maximum size of logging file
   #                   Limit: 001 - 999 (kb)
   command_tags = [
      [(0xDF, 0xAC, 0x02), b'LOG_LEVEL' ],        [(0xDF, 0xAA, 0x03), bytes('0' + args.level, 'utf-8')],
      [(0xDF, 0xAA, 0x02), b'NUMBER_OF_FILES' ],  [(0xDF, 0xAA, 0x03), bytes(args.files, 'utf-8')],
      [(0xDF, 0xAA, 0x02), b'MAX_LOGFILE_SIZE' ], [(0xDF, 0xAA, 0x03), bytes(args.size, 'utf-8')],
   ]
   command_templ = ( 0xE0, command_tags )
   P1 = int(args.level)
   conn.send([0xD0, 0x64, P1, 0x00], command_templ)
   status, buf, uns = conn.receive()
   check_status_error( status )

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
        
def LogConfiguration(args):
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
 

    # display current log settings
    logLevel = getSystemLogLevel()
    log.log('SYSLOG LEVEL REPORTED:', logLevel)
 
    # SET SYSLOG SETTINGS
    if len(args.level) > 0 and len(args.files) > 0 and len(args.size) > 0:
      log.log('SYSLOG SETTINGS ARE: LEVEL=' + args.level + ', FILES=' + args.files + ', SIZE=' + args.size)
      if (int(args.level) == logLevel):
        log.warning('SYSLOG LEVEL already set')
      else:
        log.log('SYSLOG LEVEL UPDATE TO: ' + args.level)
        setSysLogConfiguration()

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
    arg.add_argument('--level', dest='level', default='',
                     help='LOG_LEVEL')
    arg.add_argument('--files', dest='files', default='',
                     help='NUMBER_OF_FILES')
    arg.add_argument('--size', dest='size', default='',
                     help='MAX_LOGFILE_SIZE')
     
    args = util.parse_args()
    
    # validate LOG_LEVEL
    if len(args.level) > 0 and len(args.files) > 0 and len(args.size) > 0:
      if len(args.level) != 1 or int(args.level) > 8:
        log.logerr('INVALID LOG_LEVEL VALUE: ' + args.level)
        log.log('DEFAULT TO: 5')
        args.level = '5'
     
    conn = connection.Connection();
    utility.register_testharness_script( partial(LogConfiguration, args) )
    utility.do_testharness()
