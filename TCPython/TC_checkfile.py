#!/usr/bin/python3
""" This is a sample script for download file from the terminal
    using the VIPA protocol. Filename is read from file
"""
''' --------------------------------------------------------------- '''

import testharness.fileops as fops
import testharness.utility as util
from functools import partial
from testharness.syslog import getSyslog
from testharness.connection import Connection
from testharness.tlvparser import TLVParser

'''----------------------------------------------------------------- '''
''' Get File function - gets file from device                        '''
def openfile( conn, log, remote_fn, progress=None ):
    from struct import pack
    #conn.send( [0x00,0xC0,0x00,0x00], remote_fn.upper() )
    conn.send( [0x00,0xC0,0x00,0x80], remote_fn.upper() )
    status, buf, uns = conn.receive()
    if status != 0x9000:
        raise exc.invResponseException( 'Cannot select file ' + remote_fn , status )
    if progress!=None:
        log.loginfo( 'INFO: Binary stream data not included in log' )
        enable_logging = False
    else:
        enable_logging = True
    tlv = TLVParser(buf)
    fileSize = tlv.getTag(0x80, tlv.CONVERT_INT)[0]
    if fileSize == 0:
        raise exc.logicalException( 'File with name ' + remote_fn + " doesn't exists")
    fileChecksum = tlv.getTag(0x88)
    return fileChecksum

''' --------------------------------------------------------------- '''
# Check file function
def checkfile( filename ):
    conn = Connection()
    log = getSyslog()
    req_unsolicited = conn.connect()
    if req_unsolicited:
        #Receive unsolicited
        status, buf, uns = conn.receive()
        if status != 0x9000:
            log.logerr('Unsolicited fail')
            exit(-1)
        log.log('Unsolicited', TLVParser(buf) )
    progress = partial( util.display_console_progress_bar, util.get_terminal_width() )
    openfile( conn, log, filename, progress )

''' --------------------------------------------------------------- '''
#Main do testharness
if __name__ == '__main__':
    arg = util.get_argparser();
    arg.add_argument( '--file', dest='filename', metavar='file', required=True,
                            help='Filename to download' )
    args = util.parse_args();
    util.register_testharness_script( 
            partial( checkfile, args.filename ) )
    util.do_testharness()
