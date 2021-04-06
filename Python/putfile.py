#!/usr/bin/python3
""" This is a sample script for download file into the terminal
    using the VIPA protocol. Filename is read from file
"""
''' --------------------------------------------------------------- '''

import testharness.fileops as fops
import testharness.utility as util
from functools import partial
from testharness.syslog import getSyslog
from testharness.connection import Connection
import testharness.exceptions as exc
from testharness.tlvparser import TLVParser

''' --------------------------------------------------------------- '''
# Put file function
def putfile( filename , remotefilename, forceput ):
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
    if forceput:
        fops.putfile( conn, log, filename, remotefilename, progress=progress )
    else:
        try:
            fops.updatefile( conn, log, filename, remotefilename, False, progress=progress )
        except exc.invResponseException as e:
            log.logerr( "Unable to use updatefile fallback to putfile" )
            fops.putfile( conn, log, filename, remotefilename, progress=progress )

''' --------------------------------------------------------------- '''
#Main do testharness
if __name__ == '__main__':
    arg = util.get_argparser();
    arg.add_argument( '--file', dest='filename', metavar='file', required=True,
                            help='Filename to upload' )
    arg.add_argument( '--rfile', dest='remotefilename', metavar='file', default=None,
                            help='Destination filename on remote terminal' )
    arg.add_argument( '--forceputfile', dest='forceputfile', action='store_true',
                            help='Force putfile command for upload' )
    args = util.parse_args();
    util.register_testharness_script( 
            partial( putfile, args.filename, args.remotefilename, args.forceputfile) )
    util.do_testharness()
