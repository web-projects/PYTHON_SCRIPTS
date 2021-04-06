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
''' --------------------------------------------------------------- '''
# Put file function
def putfile( filename , local_fn ):
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
    fops.getfile( conn, log, filename, local_fn, progress )

''' --------------------------------------------------------------- '''
#Main do testharness
if __name__ == '__main__':
    arg = util.get_argparser();
    arg.add_argument( '--file', dest='filename', metavar='file', required=True,
                            help='Filename to download' )
    arg.add_argument( '--lfile', dest='localfilename', metavar='file', default=None,
                            help='local file name' )
    args = util.parse_args();
    util.register_testharness_script( 
            partial( putfile, args.filename, args.localfilename ) )
    util.do_testharness()
