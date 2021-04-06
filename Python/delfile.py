#!/usr/bin/python3
""" This is a sample script for deleting file from the terminal
    using the VIPA protocol.
"""

import testharness.fileops as fops
import testharness.utility as util
from functools import partial
from testharness.syslog import getSyslog
from testharness.connection import Connection
from testharness.tlvparser import TLVParser

def delfile(file):
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
    
    conn.send([0x00, 0xAB, 0x00, 0x00], file)
    sw12 = conn.receive()[0]
    if sw12 != 0x9000: exit(sw12)


if __name__ == '__main__':
    util.get_argparser().add_argument('file', help='File to delete')
    args = util.parse_args();
    util.register_testharness_script(partial(delfile, args.file))
    util.do_testharness()
