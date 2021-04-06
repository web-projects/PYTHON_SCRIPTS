from testharness import *
from sys import exit
from time import sleep
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from testharness.tlvparser import TLVParser, tagStorage
from binascii import hexlify, unhexlify
import os

def OnlinePIN():
    ''' First create connection '''
    req_unsolicited = conn.connect()
    ''' If unsolicited read it'''
    #status, buf, uns = conn.receive()
    #check_status_error( status )
    ''' Send data '''
    pan = b'\x54\x13\x33\x00\x89\x00\x00\x39'
    c_tag = tagStorage()
    #BUG: Unable to push the direct string not bytearray
    c_tag.store( (0xDF, 0xEC, 0x05), 0x00 )
    c_tag.store( (0xDF, 0xED, 0x05), 0x08 )
    c_tag.store( (0xDF, 0x17), '\x00\x00\x00\x00\x01\x51' )
    c_tag.store( (0xDF, 0x24), '\x08\x26' )
    c_tag.store( (0xDF, 0x1C,), 0x02 )
    c_tag.store( (0x5A), pan )
    conn.send([0xDE, 0xD6, 0x03, 0x00] , c_tag.getTemplate(0xE0))
    
    sleep(3)

    conn.send([0xD0, 0x00, 0x00, 0x32])
    status, buf, uns = conn.receive()
    check_status_error( status )

    # Wait for last package
    status, buf, uns = conn.receive()
    slog = getSyslog()
    if status == 0x9F41:
        slog.loginfo('Status is "Cancelled amount" as expected:', hex(status))
    else:
        slog.logerr('Status is not "Cancelled amount"', hex(status), buf)
        sys.exit(-1)


if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script( OnlinePIN )
    utility.do_testharness()
