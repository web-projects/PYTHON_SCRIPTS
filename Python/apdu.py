from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from time import sleep
from binascii import unhexlify

# CLA|INS|P1|P2=00a404000aa0000000041010d2501000
# Select File [00, a4]
# P1 = 04, P2 = 00
# data = 0a a0000000041010d25010 00
#        a0000000041010 d25010
# 11 |00 |10|00| A404000AA0000000041010D25010009D
#

commands = [
     # AMEX
     #(b'00A4040008A00000002501040200', "Select file AID", 0),
     # MASTERCARD
     #(b'00A404000AA0000000041010D2501000', "Select file AID", 0),
     (b'00A4040007A000000004101000', "Select file AID", 0),
]

''' How to create example scripts '''
def demo_function():
    ''' First create connection '''
    req_unsolicited = conn.connect()
    ''' If unsolicited read it'''
    if req_unsolicited:
         status, buf, uns = conn.receive()
         check_status_error( status )

    conn.setnad(0x11);
    for buf, msg, sleeptime in commands:
        log.log(msg)
        conn.send(unhexlify(buf))

        is_unsolicited = True
        while is_unsolicited:  # unsolicited responses come when echo mode is on
            status, buf, is_unsolicited = conn.receive()
            check_status_error( status )
        
        sleep(sleeptime)

if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script( demo_function )
    utility.do_testharness()
