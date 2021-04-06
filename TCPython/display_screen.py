from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from time import sleep

commands = [
    ([0xD2, 0x01, 0x01, 0x01], "Reset display", 0),
    ([0xD2, 0x01, 13, 0x01], "Display Insert Card", 3),
    ([0xD2, 0x01, 14, 0x01], "Display Remove Card", 3),
    ([0xD2, 0x01, 20, 0x01], "Display Re-Insert Card", 3),
    ([0xD2, 0x01, 0x01, 0x01], "Reset display", 0),
]

''' How to create example scripts '''
def demo_function():
    ''' First create connection '''
    req_unsolicited = conn.connect()
    ''' If unsolicited read it'''
    if req_unsolicited:
         status, buf, uns = conn.receive()
         check_status_error( status )

    for buf, msg, sleeptime in commands:
        log.log(msg)
        conn.send(buf)

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
