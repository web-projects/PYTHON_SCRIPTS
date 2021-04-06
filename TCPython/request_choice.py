from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from time import sleep

LIST_STYLE_SCROLL = 0x00
LIST_STYLE_NUMERIC = 0x01
LIST_STYLE_SCROLL_CIRCULAR = 0x02

''' How to create example scripts '''
def request_choice_demo():
        ''' First create connection '''
        req_unsolicited = conn.connect()
        ''' If unsolicited read it'''
        if req_unsolicited:
                status, buf, uns = conn.receive()
                check_status_error( status )
        ''' Reset display '''
        conn.send([0xD2, 0x01, 0x01, 0x00])
        status, buf, uns = conn.receive()
        check_status_error( status )
        ''' Send data '''
        c_tag = tagStorage()
        c_tag.store( (0xDF, 0xA2, 0x12), LIST_STYLE_SCROLL )
        #BUG: Unable to push the direct string not bytearray
        c_tag.store( (0xDF,0xA2,0x11), 'Optional title')
        for i in range(1, 6):
            c_tag.store( (0xDF, 0xA2, 0x02), i )
            c_tag.store( (0xDF, 0xA2, 0x03), 'Item %d' % i )
        conn.send([0xD2, 0x03, 0x00, 0x01] , c_tag.get())
        
        is_unsolicited = True
        while is_unsolicited:  # unsolicited responses come when echo mode is on
            status, buf, is_unsolicited = conn.receive()
            check_status_error( status )
        sleep(3)


def request_choice_on_pinpad_demo():
        ''' First create connection '''
        req_unsolicited = conn.connect()
        ''' If unsolicited read it'''
        if req_unsolicited:
                status, buf, uns = conn.receive()
                check_status_error( status )
        ''' Reset display '''
        conn.setnad(2)
        conn.send([0xD2, 0x01, 0x01, 0x00])
        status, buf, uns = conn.receive()
        check_status_error( status )
        ''' Send data '''
        c_tag = tagStorage()
        c_tag.store( (0xDF, 0xA2, 0x12), LIST_STYLE_SCROLL )
        #BUG: Unable to push the direct string not bytearray
        c_tag.store( (0xDF,0xA2,0x11), 'Optional title')
        for i in range(1, 6):
            c_tag.store( (0xDF, 0xA2, 0x02), i )
            c_tag.store( (0xDF, 0xA2, 0x03), 'Item %d' % i )
        conn.send([0xD2, 0x03, 0x00, 0x01] , c_tag.get())
        
        is_unsolicited = True
        while is_unsolicited:  # unsolicited responses come when echo mode is on
            status, buf, is_unsolicited = conn.receive()
            check_status_error( status )
        sleep(3)

if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script( request_choice_on_pinpad_demo )
    utility.do_testharness()
