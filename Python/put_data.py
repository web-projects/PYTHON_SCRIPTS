from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error



#send D2, 03, 00, 01, DFA21104'TEST'DFA2020101DFA20308'Option 1'DFA2020102DFA20304'Opt2'DFA2020103DFA20303'XYZ'DFA2020104DFA20308'Next Opt'DFA2020105DFA20306'Blabla'DFA2020106DFA20308'Option 6'DFA2020107DFA20308'Option 7'DFA2020108DFA20308'Option 8'DFA2020109DFA20308'Option 9'DFA202010ADFA20309'Option 10'


''' How to create example scripts '''
def put_data_sample():
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
        #BUG: Unable to push the direct string not bytearray
        c_tag.store( (0xE0), [0xDF, 0xA2, 0x0F])  
        conn.send([0x00, 0xDA, 0xFF, 0xFF] , c_tag.get())
        status, buf, uns = conn.receive()
        check_status_error( status )


if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script( put_data_sample )
    utility.do_testharness()
