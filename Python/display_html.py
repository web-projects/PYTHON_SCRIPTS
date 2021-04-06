# -*- !/bin/env python3 -*-
# -*- coding: utf-8 -*-

from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error


''' How to create example scripts '''
def demo_function():
    ''' First create connection '''
    req_unsolicited = conn.connect()
    ''' If unsolicited read it'''
    if req_unsolicited:
        status, buf, uns = conn.receive()
        check_status_error( status )
        
    ''' Reset Device '''
    # P1
    # 0x00 - perform soft-reset
    # P2
    # Bit 1 – 0
    # PTID in serial response
    # Bit 1 – 1
    # PTID plus serial number (tag 9F1E) in serial response
    # Bit 2
    # 0 — Leave screen display unchanged, 1 — Clear screen display to idle display state
    conn.send( [0xD0, 0x00, 0x00, 0x17] )
    status, buf, uns = conn.receive()
    check_status_error( status )
   
    tlv = TLVParser(buf)
    tid = tlv.getTag((0x9F, 0x1e))
    if len(tid): 
       tid = str(tid[0], 'iso8859-1')
       log.log('Terminal TID:', tid)
    else: 
       tid = ''
       log.logerr('Invalid TID (or cannot determine TID)!')
    
    ''' Send data '''
    argParse = utility.get_argparser()
    args = argParse.parse_args()
    print ("Display:", args.html)
    #resource = bytearray()
    #resource.extend(map(ord, args.html))
    resource = b'mapp/signature.html'
    #conn.send([0xD2, 0xE0, 0x00, 0x01], (0xE0, [
    tags = [
        [(0xDF, 0xAA, 0x01), resource],
        [(0xDF, 0xAA, 0x02), b'title_text'], [(0xDF, 0xAA, 0x03), b'Enter number'],
        [(0xDF, 0xAA, 0x02), b'TEMPLATE_INPUT_TYPE'], [(0xDF, 0xAA, 0x03), b'number'],
        [(0xDF, 0xAA, 0x02), b'input_precision'], [(0xDF, 0xAA, 0x03), b'0'],
        [(0xDF, 0xAA, 0x02), b'entry_mode_visibility'], [(0xDF, 0xAA, 0x03), b'hidden'],
        [(0xDF, 0xAA, 0x02), b'timeout'], [(0xDF, 0xAA, 0x03), b'10'],
    ]
    signature_templ = ( 0xE0, tags )
   
    conn.send( [0xD2, 0xE0, 0x00, 0x01], signature_templ )
    status, buf, uns = conn.receive()
    check_status_error( status )

    ''' Check for HTML display result '''
    status, buf, uns = conn.receive()
    check_status_error( status )

    ''' Reset display '''
    conn.send( [0xD2, 0x01, 0x01, 0x00] )
    status, buf, uns = conn.receive()
    check_status_error( status )

if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    argParse = utility.get_argparser()
    argParse.add_argument('--html', default="mapp/alphanumeric_entry.html", help="html file to display, file must be on the device")
    utility.register_testharness_script( demo_function )
    utility.do_testharness()
