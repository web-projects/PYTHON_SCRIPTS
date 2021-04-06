#!/bin/env python3
# -*- coding: utf-8 -*-
'''Test Power Management'''

from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from time import sleep
import datetime


states={'active':   0x00,
        'standby':  0x01,
        'sleep':    0x02,
        'deep':     0x03,
        'hibernate':0x04,
        'shutdown': 0x05,
        'reboot':   0x06
        }


def resetDispaly():
    ''' Reset display '''
    conn.send([0xD2, 0x01, 0x01, 0x00])
    status, buf, uns = conn.receive()
    check_status_error( status )

def displayText(pmState):
    testString="Power test:" + pmState + "\n" + str(datetime.datetime.now())
    conn.send([0xD2, 0x01, 0x00, 0x01], testString)
    status, buf, uns = conn.receive()
    check_status_error( status )

def reconnect():
    '''if not connected reconnect'''
    
    req_unsolicited = conn.connect()

    ''' If unsolicited read it'''
    if req_unsolicited:
        status, buf, uns = conn.receive()
        check_status_error( status )


def setPowerState(state):
    conn.send([0xD0, 0x63, state, 0x00])

def powerTest():
    '''Test power functions'''

    argParse = utility.get_argparser()
    args = argParse.parse_args()
    print ("pm state", args.pmState)

    reconnect()
    
    resetDispaly()

    displayText(args.pmState)
    sleep(3)

    setPowerState(states[args.pmState])
#    ''' Check for display status '''
#    status, buf, uns = conn.receive()
#    check_status_error( status )
#
#    ''' Check for HTML display result '''
#    status, buf, uns = conn.receive()
#    check_status_error( status )

if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    argParse = utility.get_argparser()
    argParse.add_argument('pmState', choices=states.keys(), help="Power Mode to set") #, required=True)
    utility.register_testharness_script( powerTest )
    utility.do_testharness()
