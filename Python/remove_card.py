# -*- !/bin/env python3 -*-
# -*- coding: utf-8 -*-

from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from time import sleep


EMV_CARD_REMOVED = 0
EMV_CARD_INSERTED = 1
MAGSTRIPE_TRACKS_AVAILABLE = 2
ERROR_UNKNOWN_CARD = 3

# DISPLAY MESSAGES
REMOVECARD = 0x0E


def getAnswer(ignoreUnsolicited = True, stopOnErrors = True):
    while True:
        status, buf, uns = conn.receive()
        if uns and ignoreUnsolicited:
            log.log('Unsolicited packet detected: ', TLVParser(buf))
            continue
        if status != 0x9000 and status != 0x9F36:
            log.logerr('Pinpad reported error ', hex(status))
            if stopOnErrors:
                performCleanup()
                exit(-1)
        break
    return status, buf, uns


def EMVCardState(tlv):
    res = -1
    # Check for card status
    if tlv.tagCount(0x48):
        ins_tag_val = tlv.getTag(0x48, TLVParser.CONVERT_INT)[0]
        ins_tag_val &= 0xFF00
        ins_tag_val >>= 8
        ##log.log('EMV STATUS:', ins_tag_val)
        if ins_tag_val == 3:
            log.log('EMV Card inserted!')
            res = EMV_CARD_INSERTED
        else:
            if ins_tag_val == 0:
                res = EMV_CARD_REMOVED
            else:
                res = ERROR_UNKNOWN_CARD
    return res
    
    
def removeEMVCard():
    # Display Remove card
    conn.send([0xD2, 0x01, 0x0E, 0x01])
    status, buf, uns = getAnswer(False)
    if status != 0x9000:
        log.logerr('Remove card', hex(status), buf)
        exit(-1)
    log.log('*** REMOVE CARD WAIT ***')
    while True:
        status, buf, uns = getAnswer(False)
        if uns:
            tlv = TLVParser(buf)
            cardState = EMVCardState(tlv)
            if cardState == EMV_CARD_REMOVED:
                break
        log.logerr('Bad packet ', tlv)
    return tlv


def DisplayMessage(message, beep = False):
    # DISPLAY [D2, 01]
    conn.send([0xD2, 0x01, message, 0x01, 0x01])
    status, buf, uns = getAnswer()
    sleep(2)

        
''' How to create example scripts '''
def demo_function():
    ''' First create connection '''
    req_unsolicited = conn.connect()
    ''' If unsolicited read it'''
    if req_unsolicited:
        status, buf, uns = conn.receive()
        check_status_error( status )
    
    # check for card presence and ask to remove it
    conn.send([0xD0, 0x60, 0x01, 0x00])
    status, buf, uns = getAnswer(False) # Get unsolicited
    tlv = TLVParser(buf)
    if EMVCardState(tlv) == EMV_CARD_INSERTED:
        log.log("Card inserted, asking to remove it")
        DisplayMessage(REMOVECARD, True)
        removeEMVCard()

    ''' Reset display '''
    conn.send( [0xD2, 0x01, 0x01, 0x00] )
    status, buf, uns = conn.receive()
    check_status_error( status )

if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script( demo_function )
    utility.do_testharness()
