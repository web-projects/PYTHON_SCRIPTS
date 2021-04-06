#!/usr/bin/python3
'''
Created on 21-06-2012

@authors: Lucjan_B1, Kamil_P1
'''

from testharness import *
from testharness.tlvparser import TLVParser
from functools import partial
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import getch, kbhit
from binascii import hexlify, unhexlify, b2a_hex
from time import sleep
import sys
import getpass
import datetime
import traceback

# ---------------------------------------------------------------------------- #
# GLOBALS
# ---------------------------------------------------------------------------- #

# UX == UNATTENDED
DEVICE_UNATTENDED = ""

CONVERT_INT = 1
CONVERT_STRING = 2

EMV_CARD_REMOVED = 0
EMV_CARD_INSERTED = 1
MAGSTRIPE_TRACKS_AVAILABLE = 2
ERROR_UNKNOWN_CARD = 3

DATE = b'\x20\x10\x01'
TIME = b'\x00\x00\x00'

ACQUIRER_ID = [ (0xC2), [0x36, 0x35] ]

## CURRENCY / COUNTRY CODE
UK = b'\x08\x26'
US = b'\x08\x40'
## --- 0x9F14 - Command Incorrectly Formatted
CURRENCY_CODE = [(0x5F, 0x2A), US]
COUNTRY_CODE  = [(0x9F, 0x1A), US]

AUTHRESPONSECODE = [ (0x8A), [0x30, 0x30] ]  # authorization response code of 00
#AUTHRESPONSECODE = [ (0x8A), [0x59, 0x31] ]  # authorization response code of Y1
#AUTHRESPONSECODE = [ (0x8A), [0x5A, 0x33] ]  # authorization response code of Z3

OFFLINEPINVERIFY = [ (0xC0), [0x00] ]   # Offline (Z3)
ONLINEPINVERIFY  = [ (0xC0), [0x01] ]   # Online (00)

ISOFFLINE = AUTHRESPONSECODE[1] == [0x5A, 0x33]

## TRANSACTION AMOUNT
SMALL_AMOUNT = b'\x00\x00\x00\x00\x12\x02'

# AMEX TESTS
AMEX_CLESS_CMV_REQ = b'\x00\x00\x00\x00\x15\x01'
#
AMEX_TESTCARD_12   = b'\x00\x00\x00\x00\x09\x99'   # AMEX 'TEST CARD 12' CVMReqLimit=10.00
AMEX_AXP_CPT003    = b'\x00\x00\x00\x00\x12\x01'   # AMEX AXP CPT003
AMEX_AXP_CPT005    = b'\x00\x00\x00\x05\x00\x00'   # AMEX AXP CPT005
AMEX_AXP_CPT017    = b'\x00\x00\x00\x00\x12\x02'   # AMEX AXP CPT017
AMEX_AXP_CPT017_2  = b'\x00\x00\x00\x00\x60\x02'   # AMEX AXP CPT017 2
#
# DISCOVER TESTS
DISCOVER_CLESS_REQ = b'\x00\x00\x00\x01\x00\x01'
#
DISCOVER_E2E_CL_02 = b'\x00\x00\x00\x02\x01\x00'   # DISCOVER E2E CL 02
DISCOVER_E2E_CL_17 = b'\x00\x00\x00\x00\x01\x70'   # DISCOVER E2E CL 17
DISCOVER_E2E_CL_36 = b'\x00\x00\x00\x00\x02\x00'   # DISCOVER E2E CL 36
#
# MASTERCARD TESTS
MASTERCARD_CLESS_CVM_REQ = b'\x00\x00\x00\x00\x20\x01'
#
# VISA TESTS
VISA_CLESS_CVM_REQ = b'\x00\x00\x00\x00\x09\x01'
#
VISA_ADVT70_TC01_A = b'\x00\x00\x00\x00\x10\x00'   # VISA ADVT 7.0 Test Case 01 a
VISA_CDET23_TC02   = b'\x00\x00\x00\x02\x00\x02'   # VISA CDET 2.3 TEST CASE 02
VISA_CDET23_TC03   = b'\x00\x00\x00\x00\x09\x01'   # VISA CDET 2.3 TEST CASE 03
VISA_CDET23_TC06   = b'\x00\x00\x00\x00\x06\x06'   # VISA CDET 2.3 TEST CASE 06
VISA_CDET23_TC09   = b'\x00\x00\x00\x00\x09\x00'   # VISA CDET 2.3  TEST CASE 09

### --- CHANGE AMOUNT VALUE HERE ---v
AMOUNT = [(0x9F, 0x02), SMALL_AMOUNT]
AMTOTHER = b'\x00\x00\x00\x00\x00\x00'

# Convert int to BCD
# From: https://stackoverflow.com/questions/57476837/convert-amount-int-to-bcd
def bcd2(value, length=0, pad='\x00'):
    ret = ""
    while value:
        value, ls4b = divmod(value, 10)
        value, ms4b = divmod(value, 10)
        ret = chr((ms4b << 4) + ls4b) + ret
    return pad * (length - len(ret)) + ret

def bcd(value, length=0, pad=0):
    ret = [ ]
    while value:
        value, ls4b = divmod(value, 10)
        value, ms4b = divmod(value, 10)
        ret.insert(0, (ms4b << 4) + ls4b)
    while len(ret) < length:
        ret.insert(0, pad)
    return bytes(ret)

# Converts data field to integer
def getDataField(buf, conversion = CONVERT_STRING):
    from struct import unpack
    ind = -1
    for idx0 in buf:
        print('idx0 type ', type(idx0[0]))
        #if len(idx0)==2 and type(idx0[0]) == str and idx0[0] == 'unparsed':
        if len(idx0)==1:
            ind = 0
        elif len(idx0)==2:
            ind = 1
        if ind >= 0:
            if type(idx0[ind]) == str:
                if conversion == CONVERT_INT:
                    if len(idx0[ind]) == 1: return unpack("!B", idx0[ind])[0]
                    if len(idx0[ind]) == 2: return unpack("!H", idx0[ind])[0]
                    else: return unpack("!L", idx0[ind])[0]
                else:
                    return str(idx0[ind],'iso8859-1')
            elif type(idx0[ind]) == int:
                if conversion == CONVERT_STRING: return str(idx0[ind],'iso8859-1')
                else: return idx0[ind]
    return '0'

def vspIsEncrypted(tlv):
    vsp_tag_val = tlv.getTag((0xDF,0xDF,0x6F))
    if len(vsp_tag_val):
        vsp_tag_val = tlv.getTag((0xDF,0xDF,0x6F), TLVParser.CONVERT_INT)[0]
        if vsp_tag_val != 0:
            log.log('VSP Encryption detected, flag ', hex(vsp_tag_val), '!')
            return True
        else:
            log.log('VSP present, but transaction unencrypted!')
    return False

# Decrypts VSP - encrypted data
def vspDecrypt(tlv, tid):
    if not vspIsEncrypted(tlv):
        return False
    if len(tid) == 0:
        log.logerr('Cannot decrypt, no TID detected!')
        return False
    try:
        enc = semtec.encryptor()
        enc.set_TID(tid)
    except exceptions.logicalException as exc:
        log.logerr('Cannot create decryptor object! Error ', exc)
        return False

    eparms = tlv.getTag((0xDF, 0xDF, 0x70), TLVParser.CONVERT_HEX_STR)
    if len(eparms): eparms = eparms[0]
    else: eparms = ''
    pan = tlv.getTag(0x5A, TLVParser.CONVERT_HEX_STR)
    if len(pan): pan = pan[0]
    else: pan = ''
    expiry = tlv.getTag((0x5F, 0x24), TLVParser.CONVERT_HEX_STR)
    if len(expiry): expiry = expiry[0]
    else: expiry = ''
    if len(pan) > 0:
        # EMV transaction - get appropriate tags
        log.log('EMV')
        t2eq = tlv.getTag(0x57, TLVParser.CONVERT_HEX_STR)
        if len(t2eq): t2eq = t2eq[0]
        else: t2eq = ''
        t1dd = tlv.getTag((0x9F, 0x1F), TLVParser.CONVERT_HEX_STR)
        if len(t1dd): t1dd = t1dd[0]
        else: t1dd = ''
        t2dd = tlv.getTag((0x9F, 0x20), TLVParser.CONVERT_HEX_STR)
        if len(t2dd): t2dd = t2dd[0]
        else: t2dd = ''
        if len(pan): log.log('PAN: ', pan)
        if len(expiry): log.log('Expiry: ', expiry)
        if len(t2eq): log.log('T2EQ: ', t2eq)
        if len(t2dd): log.log('T2DD: ', t2dd)
        if len(t1dd): log.log('T1DD: ', t1dd)
        try:
            pan_d, expiry_d, t2eq_d, t2dd_d, t1dd_d = enc.decrypt_emv(pan, expiry, t2eq, t2dd, t1dd, eparms)
            if len(pan_d): log.log('Decrypted PAN: ', pan_d)
            if len(expiry_d): log.log('Decrypted Expiry: ', expiry_d)
            if len(t2eq_d): log.log('Decrypted T2EQ: ', t2eq_d)
            if len(t2dd_d): log.log('Decrypted T2DD: ', t2dd_d)
            if len(t1dd_d): log.log('Decrypted T1DD: ', t1dd_d)
            return True
        except exceptions.logicalException as exc:
            log.logerr('Cannot decrypt! Error ', exc)
            # log.logerr('Cannot decrypt!')
            return False
    else:
        log.log('Magstripe')
        t1 = tlv.getTag((0x5F, 0x21), TLVParser.CONVERT_STR)
        if len(t1): t1 = t1[0]
        else: t1 = ''
        t2 = tlv.getTag((0x5F, 0x22), TLVParser.CONVERT_STR)
        if len(t2): t2 = t2[0]
        else: t2 = ''
        if len(pan): log.log('PAN: ', pan)
        if len(expiry): log.log('Expiry: ', expiry)
        if len(t1): log.log('T1: ', t1)
        if len(t2): log.log('T2: ', t2)

        try:
            pan_d, expiry_d, t1_d, t2_d = enc.decrypt(pan, expiry, t1, t2, eparms)
            if len(pan_d): log.log('Decrypted PAN: ', pan_d)
            if len(expiry_d): log.log('Decrypted Expiry: ', expiry_d)
            if len(t1_d): log.log('Decrypted T1: ', t1_d)
            if len(t2_d): log.log('Decrypted T2: ', t2_d)
            return True
        except exceptions.logicalException as exc:
            log.logerr('Cannot decrypt! Error ', exc)
            # log.logerr('Cannot decrypt!')
            return False

# Finalise the script, clear the screen
def performCleanup():
    # Clear screen
    conn.send([0xD2, 0x01, 0x01, 0x01])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer(True, False)
    # Disconnect

# Gets answer from the device, optionally ignoring unsolicited and stopping on errors
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

def getEMVAnswer(ignoreUnsolicited = False):
    return getAnswer(ignoreUnsolicited, False)

# Checks card status, based on device response
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

# Get magstripe status, based on device response
def MagstripeCardState(tlv):
    res = -1
    # Check for card status
    if tlv.tagCount(0x48):
        ins_tag_val = tlv.getTag(0x48, TLVParser.CONVERT_INT)[0]
        ins_tag_val &= 0x00FF
        ##log.log('MSR STATUS:', ins_tag_val)
        if ins_tag_val == 1:
            log.logerr('Magstripe, but no tracks!')
            res = ERROR_UNKNOWN_CARD
        else:
            if ins_tag_val == 0:
                res = EMV_CARD_REMOVED
            else:
                res = MAGSTRIPE_TRACKS_AVAILABLE
    return res

# Ask for card removal and waits until card is removed
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

# Processes magstripe fallback - asks for swipe
def processMagstripeFallback(tid):
    # Ask for removal and swipe 
    conn.send([0xD0, 0x60, 0x1D, 0x00])
    while True:
        status, buf, uns = getAnswer(False) # Get unsolicited
        if uns:
            tlv = TLVParser(buf)
            if EMVCardState(tlv) == EMV_CARD_INSERTED:
                tlv = removeEMVCard()
                break
    # Ask for swipe
    if MagstripeCardState(tlv) == EMV_CARD_REMOVED:
        conn.send([0xD2, 0x01, 0x00, 0x01], '\x09Please Swipe Card')
        status, buf, uns = getAnswer()
        # Wait for swipe
        while True:
            status, buf, uns = getAnswer(False)
            if uns:
                tlv = TLVParser(buf)
                magState = MagstripeCardState(tlv)
                if magState == ERROR_UNKNOWN_CARD or magState == MAGSTRIPE_TRACKS_AVAILABLE:
                     break
            log.log('Ignoring unsolicited packet ', tlv)
            continue
    if MagstripeCardState(tlv) == MAGSTRIPE_TRACKS_AVAILABLE:
        vspDecrypt(tlv, tid)

    # We're done!
    return 5

# EMV transaction
def processEMV(tid):

    log.log("START TRANSACTION: ***************************************************************************************")

    #Create localtag for transaction
    aid = b'\xa0\x00\x00\x00\x03\x10\x10'
    start_trans_tag = [
         ##[(0x9F, 0x06), aid],
         TRANSACTION_AMOUNT,              # amount
         [(0x9A), DATE],                  # date
         [(0x9F,0x21), TIME],             # time
         [(0x9C), b'\x00'],               # transaction type
         CURRENCY_CODE,                   # currency code
         [(0x9F,0x41), b'\x00\x01' ],     # transaction counter
         [(0xDF,0xA2,0x18), b'\x00'],     # pin entry style
         [(0xDF,0xA2,0x14), b'\x01'],
         [(0xDF,0xA2,0x04), b'\x00']      # Manual app selection!!
         #[(0xDF, 0xDF, 0x0D), b'\x02']   # Don't force transaction online
    ]
    start_templ = ( 0xE0, start_trans_tag )
    #Start transaction
    conn.send([0xDE, 0xD1, 0x00, 0x00], start_templ)

    while True:
        #sleep(1)
        #conn.send([0xD0, 0xFF, 0x00, 0x00])
        status, buf, uns = getEMVAnswer()
        if status != 0x9000:
            if status == 0x9F28:
                return processMagstripeFallback(tid)
            else:
                log.logerr('Transaction terminated with status ', hex(status))
                return -1
        if uns and status == 0x9000:
            tlv = TLVParser(buf)
            if tlv.tagCount(0xE6) != 0:
                log.log('Multi application card!')
                continue
            else:
                log.log('Ignoring unsolicited packet ', tlv)
                continue
        else:
            tlv = TLVParser(buf)
            if tlv.tagCount(0x50) > 1 and tlv.tagCount((0x9F, 0x06)) > 1:
                # This is app selection stuff
                appLabels = tlv.getTag(0x50)
                appAIDs = tlv.getTag((0x9F, 0x06))
                log.log('We have ', len(appLabels), ' applications')
                if len(appLabels) != len(appAIDs):
                    log.logerr('Invalid response: AID count ', len(appAIDs), ' differs from Labels count ', len(appLabels))
                    exit(-1)
                for i in range(len(appLabels)):
                    log.log('App ', i+1, ': AID ', hexlify(appAIDs[i]), ', label ', str(appLabels[i]))
                sel = -1

                while True:
                    #sels = input('Choose one app: ')
                    #try:
                    #    sel = int(sels.strip())
                    #except:
                    #    print('invalid entry!!!')
                    #if sel > 0 and sel <= len(appLabels): break
                    #print(' Invalid selection, please pick valid number! ')
                    # Note: The below will work for up to 9 apps...
                    if kbhit():
                        try:
                            sel = ord(getch())
                        except:
                            print('invalid key!')
                        #log.log('key press ', sel)
                        if sel > 0x30 and sel <= 0x30+len(appLabels): 
                            sel -= 0x30 # to number (0 .. x)
                            break
                        elif sel == 27:
                            conn.send([0xD0, 0xFF, 0x00, 0x00])
                            status, buf, uns = getAnswer()
                            log.logerr('Transaction aborted')
                            return -1
                        print(' Invalid selection, please pick valid number! ')
                    if conn.is_data_avail():
                        status, buf, uns = getEMVAnswer()
                        if status != 0x9000:
                            log.logerr('Transaction terminated with status ', hex(status))
                            return -1
                        break
                if sel >= 0:
                    sel = sel-1
                    log.log('Selected ', sel)
                    app_sel_tags = [
                        [(0x50), bytearray(appLabels[sel])],
                        [(0x9F, 0x06), bytearray(appAIDs[sel])]
                    ]
                    app_sel_templ = ( 0xE0, app_sel_tags )
                    conn.send([0xDE, 0xD2, 0x00, 0x00], app_sel_templ)
                    log.log('App selected, waiting for response...')
                    continue
            break

    #Let's check VSP
    tlv = TLVParser(buf)
    vspDecrypt(tlv, tid)

    log.log("CONTINUE TRANSACTION: GenAC1 -----------------------------------------------------------------------------")

    #print(TLVParser(buf))
    #Continue transaction
    continue_tran_tag = [
        TRANSACTION_AMOUNT,
        CURRENCY_CODE,
        COUNTRY_CODE,
        ACQUIRER_ID,                      
        [ (0xDF, 0xA2, 0x18), [0x00] ],                         # Pin entry style
        [ (0xDF, 0xA3, 0x07), [0x03,0xE8] ],                    # Bit map display
        [ (0x89), [0x00] ],                                     # Host Authorisation Code)
        AUTHRESPONSECODE,                                       # TAG 8A
        OFFLINEPINVERIFY if ISOFFLINE else ONLINEPINVERIFY,     # TAG C0 object decision: 00=AAC, 01=TC
        [ (0xDF, 0xCC, 0x79), [0x01] ],                         # QuickChip transaction
        [ (0x91), [0x37, 0xDD, 0x29, 0x75, 0xC2, 0xB6, 0x68, 0x2D, 0x00, 0x12] ]
    ]
    continue_tpl = (0xE0, continue_tran_tag )
    conn.send([0xDE, 0xD2, 0x00, 0x00], continue_tpl)

    while True:
        status, buf, uns = getEMVAnswer()
        if status != 0x9000:
            log.logerr('Transaction terminated with status ', hex(status))
            return -1
        tlv = TLVParser(buf)
        if uns and status == 0x9000:
            #print(tlv)
            if tlv.tagCount(0xE6) != 0:
                log.log('PIN Entry is being performed, waiting again')
                print('PIN Entry, press \'A\' to abort, \'B\' to bypass or \'C\' to cancel')
                while True:
                    #sleep(1)
                    validKey = False
                    if kbhit():
                        key = getch()
                        log.log('key press ', key)
                        if key == 'a' or key == 'A':
                            log.logerr('aborting')
                            conn.send([0xD0, 0xFF, 0x00, 0x00])
                            validKey = True
                        if key == 'b' or key == 'B':
                            log.logerr('bypassing')
                            conn.send([0xDE, 0xD5, 0xFF, 0x01])
                            validKey = True
                        if key == 'c' or key == 'C':
                            log.logerr('cancelling')
                            conn.send([0xDE, 0xD5, 0x00, 0x00])
                            validKey = True

                        if validKey:
                            status, buf, uns = getAnswer(stopOnErrors = False) # Wait for confirmation, then break to wait for response
                            if status == 0x9000: break
                            else: continue
                        else:
                            continue
                    if conn.is_data_avail():
                        break
                continue
            else:
                log.log('Ignoring unsolicited packet ', tlv)
                continue
        else:
            if tlv.tagCount(0xE3):
                log.log("Transaction approved offline")
                return 1
            else:
                if tlv.tagCount(0xE5):
                    log.log("Transaction declined offline")
                    return 2
                else:
                    break

    log.log("CONTINUE TRANSACTION: GenAC2 -----------------------------------------------------------------------------")

    # If we get here, we received Online Request. Continue with positive response. 
    conn.send([0xDE, 0xD2, 0x00, 0x00])
    status, buf, uns = getEMVAnswer(True) # Ignore unsolicited automatically here
    if status != 0x9000:
        log.logerr('Online Request has failed', hex(status))
        return -1
    tlv = TLVParser(buf)
    if tlv.tagCount(0xE3):
        log.log("Transaction approved")
        return 1
    if tlv.tagCount(0xE5):
        log.log("Transaction declined")
        return 2
    return 3

# Processes contactless continue
def processCtlsContinue():
    #Create localtag for transaction
    continue_ctls_tag = [
        ##[ (0xC2), [0x30, 0x30] ],
        [ (0xC2), [0x36, 0x35] ],
        [ (0xC0), [0x01] ],
        [ (0x89), b'\x37\xDD\x29\x75\xC2\xB6' ]  # Warning: DUMMY VALUE!
    ]
    continue_ctls_templ = ( 0xE0, continue_ctls_tag )
    #Start transaction
    conn.send([0xC0, 0xA1, 0x00, 0x00], continue_ctls_templ)
    status, buf, uns = getAnswer()
    log.log('Waiting for Contactless Continue')
    while True:
        status, buf, uns = getAnswer(False)
        if uns:
            break
        log.logerr('Unexpected packet detected, ', TLVParser(buf))

# Inits contactless device
def initContactless():
    #Get contactless count
    ctls = False
    conn.send([0xC0, 0x00, 0x00, 0x00])
    status, buf, uns = getAnswer(True, False)
    if status == 0x9000:
        cnt = getDataField(buf, CONVERT_INT)
        if cnt >= 1:
            log.log("Detected ", cnt, " contactless devices")
            ctls = True
            # Init contactless
            conn.send([0xC0, 0x01, 0x00, 0x00])
            status, buf, uns = getAnswer()
            # Get contactless info, for logging purposes mainly
            conn.send([0xC0, 0x00, 0x01, 0x00])
            status, buf, uns = getAnswer()
        else:
            log.log('No contactless devices found')
    else:
        log.log('No contactless driver found')
    return ctls

# Start Contactless Transaction
def startContactless():
    global AMOUNT, AMTOTHER, DATE, TIME
    # Start Contactless transaction
    start_ctls_tag = [
        AMOUNT,
        [(0x9A), b'\x20\x03\x23'],
        [(0x9C), b'\x00'],
        [(0x9F,0x21), b'\x10\x30\x01'],
        # [(0x9F, 0x41), b'\x00\x01' ],
        ## --- 0x9F14 - Command Incorrectly Formatted
        CURRENCY_CODE,
        COUNTRY_CODE
    ]
    start_ctls_templ = ( 0xE0, start_ctls_tag )

    # START CONTACTLESS TRANSACTION [C0, A0]
    # P1
    #     Bit 0 (0x01)
    #     arm for Payment cards (transaction)
    #     Bit 1 (0x02)
    #     arm for MIFARE cards (VIPA 6.2.0.11+ on V/OS)
    #     Bit 3 (0x08)
    #     force transaction in offline
    #     Bit 4 (0x10)
    #     prioritize MIFARE before payment
    #     Bit 5 (0x20)
    #     (VOS2 devices only) arm for VAS (Value Added Services) transaction 
    #     (wallet/loyalty)
    #     Bit 6 (0x40)
    #     force CVM (transaction forces processing CVM regardless of CVM Limit configured)
    #     * this feature is used primarily for SCA
    #     Bit 7 (0x80)
    #     stop on MIFARE command processing errors (only valid when bit 1 is set)
    conn.send([0xC0, 0xA0, 0x01, 0x00], start_ctls_templ)

    log.log('Starting Contactless transaction')

# Prompts for card insertion
def promptForCard():
    #Prompt for card
    conn.send([0xD2, 0x01, 0x0D, 0x01])
    status, buf, uns = getAnswer()

# Main function
def processTransaction():

    global DATE, TIME
    
    # TIMESTAMP
    now = datetime.datetime.now()
    DATE = bcd(now.year % 100) + bcd(now.month) + bcd(now.day)
    TIME = bcd(now.hour % 100) + bcd(now.minute) + bcd(now.second)
    
    req_unsolicited = conn.connect()
    if req_unsolicited:
        #Receive unsolicited
        log.log('Waiting for unsolicited')
        #status, buf, uns = getAnswer(False)
        #log.log('Unsolicited', TLVParser(buf) )

    #Send reset device
    conn.send([0xD0, 0x00, 0x00, 0x01])
    status, buf, uns = getAnswer()
    tlv = TLVParser(buf)
    tid = tlv.getTag((0x9F, 0x1E))
    if len(tid): 
        tid = str(tid[0], 'iso8859-1')
        log.log('Terminal TID: ', tid)
    else: 
        tid = ''
        log.logerr('Invalid TID (or cannot determine TID)!')

    #Send clear display
    conn.send([0xD2, 0x01, 0x01, 0x01])
    status, buf, uns = getAnswer()

    ## CARD STATUS [D0, 60]
    # P1 - REQUESTS
    # Bit 0 - Sets the device to report changes in card status
    # Bit 1 - Requests the ATR in the response (tag 63)
    # Bit 2 - Requests the Track 1 data in the response (tag 5F21)
    # Bit 3 - Requests the Track 2 data in the response (tag 5F22)
    # Bit 4 - Requests the Track 3 data in the response (tag 5F23)
    # Bit 5 - Enables magnetic track status reporting (tag DFDF6E)
    # Bit 6 - Disables magnetic reader notifications
    # Bit 7 - Disables ICC notifications   
    #  
    # P2 - Monitor card and keyboard status
    # 00 - stop reporting key presses
    # Bit 0 - report enter, cancel and clear key presses
    # Bit 1 - report function key presses
    ## ICC + MSR
    conn.send([0xD0, 0x60, 0x3F, 0x03])
    ## TURN OFF ICC
    ##conn.send([0xD0, 0x60, 0xBF, 0x03])
    ## TURN OFF MSR
    #conn.send([0xD0, 0x60, 0x7F, 0x03])
    status, buf, uns = getAnswer(False)
    cardState = EMV_CARD_REMOVED
    if uns:
        # Check for insertion unsolicited message
        tlv = TLVParser(buf)
        if tlv.tagCount(0x48):
            cardState = EMVCardState(tlv)

    ctls = initContactless()
    ###ctls = False
    if (cardState != EMV_CARD_INSERTED):
        if (ctls):
            # Start Contactless transaction
            startContactless()
            status, buf, uns = getAnswer()
            ## TEST BUG WITH PRESENT CARD IMAGE
            ##exit(-1)
        else:
            promptForCard()
        log.log('**** WAIT FOR CARD INSERTION / TAP / SWIPE ****')

        tranType = 0
        result = 0
        ignoreSwipe = False
        attempts = 0
        
        while True:
            status, buf, uns = getAnswer(False) # Get unsolicited ONLY
            if uns:
                ##log.log('Card reading attempt...')
                # Check for insertion unsolicited message
                tlv = TLVParser(buf)
                #if tlv.tagCount(0x63):
                #    reader_tag_val = tlv.getTag((0x63), TLVParser.CONVERT_INT)[0]
                #    log.log("reader status ",hex(reader_tag_val), 'h')
                if tlv.tagCount(0x48):
                    #log.log('Card read attempts', attempts)
                    #if attempts == 1:
                    #    log.log("MSR fallback in effect!")
                    #    processMagstripeFallback(tid)
                    #    break
                    #attempts = attempts + 1
                    cardState = EMVCardState(tlv)
                    magState = MagstripeCardState(tlv)
                    if ctls and (cardState == EMV_CARD_INSERTED or magState == MAGSTRIPE_TRACKS_AVAILABLE): # Ignore failed swipes
                        # Cancel Contactless first
                        log.log('Cancelling contactless')
                        conn.send([0xC0, 0xC0, 0x00, 0x00])
                        status, buf, uns = getAnswer()
                        status, buf, uns = getAnswer(False) # Ignore unsolicited as the answer WILL BE unsolicited... 
                    if cardState == EMV_CARD_INSERTED:
                        log.log("Card inserted, process EMV transaction!")
                        result = processEMV(tid)
                        tranType = 1
                        break
                    else:
                        if cardState == ERROR_UNKNOWN_CARD:
                            log.log('Unknown card type ')
                            continue
                    if not ignoreSwipe:
                        if magState == ERROR_UNKNOWN_CARD:
                            log.logerr('Swipe has failed, there are no tracks!')
                            continue
                        else:
                            if magState == MAGSTRIPE_TRACKS_AVAILABLE:
                                log.log('Card swiped!')
                                vspDecrypt(tlv, tid)
                                tranType = 2
                                break
                    log.log("Waiting for next occurrance!")
                    continue
                # Check for unsolicited keyboard status
                if tlv.tagCount((0xDF,0xA2,0x05)):
                    kbd_tag_val = tlv.getTag((0xDF,0xA2,0x05), TLVParser.CONVERT_INT)[0]
                    log.log("Keyboard status, keypress ",hex(kbd_tag_val), 'h')
                    continue
                if tlv.tagCount(0xE3) or tlv.tagCount(0xE5):
                    log.log("Approved contactless EMV transaction!")
                    # todo: vsp decrypt!
                    vspDecrypt(tlv, tid)
                    tranType = 4
                    break
                if tlv.tagCount(0xE7):
                    vspDecrypt(tlv, tid)
                    processCtlsContinue()
                    tranType = 3
                    break
                if tlv.tagCount(0xE4):
                    vspDecrypt(tlv, tid)
                    processCtlsContinue()
                    tranType = 5
                    break
                if status != 0x9000:
                    if status == 0x9F33: # Fallforward to ICC / Swipe
                        promptForCard()
                        # No need to exit the loop - swipe is not active now
                        continue
                    else:
                        if status == 0x9F34: # Fallforward to ICC only
                            promptForCard()
                            # No need to exit the loop - ctls is not active now, but we have to disable swipes
                            ignoreSwipe = True
                            continue
            log.logerr("Invalid packet detected, ignoring it!")
            print('E4: ', tlv.tagCount(0xE4))
            print(tlv)
    else:
        log.log("Card already inserted!")
        result = processEMV(tid)
        tranType = 1

    # After loop
    if tranType == 1:
        # If card still inserted, ask for removal
        conn.send([0xD0, 0x60, 0x01, 0x00])
        status, buf, uns = getAnswer(False) # Get unsolicited
        tlv = TLVParser(buf)
        if EMVCardState(tlv) == EMV_CARD_INSERTED:
            log.log("Card inserted, asking to remove it")
            removeEMVCard()
    else:
      log.log('Closing Contactless reader')
      conn.send([0xC0, 0x02, 0x00, 0x00])
      status, buf, uns = getAnswer(False) # Get unsolicited
         
    # STOP Monitor card and keyboard status
    # P2 - keyboard monitoring
    # 00 - stop reporting key presses
    # Bit 0 - report enter, cancel and clear key presses
    # Bit 1 - report function key presses
    conn.send([0xD0, 0x61, 0x00, 0x00])
    log.log('*** STOP KEYBOARD MONITORING ***')
    status, buf, uns = getAnswer()
    
    #Reset display - regardless of tx type
    conn.send([0xD2, 0x01, 0x01, 0x00])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer()

    #log.log('*** DISCONNECT ***')
    #status, buf, uns = conn.receive()
    #if status != 0x9000:
    #    log.logerr('Disconnect wait', hex(status), buf)
    #    exit(-1)


if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection()

    utility.register_testharness_script(processTransaction)
    utility.do_testharness()
