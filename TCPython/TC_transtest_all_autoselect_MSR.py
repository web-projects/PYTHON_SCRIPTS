#!/usr/bin/python3
'''
Created on 21-06-2012

@authors: Lucjan_B1, Kamil_P1, Matthew_H
'''

from TC_testharness import *
import TC_testharness.utility as util
from functools import partial
from TC_testharness.tlvparser import TLVParser
from TC_testharness.tlvparser import TLVPrepare
from sys import exit
from TC_testharness.syslog import getSyslog
from TC_testharness.utility import getch, kbhit
import TC_TCLink
from binascii import hexlify, unhexlify
from time import sleep
import sys
import getpass
import datetime
import traceback

CONVERT_INT = 1
CONVERT_STRING = 2

EMV_CARD_REMOVED = 0
EMV_CARD_INSERTED = 1
MAGSTRIPE_TRACKS_AVAILABLE = 2
ERROR_UNKNOWN_CARD = 3

# BCD EMV values (must poplate before transaction start)
AMOUNT = b'\x00\x00\x00\x00\x01\x00'
DATE = b'\x20\x01\x01'
TIME = b'\x00\x00\x00'

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
            traceback.print_stack()
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
        if ins_tag_val == 3:
            log.log('Card inserted!')
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
    global AMOUNT, DATE, TIME
    #Create localtag for transaction
    start_trans_tag = [
         #[(0x9F, 0x02), b'\x00\x00\x00\x00\x50\x00' ],
         [(0x9F, 0x02), AMOUNT ],
         #[(0x9A), b'\x20\x01\x27'],   # TODO: Update to actual date
         [(0x9A), DATE],
         [(0x9C), b'\x00'],
         #[(0x9F,0x21), b'\x01\x01\x01'],   # TODO: Update to actual time
         [(0x9F,0x21), TIME],
         [(0x9F,0x41), b'\x00\x01' ],
         # [(0x5F,0x2A), b'\x08\x26' ],
         [(0x5F,0x2A), b'\x08\x40' ],
         [(0xDF,0xA2,0x18), b'\x00'],
         [(0xDF,0xA2,0x14), b'\x01'],
         #[(0xDF,0xA2,0x04), b'\x00']   # Comment for Manual app selection!!
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
            # Check for Contact EMV Capture
            #print(">>> EMV Data 0 ff7f", tlv.tagCount((0xFF,0x7F)))
            TC_TCLink.saveCardData(tlv)
            break

    #Let's check VSP
    tlv = TLVParser(buf)
    vspDecrypt(tlv, tid)
	# Check for Contact EMV Capture
    #print(">>> EMV Data 1 ff7f", tlv.tagCount((0xFF,0x7F)))
    TC_TCLink.saveCardData(tlv)

    #print(TLVParser(buf))
    #Continue transaction
    continue_tran_tag = [
        [ (0x9F,0x02), [0x00, 0x00, 0x00,0x00, 0x54, 0x00 ] ],
        [ (0x5F,0x2A), [0x08, 0x40] ],
        [ (0xC2), [0x36, 0x35] ],
        #[ (0xDF,0xA2,0x18), [0x00] ],
        #[ (0xDF,0xA3,0x07), [0x03,0xE8] ],
        #[ (0xC0), [0x01] ],
        [ (0x8A), [0x5A,0x33] ],
        # [ (0x91), [0x37,0xDD,0x29,0x75,0xC2,0xB6,0x68,0x2D,0x00,0x12] ],
        [ (0xDF,0xCC,0x79), [0x01] ]
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

    # If we get here, we received Online Request. Continue with positive response. 
    # continue_tran_tag = [
    #     [ (0x8A), [0x5A,0x33] ]
    # ]
    # continue_tpl = (0xE0, continue_tran_tag )
    # conn.send([0xDE, 0xD2, 0x00, 0x00], continue_tpl)
    conn.send([0xDE, 0xD2, 0x00, 0x00])
    status, buf, uns = getEMVAnswer(True) # Ignore unsolicited automatically here
    if status != 0x9000:
        log.logerr('Online Request has failed', hex(status))
        return -1
    tlv = TLVParser(buf)
    if tlv.tagCount(0xE3):
        log.log("Transaction approved")
        # Check for Contact EMV Capture
        #print(">>> EMV Data 2 ff7f", tlv.tagCount((0xFF,0x7F)))
        TC_TCLink.saveCardData(tlv)
        return 1
    if tlv.tagCount(0xE5):
        log.log("Transaction declined")
        # Check for Contact EMV Capture
        #print(">>> EMV Data 3 ff7f", tlv.tagCount((0xFF,0x7F)))
        TC_TCLink.saveCardData(tlv)
        return 2
    # Check for Contact EMV Capture
    #print(">>> EMV Data 4 ff7f", tlv.tagCount((0xFF,0x7F)))
    TC_TCLink.saveCardData(tlv)
    return 3

# Processes contactless continue
def processCtlsContinue():
    #print(">>>  processCtlsContinue")
    #Create localtag for transaction
    continue_ctls_tag = [
        [ (0xC2), [0x30, 0x30] ],
        [ (0xC0), [0x01] ],
        [ (0x8A), [0x5A,0x33] ]
        # [ (0x89), b'\x37\xDD\x29\x75\xC2\xB6' ]  # Warning: DUMMY VALUE!
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

# Prompts for card insertion
def promptForCard():
    #Prompt for card
    conn.send([0xD2, 0x01, 0x0D, 0x01])
    status, buf, uns = getAnswer()

# Main function
def processTransaction(args):
    global AMOUNT, DATE, TIME
    TC_TCLink.SetProperties(args, log)
    AMOUNT = bcd(args.amount, 6)
    now = datetime.datetime.now()
    DATE = bcd(now.year % 100) + bcd(now.month) + bcd(now.day)
    TIME = bcd(now.hour % 100) + bcd(now.minute) + bcd(now.second)
    #print("Amount", str(AMOUNT), "vs", str(b'\x00\x00\x00\x00\x01\x00'))
    #print("Date", str(DATE), "Time", str(TIME))
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
    tid = tlv.getTag((0x9F, 0x1e))
    if len(tid): 
        tid = str(tid[0], 'iso8859-1')
        TC_TCLink.setDeviceSerial(tid)
        log.log('Terminal TID: ', tid)
    else: 
        tid = ''
        log.logerr('Invalid TID (or cannot determine TID)!')

    #Send clear display
    conn.send([0xD2, 0x01, 0x01, 0x01])
    status, buf, uns = getAnswer()

    #Monitor card and keyboard status
    conn.send([0xD0, 0x60, 0x1D, 0x03])
    status, buf, uns = getAnswer(False)
    cardState = EMV_CARD_REMOVED
    if uns:
        # Check for insertion unsolicited message
        tlv = TLVParser(buf)
        if tlv.tagCount(0x48):
            cardState = EMVCardState(tlv)

    ctls = initContactless()
    if (cardState != EMV_CARD_INSERTED):
        if (ctls):
            # Start Contactless transaction
            start_ctls_tag = [
                #[(0x9F, 0x02), b'\x00\x00\x00\x00\x01\x00' ],
                [(0x9F, 0x02), AMOUNT ],
                #[(0x9A), b'\x12\x01\x01'],
                [(0x9A), DATE],
                [(0x9C), b'\x00'],
                #[(0x9F,0x21), b'\x01\x01\x01'],
                [(0x9F,0x21), TIME],
                # [(0x9F,0x41), b'\x00\x01' ],
                # [(0x5F,0x2A), b'\x08\x26' ],
                [(0x5F,0x2A), b'\x08\x40' ],
                # [(0x9F,0x1A), b'\x08\x26' ]
                [(0x9F,0x1A), b'\x08\x40' ]
            ]
            start_templ = ( 0xE0, start_ctls_tag )
            conn.send([0xC0, 0xA0, 0x01, 0x00], start_templ)
            log.log('Starting Contactless transaction')
            status, buf, uns = getAnswer()
        else:
            promptForCard()
        log.log('**** WAIT FOR CARD INSERTION / TAP / SWIPE ****')

        tranType = 0
        result = 0
        ignoreSwipe = False
        while True:
            #status, buf, uns = getAnswer(False) # Get unsolicited ONLY
            status, buf, uns = getAnswer(False, False) # Get unsolicited ONLY
            if uns:
                # Check for insertion unsolicited message
                tlv = TLVParser(buf)
                if tlv.tagCount(0x48):
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
                TC_TCLink.saveCardData(tlv)
                #print(">>> ff7f", tlv.tagCount((0xFF,0x7F)))
                #if tlv.tagCount((0xFF,0x7F)):
                #    #log.log('>>> vsp_tlv bytes', tlv.getTag((0xFF,0x7F))[0])
                #    tlvp = TLVPrepare()
                #    vsp_tlv_tags = tlvp.parse_received_data( tlv.getTag((0xFF,0x7F))[0] )
                #    vsp_tlv = TLVParser(vsp_tlv_tags)
                #    #vsp_tlv = TLVParser(tlv.getTag((0xFF,0x7F))[0])
                #    #log.log('>>> buf', buf)
                #    #log.log('>>> tlv', tlv)
                #    #log.log('>>> vsp_tlv_tags', vsp_tlv_tags)
                #    #log.log('>>> vsp_tlv', vsp_tlv)
                #    if vsp_tlv.tagCount((0xDF,0xDF,0x10)):
                #        print(">>> vsp_tlv DFDF10", hexlify(vsp_tlv.getTag((0xDF,0xDF,0x10))[0]))
                #    if vsp_tlv.tagCount((0xDF,0xDF,0x11)):
                #        print(">>> vsp_tlv DFDF11", hexlify(vsp_tlv.getTag((0xDF,0xDF,0x11))[0]))
                #    if vsp_tlv.tagCount((0xDF,0xDF,0x12)):
                #        print(">>> vsp_tlv DFDF12", hexlify(vsp_tlv.getTag((0xDF,0xDF,0x12))[0]))
                #    if vsp_tlv.tagCount((0xDF,0xDF,0x10)) and vsp_tlv.tagCount((0xDF,0xDF,0x11)) and vsp_tlv.tagCount((0xDF,0xDF,0x12)):
                #        encryptedtrack = 'TVP|iv:' + vsp_tlv.getTag((0xDF,0xDF,0x12))[0].hex() + '|ksn:' + vsp_tlv.getTag((0xDF,0xDF,0x11))[0].hex() + '|vipa:' + vsp_tlv.getTag((0xDF,0xDF,0x10))[0].hex()
                #        log.log('>>> encryptedtrack=' + str(encryptedtrack) + '\\ncustid=' + str(custid) + '\\npassword=' + str(password) + '\\naction=' + str(action) + '\\ndevice_serial=' + str(tid))
                if tlv.tagCount(0xE3) or tlv.tagCount(0xE5): # E3 = transaction approved; E5 = Transaction Declined
                    log.log("Approved contactless EMV transaction!")
                    # todo: vsp decrypt!
                    vspDecrypt(tlv, tid)
                    # Should tags be captured for an Offline Decline case and sent to TCLink?
                    if tlv.tagCount(0xE3): # E3 = transaction approved
                        TC_TCLink.saveEMVData(tlv,0xE3)
                    if tlv.tagCount(0xE5): # E5 = Transaction Declined
                        TC_TCLink.saveEMVData(tlv,0xE5)
                    tranType = 4
                    break
                if tlv.tagCount(0xE7): # Contactless Magstripe Transaction
                    vspDecrypt(tlv, tid)
                    processCtlsContinue()
                    tranType = 3
                    break
                if tlv.tagCount(0xE4): # Online Action Required
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
        sleep(0.500)	# Delay for some CLess messaging to complete; may be able to replace with loop awaiting card removed from field
    #Reset display - regardless of tx type
    conn.send([0xD2, 0x01, 0x01, 0x01])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer()
	# Check for Card data
    TC_TCLink.saveCardData(tlv)
	# Check for Contact EMV Capture
    #print(">>> tranType", tranType, "ff7f", tlv.tagCount((0xFF,0x7F)))
    #print(">>> tranType", tranType)
    if tranType == 1:
        #print(">>> ff7f", tlv.tagCount((0xFF,0x7F)))
        TC_TCLink.processEMVTransaction()
	# Check for swipe
    if tranType == 2:
        #print(">>> ff7f", tlv.tagCount((0xFF,0x7F)))
        TC_TCLink.processMSRTransaction()
	# Check for contactless magstripe
    if tranType == 3:
        #print(">>> ff7f", tlv.tagCount((0xFF,0x7F)))
        TC_TCLink.processCLessMagstripeTransaction()
	# Check for Offline approve/decline
    if tranType == 4:	# Should tags be captured for an Offline Decline case and sent to TCLink?
        #print(">>> ff7f", tlv.tagCount((0xFF,0x7F)))
        TC_TCLink.processEMVTransaction()
	# Check for CLess
    if tranType == 5:
        print(">>> ff7f", tlv.tagCount((0xFF,0x7F)))
        TC_TCLink.processEMVTransaction()
        #TC_TCLink.processCLessMagstripeTransaction()

    #log.log('*** DISCONNECT ***')
    #status, buf, uns = conn.receive()
    #if status != 0x9000:
    #    log.logerr('Disconnect wait', hex(status), buf)
    #    exit(-1)


if __name__ == '__main__':
    log = getSyslog()

    arg = util.get_argparser();
    arg.add_argument( '--custid', dest='custid', default='1152701', type=int,
                            help='TC CustID for transaction' )
    arg.add_argument( '--password', dest='password', default='testipa1',
                            help='TC Password for transaction' )
    arg.add_argument( '--action', dest='action', default='sale',
                            help='TC Action for transaction' )
    arg.add_argument( '--amount', dest='amount', default='100', type=int,
                            help='Amount of transaction' )
    arg.add_argument( '--operator', dest='operator', default=getpass.getuser(),
                            help='Operator for transaction' )
    arg.add_argument( '--lanenumber', dest='lanenumber', default=None,
                            help='Lane Number for transaction' )
    args = util.parse_args();

    conn = connection.Connection()

    #print('custid=' + str(args.custid) + ",password=" + str(args.password) + ",action=" + str(args.action))
    utility.register_testharness_script(
               partial( processTransaction, args ))
    utility.do_testharness()


