#!/usr/bin/python3
'''
Created on 21-06-2012

@authors: Lucjan_B1, Kamil_P1
'''

from testharness import *
from testharness.tlvparser import TLVParser, TLVPrepare, tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import getch, kbhit
from binascii import hexlify, unhexlify
from time import sleep
from subprocess import Popen, PIPE

CONVERT_INT = 1
CONVERT_STRING = 2

EMV_CARD_REMOVED = 0
EMV_CARD_INSERTED = 1
MAGSTRIPE_TRACKS_AVAILABLE = 2
ERROR_UNKNOWN_CARD = 3

RSA_PUBLIC_KEY="rsa-public-key.pem"
RSA_PRIVATE_KEY="rsa-private-key.pem"

def execute(*args, stdinput = None):
    log.log("Executing:", args)
    proc = Popen(args, stdin=PIPE, stdout=PIPE, shell=True)
    (out, err) = proc.communicate(input = stdinput)
    output = out.decode('utf-8')
    log.log(output)
    if err:
        log.logerr("'%s %s' returned %s" % (cmd, args, ret))
        exit(err)
    return output

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

def checkEncryptedPAN(tlv):
    tokenTemplate = tlv.getTag((0xFF, 0x7C))
    if len(tokenTemplate) == 0: return

    parsed = TLVPrepare().parse_received_data(tokenTemplate[0] + b'\x90\x00')
    tokenTLV = TLVParser(parsed)
    encryptedPANblock = tokenTLV.getTag((0xDF, 0x83, 0x6F))
    if len(encryptedPANblock) == 0:
        log.log("Encrypted PAN block not found")
        return

    sha1len = 20
    encryptedlen = 128
    if len(encryptedPANblock[0]) != encryptedlen + sha1len:
        log.logerr("Invalid encrypted PAN length: %s, not %s"
            % (len(encryptedPANblock[0]), encryptedlen + sha1len))
    encryptedPAN = encryptedPANblock[0][ : encryptedlen]
    fingerprint = encryptedPANblock[0][-sha1len : ]
    strFingerprint = hexlify(fingerprint).decode('utf-8')
    log.log("Encrypted PAN:", hexlify(encryptedPAN).decode('utf-8'))
    global rsaPublicKeyFingerprint
    if rsaPublicKeyFingerprint != strFingerprint:
        log.logerr("RSA public key fingerprint does not match")
        log.logerr("Ours:", rsaPublicKeyFingerprint)
        log.logerr("Came:", strFingerprint)
        exit(1)
    else:
        log.log("RSA public key fingerprint OK:", strFingerprint)
    decryptedPAN = execute('openssl', 'rsautl', '-decrypt', '-inkey', RSA_PRIVATE_KEY,
        stdinput=encryptedPAN)
    log.log("Decrypted PAN:", decryptedPAN)

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
        tlv = TLVParser(buf)
        checkEncryptedPAN(tlv)
        if uns and ignoreUnsolicited:
            log.log('Unsolicited packet detected: ', tlv)
            continue
        if status != 0x9000:
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
    #Create localtag for transaction
    start_trans_tag = [
         [(0x9F, 0x02), b'\x00\x00\x00\x00\x50\x00' ],
         [(0x9A), b'\x04\x01\x01'],
         [(0x9C), b'\x00'],
         [(0x9F,0x21), b'\x01\x01\x01'],
         [(0x9F,0x41), b'\x00\x01' ],
         [(0x5F,0x2A), b'\x08\x26' ],
         [(0xDF,0xA2,0x18), b'\x00'],
         [(0xDF,0xA2,0x14), b'\x01'],
         [(0xDF,0xA2,0x04), b'\x01']
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
            break

    #Let's check VSP
    tlv = TLVParser(buf)
    vspDecrypt(tlv, tid)
    checkEncryptedPAN(tlv)

    #print(TLVParser(buf))
    #Continue transaction
    continue_tran_tag = [
        [ (0x9F,0x02), [0x00, 0x00, 0x00,0x00, 0x54, 0x00 ] ],
        [ (0x5F,0x2A), [0x09, 0x78] ],
        [ (0xC2), [0x36, 0x35] ],
        [ (0xDF,0xA2,0x18), [0x00] ],
        [ (0xDF,0xA3,0x07), [0x03,0xE8] ],
        [ (0xC0), [0x01] ],
        [ (0x91), [0x37,0xDD,0x29,0x75,0xC2,0xB6,0x68,0x2D,0x00,0x12] ]
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
    conn.send([0xDE, 0xD2, 0x00, 0x00])
    status, buf, uns = getEMVAnswer(True) # Ignore unsolicited automatically here
    if status != 0x9000:
        log.logerr('Online Request has failed', hex(status))
        return -1
    tlv = TLVParser(buf)
    checkEncryptedPAN(tlv)
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
        [ (0xC2), [0x30, 0x30] ],
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

# Processes MiFare stuff
def processCtlsMiFare():
    # Set LEDs
    leds_tag = [
      [ (0xDF, 0xDF, 0x0C), [ 0x01 ] ],  # Success - single beep (0x02 = Error - Double beep)
      [ (0xDF, 0xC0, 0x18), [ 0xff ] ]   # All LEDs on (0A would enable 2nd and 4th LED, it's 1010 binary)
    ]
    leds_template = ( 0xE0, leds_tag )
    conn.send( [0xC0, 0x10, 0x00, 0x00], leds_template )
    status, buf, uns = getAnswer()
    if (status != 0x9000):
        log.logerr('UI function failed!')
        # Todo: What should we do? Let's just ignore the error and continue
    
    # Read some stuff
    c_read_oper = tagStorage()
    c_read_oper.store((0xDF, 0xA5, 0x01), [ 0x02 ]) # DFA501 - Operation type (0x02 - Read, 0x03 - Write, ,0x04 - EPurse)
    c_read_oper.store((0xDF, 0xA5, 0x02), 'READ1') # DFA502 - ID so that the output can be identified
    c_read_oper.store((0xDF, 0xC0, 0x5A), [0x00]) # DFC05A - Sector number
    c_read_oper.store((0xDF, 0xC0, 0x5B), [0x01]), # DFC05B - Key type (0x01 - Type A, 0x02 - Type B)
    c_read_oper.store((0xDF, 0xC0, 0x5C), b'\xFF\xFF\xFF\xFF\xFF\xFF') # DFC05C - Valid key (6 bytes)
    c_read_oper.store((0xDF, 0xC0, 0x5D), [0x01]) # DFC05D - Starting block number
    c_read_oper.store((0xDF, 0xC0, 0x5E), [0x02]) # DFC05E - Number of blocks to read
    read_oper_1 = c_read_oper.getAsBytearray()
    c_read_oper.clear()
    c_read_oper.store((0xDF, 0xA5, 0x01), [ 0x02 ]) # DFA501 - Operation type (0x02 - Read, 0x03 - Write, ,0x04 - EPurse)
    c_read_oper.store((0xDF, 0xA5, 0x02), 'READ2') # DFA502 - ID so that the output can be identified
    c_read_oper.store((0xDF, 0xC0, 0x5A), [0x03]) # DFC05A - Sector number
    c_read_oper.store((0xDF, 0xC0, 0x5B), [0x01]) # DFC05B - Key type (0x00 - Type A, 0x01 - Type B)
    c_read_oper.store((0xDF, 0xC0, 0x5C), b'\xFF\xFF\xFF\xFF\xFF\xFF') # DFC05C - Valid key (6 bytes)
    c_read_oper.store((0xDF, 0xC0, 0x5D), [0x02]) # DFC05D - Starting block number
    c_read_oper.store((0xDF, 0xC0, 0x5E), [0x02])  # DFC05E - Number of blocks to read
    read_oper_2 = c_read_oper.getAsBytearray()
    c_read_oper.clear()
    c_read_oper.store((0xDF, 0xC0, 0x30), read_oper_1)
    #c_read_oper.store((0xDF, 0xC0, 0x30), read_oper_2)
    conn.send( [0xC0, 0xA1, 0x00, 0x00], c_read_oper.getTemplate(0xE0) )
    status, buf, uns = getAnswer()


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
def processTransaction():
    global rsaPublicKeyFingerprint
    rsaPublicKeyFingerprint = execute('openssl', 'sha1', '-r', RSA_PUBLIC_KEY).split()[0]
    log.log("Our RSA public key fingerprint:", rsaPublicKeyFingerprint)

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
                [(0x9F, 0x02), b'\x00\x00\x00\x00\x01\x00' ],
                [(0x9A), b'\x12\x01\x01'],
                [(0x9C), b'\x00'],
                [(0x9F,0x21), b'\x01\x01\x01'],
                # [(0x9F,0x41), b'\x00\x01' ],
                [(0x5F,0x2A), b'\x08\x26' ],
                [(0x9F,0x1A), b'\x08\x26' ]
            ]
            start_templ = ( 0xE0, start_ctls_tag )
            conn.send([0xC0, 0xA0, 0x01, 0x00], start_templ)  # For MiFare, change P1 to 0x03
            log.log('Starting Contactless transaction')
            status, buf, uns = getAnswer()
        else:
            promptForCard()
        log.log('**** WAIT FOR CARD INSERTION / TAP / SWIPE ****')

        tranType = 0
        result = 0
        ignoreSwipe = False
        while True:
            status, buf, uns = getAnswer(False) # Get unsolicited ONLY
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
                if tlv.tagCount(0xE0) and tlv.tagCount((0xDF, 0xC0, 0x41)):
                    log.log('MiFare tx detected!')
                    processCtlsMiFare()
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
    #Reset display - regardless of tx type
    conn.send([0xD2, 0x01, 0x01, 0x01])
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


