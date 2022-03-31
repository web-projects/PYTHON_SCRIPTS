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
import testharness.utility as util
import TC_TransactionHelper

# MiFare - inner tag processing
from testharness.tlvparser import TLVPrepare

# pip install pyperclip
import pyperclip

# ---------------------------------------------------------------------------- #
# GLOBALS
# ---------------------------------------------------------------------------- #

# 20211108
# 1. Added TVR status reporting
VERSION_LBL = '1.0.0.1'

# TRANSACTION TYPE (TAG 9C)
# 0x00 - Sale / Purchase (EMV) - "transaction_type_goods" is used
# 0x01 - Cash Advance (EMV) - "transaction_type_cash" is used
# 0x09 - Sale / Purchase with cashback (EMV) - "transaction_type_goods_with_disbursement" is used
# 0x20 - Return / Refund (EMV) - "transaction_type_returns" is used
# 0x30 - Balance (non-EMV) - "transaction_type_balance_inquiry" is used
# 0x31 - Reservation (non-EMV) - "transaction_type_reservation" is used
# 0xFE - none (non-EMV) - "transaction_type_" is skipped

TRANSACTION_TYPE = b'\x00' # SALE TRANSACTION
#TRANSACTION_TYPE = b'\x09'  # SALE WITH CASHBACK TRANSACTION - MTIP05-USM Test 08 Scenario 01f
#TRANSACTION_TYPE = b'\x30' # BALANCE INQUIRY - MTIP06_10_01_15A, MTIP06_12_01_15A
ISBALANCEINQUIRY = TRANSACTION_TYPE == b'\x30'
AMOUNTFORINQUIRY = b'\x00\x00\x00\x00\x00\x00'

# EMV DISABLEMENT
EMV_ENABLED = 'y'

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

USE_QUICKCHIP_MODE = True
QUICKCHIP_ENABLED = [ (0xDF, 0xCC, 0x79), [0x01] ]
QUICKCHIP_DISABLED = [ (0xDF, 0xCC, 0x79), [0x00] ]
ISSUER_AUTH_DATA = [ (0x91), [0x37,0xDD,0x29,0x75,0xC2,0xB6,0x68,0x2D,0x00,0x12] ]

ACQUIRER_ID = [ (0xC2), [0x36, 0x35] ]

## CURRENCY / COUNTRY CODE
UK = b'\x08\x26'
US = b'\x08\x40'
## --- 0x9F14 - Command Incorrectly Formatted
CURRENCY_CODE = [(0x5F, 0x2A), US]
COUNTRY_CODE  = [(0x9F, 0x1A), US]

#AUTHRESPONSECODE = [ (0x8A), [0x30, 0x30] ]  # authorization response code of 00
#AUTHRESPONSECODE = [ (0x8A), [0x59, 0x31] ]  # authorization response code of Y1
#AUTHRESPONSECODE = [ (0x8A), [0x59, 0x32] ]  # authorization response code of Y2
AUTHRESPONSECODE = [ (0x8A), [0x5A, 0x33] ]  # authorization response code of Z3

# After an AAR (Application Authorisation Referral) or ARQC (Authorisation Request Cryptogram) where the acquirer
# is contacted, the decision is made with tag C0. If the acquirer cannot be contacted or a stand-in authorisation
# is detected, do not send this tag. By not sending the tag, default analysis is carried out.
#
# ‘C0’ must be sent in the next ‘Continue Transaction’ command, set as positive (0x01) to request a TC or negative (0x00) to request an AAC.
CONTINUE_REQUEST_AAC = [(0xC0), [0x00]]  # Online (00)
CONTINUE_REQUEST_TC = [(0xC0), [0x01]]  # Offline (Z3)

ISOFFLINE = AUTHRESPONSECODE[1] == [0x5A, 0x33]
IS_PIN_BYPASSED = False

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

## TRANSACTION AMOUNT
SMALL_AMOUNT = b'\x00\x00\x00\x00\x11\x50'
LARGE_AMOUNT = b'\x00\x00\x09\x99\x99\x99' 

### --- CHANGE AMOUNT VALUE HERE ---v
AMOUNT = b'\x00\x00\x00\x00\x00\x00' if ISBALANCEINQUIRY else SMALL_AMOUNT
#AMOUNT = LARGE_AMOUNT
AMTOTHER = b'\x00\x00\x00\x00\x00\x00'

APPLICATION_LABEL = ''

# PROCESSING
EMV_VERIFICATION = 0

# CONTACTLESS CARD WORKFLOWS
ENABLE_EMV_CONTACTLESS = True
AID_SELECTION_ENABLED = True

# VIPA VERSION_LBL
VIPA_VAS_VER = '6.8.2.17'
VIPA_VERSION = '6.8.2.11'

# VAS REPORTING: VIPA 6.8.2.17+
ENABLE_VAS_REPORTING = False

# APPLICATION SELECTION OPTION
APPLICATION_SELECTION_POS = False
APPLICATION_AID = ''
APPLICATION_LABEL = ''
APPLICATION_SELECTION = 0


# ---------------------------------------------------------------------------- #
# ONLINE PIN VSS DUPKT
#
host_id_vss = 0x02;
# Key Set Id - VSS SLOT (0 - PROD, 8 - DEV)
keyset_id_vss = 0x00
    
# ---------------------------------------------------------------------------- #
# ONLINE PIN IPP DUPKT

host_id_ipp = 0x05
# IPP KEY SLOT
keyset_id_ipp = 0x01
    
ISIPPKEY = True    
HOST_ID = host_id_ipp if ISIPPKEY else host_id_vss
KEYSET_ID = keyset_id_ipp if ISIPPKEY else keyset_id_vss
IPP_PIN_IS_ASCII = True

PINLEN_MIN = 4
PINLEN_MAX = 6
PIN_ATTEMPTS = 2

OnlineEncryptedPIN = ""
OnlinePinKSN = ""

ENABLE_MiFARE = False

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

# Terminal exception file for pan - ENSURE FILE IS UNIX LINE TERMINATED (EOL)
# PAN.TXT file is used as an exception file(blacklist) to specify primary account numbers. It is used at
# the terminal risk management stage and if a match is found in the exception file, bit 5 in byte1 of
# TVR is set indicating “card number appears on hotlist”.
# There must be a pan number on each line of file. There might be whitespaces around it. Pan should
# not contain any non-digit character and its length should be between 7-19.
def getFile(filename , local_fn):
    try:
        progress = partial(util.display_console_progress_bar, util.get_terminal_width())
        fops.getfile(conn, log, filename, local_fn, progress)
        return True
    except Exception:
        return False

def loadBlackList():
    fileName = "PAN.txt"
    if getFile(fileName, fileName):
      data = open(fileName, "rb").read()
      if len(data):
          return data.split()
    return ""

def isPanBlackListed(pan):
    BLACK_LIST = loadBlackList()
    if len(BLACK_LIST):
        for value in BLACK_LIST:
            # PAN FORMAT: ######aaaaaa####
            if value[0:6] == pan[0:6] and value[12:16] == pan[12:16]:
                return True
    return False

def vspIsEncrypted(tlv):
    vsp_tag_val = tlv.getTag((0xDF,0xDF,0x6F))
    if len(vsp_tag_val):
        vsp_tag_val = tlv.getTag((0xDF,0xDF,0x6F), TLVParser.CONVERT_INT)[0]
        if vsp_tag_val != 0:
            log.log('VSP Encryption detected, flag ', hex(vsp_tag_val), '!')
            return True
        else:
            log.log('VSP present, but transaction unencrypted!')
    else:
        log.logerr('VSP DFDF6F NOT present')
    return False

# Decrypts VSP - encrypted data
def vspDecrypt(tlv, tid):
    return False
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

def AbortTransaction():
  log.log('Abort Transaction')
  conn.send([0xD0, 0xFF, 0x00, 0x00])
  status, buf, uns = getAnswer()
  if status == 0x9000:
    log.logerr('Transaction aborted')

def ResetDevice(p2 = 0x01):
  # Send reset device
  # P1 - 0x00
  # perform soft-reset, clears all internal EMV collection data and returns Terminal ID,
  #  Serial Number and Application information
  conn.send([0xD0, 0x00, 0x00, p2])
  status, buf, uns = getAnswer()
  log.logerr('DEVICE RESET COMPLETED ----------')
  return buf


# Finalise the script, clear the screen
def performCleanup():
    # Clear screen
    conn.send([0xD2, 0x01, 0x01, 0x01])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer(True, False)


def getCVMResult(tlv):
    cvm_result = tlv.getTag((0x9F,0x34))[0]
    encrypted_pin = (cvm_result[0] & 0x0f)
    # Indicate CVM type
    switcher = {
        1: "PLAIN PIN BY ICC",
        2: "ONLINE PIN",
        4: "ENCRYPTED BY ICC",
        14: "SIGNATURE",
        15: "NO CVM PERFORMED"
    }
    cvm_value = switcher.get(encrypted_pin, "UNKNOWN CVM TYPE")
    return cvm_value


# Gets answer from the device, optionally ignoring unsolicited and stopping on errors
def getAnswer(ignoreUnsolicited = True, stopOnErrors = True):
    while True:
        status, buf, uns = conn.receive()
        if uns and ignoreUnsolicited:
            log.log('Unsolicited packet detected: ', TLVParser(buf))
            continue
        if (status != 0x9000 and status != 0x9F0D and status != 0x9F36 and 
            status != 0x9F22 and status != 0x9F25 and status != 0x9F28 and 
            status != 0x9F31 and status != 0x9F33 and status != 0x9F34 and 
            status != 0x9F35 and status != 0x9F41 and status != 0x9F42 and 
            status != 0x9F43
        ):
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

# ---------------------------------------------------------------------------- #
# PIN Workflow
# ---------------------------------------------------------------------------- #

def OnlinePinTransaction(tlv, tid, cardState, continue_tpl, bypassSecongGen=False):
    global TRANSACTION_TYPE, AMOUNT, PINLEN_MIN, PINLEN_MAX, PIN_ATTEMPTS
    global HOST_ID, KEYSET_ID
 
    # AXP QC 032 REQUIRES 2nd GENERATE AC to report TAGS 8A and 9F27
    if cardState == EMV_CARD_INSERTED and bypassSecongGen == False:    
      sendSecondGenAC(continue_tpl, tid)

    log.log('Online PIN TRANSACTION ------------------------------------------')

    # If SRED is enabled and pan_cache_timeout is specified in the [vipa] section of MAPP_VSD_SRED.CFG, the last cached PAN will be used for
    # PIN Block Formats that require PAN in case the PAN tag is not supplied.
    PANDATA = b'\x54\x13\x33\x00\x89\x00\x00\x39'
    #PANDATA = tlv.getTag(0x5A)
    log.log("PAN: ", hexlify(PANDATA).decode('ascii'))

    onlinepin_tag = [
         [(0xDF, 0xDF, 0x17), AMOUNT]           # transaction amount
        ,[(0xDF, 0xDF, 0x24), b'PLN']           # transaction currency
        ,[(0xDF, 0xDF, 0x1C), 0x02]             # transaction currency exponent
        ,[(0xDF, 0xDF, 0x1D), TRANSACTION_TYPE] # transaction type
        ,[(0xDF, 0xA2, 0x0E), 0x0F]             # pin entry timeout: default 30 seconds
        ,[(0xDF, 0xED, 0x04), PINLEN_MIN]       # min pin length 
        ,[(0xDF, 0xED, 0x05), PINLEN_MAX]       # max pin length
        #,[(0x5A), PANDATA]                     # PAN DATA
        # 20201119: JIRA TICKET VS-52542 as this option does not work
        # AXP QC 037 - ALLOW PIN BYPASS WITH <GREEN> BUTTON
        ,[(0xDF, 0xEC, 0x7D), b'\x01'],         # PIN entry type: pressing ENTER on PIN Entry screen (without any PIN digits) will return SW1SW2=9000 response with no data
        [(0xDF, 0xED, 0x08), b'\x00']           # PIN Block Format ISO
    ]
    onlinepin_tpl = (0xE0, onlinepin_tag)

    response = "declined"
    attempts = 0

    while response != "approved" and attempts < PIN_ATTEMPTS:
        # ONLINE PIN [DE, D6]
        conn.send([0xDE, 0xD6, HOST_ID, KEYSET_ID], onlinepin_tpl)
        status, buf, uns = getEMVAnswer() 
        if status != 0x9000:
            break
        pin_tlv = TLVParser(buf)

        # PIN bypass is allowed as per: AXP QC 037
        encryptedPIN = pin_tlv.getTag((0xDF,0xED,0x6C))
        if len(encryptedPIN):
            encryptedPIN = pin_tlv.getTag((0xDF,0xED,0x6C))[0].hex().upper()
            if len(encryptedPIN):
                ksn = pin_tlv.getTag((0xDF, 0xED, 0x03), TLVParser.CONVERT_HEX_STR)[0].upper()
                if len(ksn):
                    if HOST_ID == 0x05:
                      if IPP_PIN_IS_ASCII:
                        encryptedPIN = bytes.fromhex(encryptedPIN).decode('utf-8')
                        ksnStr = bytes.fromhex(ksn).decode('utf-8')
                      else:
                        ksnStr = ksn
                      ksn = "{:F>20}".format(ksnStr)
                
                    # this script doesn't process online
                    print("ONLINE PIN - Encrypted PIN/KSN", encryptedPIN, ksn)
                    break
                    displayMsg('Processing ...')
                    TC_TCLink.saveEMVData(tlv,0xE4)

                    # send to process online PIN entry
                    response = TC_TCLink.processPINTransaction(encryptedPIN, ksn)
                    log.log("PIN response: "+ response)
                    if response != "approved":
                        displayMsg('Invalid PIN', 3)
                        attempts += 1

                    TC_TCLink.SetProperties(args, log)

                    if response != "approved" and attempts >= args.pinattempts:
                        displayMsg('PIN try limit exceeded', 3)
        else:
            # force PIN bypass
            status = 0x9f41
            break

    # user pinbypass
    nextstep = -1
    if status == 0x9f41:
        nextstep = 2
        #processPinBypass()
        log.warning('PIN BYPASSED')
        
    if (cardState == EMV_CARD_INSERTED):       
        removeEMVCard()

    # transaction result
    if nextstep == -1:
        displayMsg(response.upper(), 3)

        # DISPLAY [D2, 01]
        conn.send([0xD2, 0x01, 0x01, 0x01])
        log.log("Online PIN transaction:", response)
        sleep(2)

    # DISPLAY [D2 01]
    conn.send([0xD2, 0x01, 0x01, 0x00])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer()

    return nextstep

def OnlinePinInTemplateE6(tlv, cardState, continue_tpl):

    global OnlineEncryptedPIN, OnlinePinKSN
    global HOST_ID, KEYSET_ID
    global IS_PIN_BYPASSED

    log.log('Online PIN: retrieving PINBLOCK ---------------------------------------------')
    log.log('HOST_ID=' + str(HOST_ID) + ', KEY_SLOT=' + str(KEYSET_ID))
    
    if IS_PIN_BYPASSED:
      log.warning('PIN BYPASS IN EFFECT...')
      return -1
    
    # DFED0D
    # Flags for the entry. The following bits are checked:
    # • Bit 0 = bypass KSN incrementation in case of DUKPT support
    # • Bit 4 = PIN confirmation request: PINblock is not returned, check Return code (DFDF30) for PIN confirmation result
    # • Bit 5 = use Flexi PIN entry method (see information on Flexi PIN entry below) - only VOS and VOS2 platforms
    # • Bit 6 = PIN already entered, only processing request
    # • Bit 7 = PIN collected, no further processing required
    retrieve_pinblock = b'\x40'
    #
    # ONLINE_PIN_PART_OF_EMV_TRANS=1 must be set in cardapp.cfg
    # 
    onlinepin_tag = [
         [(0xDF, 0xED, 0x0D), retrieve_pinblock]
    ]
    onlinepin_tpl = (0xE0, onlinepin_tag)

    # ONLINE PIN [DE, D6]
    conn.send([0xDE, 0xD6, HOST_ID, KEYSET_ID], onlinepin_tpl)
    status, buf, uns = getEMVAnswer() 
    if status != 0x9000:
        pin_tlv = TLVParser(buf)
        if pin_tlv.tagCount((0xDF, 0xDF, 0x30)):
            response = pin_tlv.getTag((0xDF, 0xDF, 0x30), TLVParser.CONVERT_HEX_STR)[0].upper()
            if len(response):
                log.logerr("PIN RETRIEVE RESPONSE=" + response)    
        return -1
    pin_tlv = TLVParser(buf)

    response = 'Declined'
    
    # obtain PIN Block: KSN and Encrypted data
    encryptedPINData = pin_tlv.getTag((0xDF,0xED,0x6C))
    if len(encryptedPINData):
      encryptedPINData = pin_tlv.getTag((0xDF,0xED,0x6C))[0].hex().upper()
      if len(encryptedPINData):
          ksn = pin_tlv.getTag((0xDF, 0xED, 0x03), TLVParser.CONVERT_HEX_STR)[0].upper()
          if len(ksn):
            # adjust KSN for IPP
            if HOST_ID == 0x05:
                if IPP_PIN_IS_ASCII:
                  encryptedPINData = bytes.fromhex(encryptedPINData).decode('utf-8')
                  ksnStr = bytes.fromhex(ksn).decode('utf-8')
                else:
                  ksnStr = ksn
                ksn = "{:F>20}".format(ksnStr)
            
            # store globals
            OnlineEncryptedPIN = encryptedPINData
            OnlinePinKSN = ksn
            
            log.warning("E6 Template - Encrypted PIN/KSN", OnlineEncryptedPIN, OnlinePinKSN)
            log.warning("HOST_ID =", HOST_ID, "<==> KEYSET_ID =", KEYSET_ID)
            #displayMsg('Processing ...')
            #response = 'Approved'
            #TC_TCLink.saveEMVData(tlv,0xE4)

            # send to process online PIN entry
            #response = TC_TCLink.processPINTransaction(encryptedPIN, ksn)
            #log.log("PIN response: "+ response)
            #if response != "approved":
            #    displayMsg('Invalid PIN', 3)
            #    return OnlinePinTransaction(tlv, tid, cardState, continue_tpl)

            #TC_TCLink.SetProperties(args, log)
    else:
      log.logerr("UNABLE TO RETRIEVE ONLINE PIN PAYLOAD")
      
    if (cardState == EMV_CARD_INSERTED):
        removeEMVCard()

    # transaction result
    displayMsg(response.upper(), 3)

    # DISPLAY [D2, 01]
    conn.send([0xD2, 0x01, 0x01, 0x01])
    log.log("Online PIN transaction:", response)
    sleep(2)

    # DISPLAY [D2 01]
    conn.send([0xD2, 0x01, 0x01, 0x00])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer()

    return -1

def performUserPINEntry():

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
                # ABORT [D0 FF]
                conn.send([0xD0, 0xFF, 0x00, 0x00])
                validKey = True

            if key == 'b' or key == 'B':
                log.logerr('bypassing')
                # VERIFY PIN [DE D5]
                conn.send([0xDE, 0xD5, 0xFF, 0x01])
                validKey = True

            if key == 'c' or key == 'C':
                log.logerr('cancelling')
                # VERIFY PIN [DE D5]
                conn.send([0xDE, 0xD5, 0x00, 0x00])
                validKey = True

            if validKey:
                status, buf, uns = getAnswer(stopOnErrors = False) # Wait for confirmation, then break to wait for response
                if status == 0x9000: 
                    break
                else: 
                    continue
            else:
                continue

        if conn.is_data_avail():
            break

# Ask for card removal and waits until card is removed
def removeEMVCard():
    # Display Remove card (with beeps)
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

# ---------------------------------------------------------------------------- #
# EMV Workflow
# ---------------------------------------------------------------------------- #

# Processes magstripe fallback - asks for swipe
def processMagstripeFallback(tid):

    # Cancel Contactless first
    cancelContactless()
                        
    log.log('Setting up MSR fallback...')
                        
    # Ask for removal and swipe 
    conn.send([0xD0, 0x60, 0x1D, 0x00])
    while True:
        status, buf, uns = getAnswer(False) # Get unsolicited
        if uns:
            tlv = TLVParser(buf)
            if EMVCardState(tlv) == EMV_CARD_INSERTED:
                tlv = removeEMVCard()
                break
            break
            
    log.log('Ready for MSR fallback processing')
    
    # Ask for swipe
    if MagstripeCardState(tlv) == EMV_CARD_REMOVED:
        #conn.send([0xD2, 0x01, 0x00, 0x01], '\x09Please Swipe Card')
        conn.send([0xD2, 0x01, 0x2B, 0x01])
        status, buf, uns = getAnswer()
        # Wait for swipe
        while True:
            status, buf, uns = getAnswer(False)
            if uns:
                tlv = TLVParser(buf)
                magState = MagstripeCardState(tlv)
                if magState == ERROR_UNKNOWN_CARD or magState == MAGSTRIPE_TRACKS_AVAILABLE:
                     break
            log.log('PROCESS MSR: ignoring unsolicited packet ', tlv)
            continue
            
    if MagstripeCardState(tlv) == MAGSTRIPE_TRACKS_AVAILABLE:
        log.logerr('Attempting to decrypt SWIPE...')
        vspDecrypt(tlv, tid)
    
    # cardholder name
    displayEncryptedTrack(tlv)
    
    # HMAC PAN
    displayHMACPAN(tlv)

    
    # We're done!
    return 5

def setFirstGenContinueTransaction():

    continue_tran_tag = [
        [(0x9F, 0x02), AMOUNT],         # Amount
        [(0x9F, 0x03), AMTOTHER],       # Amount, other
        CURRENCY_CODE,
        COUNTRY_CODE,
        ACQUIRER_ID,                    # TAG C2 acquirer id: ref. iccdata.dat
        [(0xDF, 0xA2, 0x18), [0x00]],   # Pin entry style
        AUTHRESPONSECODE,               # TAG 8A
        CONTINUE_REQUEST_AAC if (ISOFFLINE or ISBALANCEINQUIRY) else CONTINUE_REQUEST_TC,  # TAG C0 object decision: AAC=00, TC=01
        # quick chip as option for NO-PIN M/C Test Case MTIP-51.Test01.Scenario.01f
        QUICKCHIP_ENABLED if USE_QUICKCHIP_MODE else QUICKCHIP_DISABLED
    ]
      
    return (0xE0, continue_tran_tag)

def sendFirstGenAC(tlv, tid):
    global APPLICATION_LABEL, EMV_VERIFICATION
    global APPLICATION_SELECTION, APPLICATION_SELECTION_POS
    
    print('')

    # allow for decision on offline decline when issuing 1st GenAC (DNA)
    EMV_VERIFICATION = 0x01
    
    APPLICATION_AID   = ''
    APPLICATION_LABEL = ''
    panBlacklisted = False
    
    # TEMPLATE E2 - DECISION REQUIRED
    # Should the device require a decision to be made it will return this template. The template could
    # contain one or more copies of the same data object with different value fields.
    # Issuing a Continue Transaction [DE, D2] instruction with template E0 containing the data object to
    # be used makes the decision for the device.
    # Should this template contain a single data element, there is still a decision to be made. In the case of
    # an AID it is the card that requests customer confirmation; returning the AID in the next Continue
    # instruction confirms the selection of this application.
    if tlv.tagCount(0xE2):
        print('APPLICATION SELECTION REQUEST ===================>')
        EMV_VERIFICATION = 0x00
        appLabels = tlv.getTag(0x50)
        appAIDs = tlv.getTag((0x9F, 0x06))
        # LIST WITH SINGLE ITEM
        if tlv.tagCount(0x50) == 1 and tlv.tagCount((0x9F, 0x06)) == 1:
            APPLICATION_SELECTION = 0
        # set AID
        log.warning("APPLICATION SELECTED:", APPLICATION_SELECTION + 1)
        print('')
        APPLICATION_AID   = [(0x9F, 0x06), bytearray(appAIDs[APPLICATION_SELECTION])]
        APPLICATION_LABEL = [(0x50, ), bytearray(appLabels[APPLICATION_SELECTION])]

    pan = tlv.getTag(0x5A)
    if len(pan):
      panBlacklisted = isPanBlackListed(b2a_hex(pan[0]))
    continue_tran_tag = [
        [(0x9F, 0x02), AMOUNTFORINQUIRY if ISBALANCEINQUIRY else AMOUNT], # Amount
        [(0x9F, 0x03), AMTOTHER],                                         # Amount, other
        CURRENCY_CODE,                                                    # Currency code
        COUNTRY_CODE,                                                     # Country code
        ACQUIRER_ID,                                                      # TAG C2 acquirer id: ref. iccdata.dat
        #[ (0x89), [0x00] ],                                              # Host Authorisation Code)
        AUTHRESPONSECODE,                                                 # TAG 8A
        [ (0xDF, 0xA2, 0x18), [0x00] ],                                   # Pin entry style
        # note: this tag presence will cause DNA tests to fail - need to evaluate further when to include/exclude
        CONTINUE_REQUEST_TC if ISOFFLINE else CONTINUE_REQUEST_AAC,       # TAG C0 object decision: 00=AAC, 01=TC
        # quick chip as option for NO-PIN M/C Test Case MTIP-51.Test01.Scenario.01f
        QUICKCHIP_ENABLED if USE_QUICKCHIP_MODE else QUICKCHIP_DISABLED                                                
    ]
    # The terminal requests an ARQC in the 1st GENERATE AC Command.
    # The card returns an AAC to the 1st GENERATE AC Command. 
    # The terminal does not send a 2nd GENERATE AC Command
    if panBlacklisted:
        continue_tran_tag.append(CONTINUE_REQUEST_TC)
    
    if len(APPLICATION_AID) and len(APPLICATION_LABEL):
        continue_tran_tag.append(APPLICATION_AID)
        #continue_tran_tag.append(APPLICATION_LABEL)
    
    continue_tpl = (0xE0, continue_tran_tag)
    
    if APPLICATION_SELECTION_POS == False:
      message = str(appLabels[APPLICATION_SELECTION], 'iso8859-1')
      if len(message):
        displayMsg('* APPLICATION LABEL *\n\t' + message, 2)

    log.log("CONTINUE TRANSACTION: GenAC1 -----------------------------------------------------------------------------")

    # process 1st GenAC
    conn.send([0xDE, 0xD2, EMV_VERIFICATION, 0x00], continue_tpl)

    return continue_tpl
    
def sendSecondGenAC(tlv, tid):
    global IS_PIN_BYPASSED

    log.log("CONTINUE TRANSACTION: GenAC2 -----------------------------------------------------------------------------")
    
    continue_trans_tag =[
      [(0x9F, 0x02), AMOUNTFORINQUIRY if ISBALANCEINQUIRY else AMOUNT],   # Amount
      [(0x9F, 0x03), AMTOTHER],                                           # Amount, other
      CURRENCY_CODE,
      COUNTRY_CODE,
      ACQUIRER_ID,
      AUTHRESPONSECODE,
      [ (0xDF,0xA2,0x18), [0x00] ],                                       # PIN Entry style
      [ (0xDF,0xA3,0x07), [0x03,0xE8] ],
      CONTINUE_REQUEST_TC if ISOFFLINE else CONTINUE_REQUEST_AAC,         # TAG C0 object decision:
                                                                          # 00=AAC, 01=TC
      #ISSUER_AUTH_DATA,                                                   # Authentication Data
      # quick chip as option for NO-PIN M/C Test Case MTIP-51.Test01.Scenario.01f
      QUICKCHIP_ENABLED if USE_QUICKCHIP_MODE else QUICKCHIP_DISABLED
    ]
    
    if IS_PIN_BYPASSED:
      continue_trans_tag.append([(0xDF, 0xA2, 0x0A), [0x01]])
      
    continue2_tpl = (0xE0, continue_trans_tag )

    # If we get here, we received Online Request. Continue with positive response. 
    conn.send([0xDE, 0xD2, 0x00, 0x00], continue2_tpl)

    status, buf, uns = getEMVAnswer(True) # Ignore unsolicited automatically here
    if status != 0x9000 and status != 0x9f22:
        log.logerr('Online Request has failed', hex(status))
        return -1
    
    return TLVParser(buf)
 

def applicationSelection(tlv):
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
              AbortTransaction()
              return -1
          print(' Invalid selection, please pick valid number! ')
      if conn.is_data_avail():
          status, buf, uns = getEMVAnswer()
          if status != 0x9000:
              log.logerr('Transaction terminated with status ', hex(status))
              return -1
          break
  # set application selection based on choice
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
      return 0

  return 1


def applicationSelectionAutomatic(tlv):
  if tlv.tagCount(0x50):
    appLabels = tlv.getTag(0x50)
    appAIDs = tlv.getTag((0x9F, 0x06))
    log.log('We have ', len(appLabels), ' applications')
    if len(appLabels) != len(appAIDs):
        log.logerr('Invalid response: AID count ', len(appAIDs), ' differs from Labels count ', len(appLabels))
        exit(-1)
    # auto select first item
    sel = 0
    app_sel_tags = [
        [(0x50), bytearray(appLabels[sel])],
        [(0x9F, 0x06), bytearray(appAIDs[sel])]
    ]
    app_sel_templ = ( 0xE0, app_sel_tags )
    conn.send([0xDE, 0xD2, 0x00, 0x00], app_sel_templ)
    log.warning('APPLICATION SELECTED:', appLabels[sel])
    return 0


def applicationSelectionDefault(tlv):
  APPLICATION_SELECTION = ''
  if tlv.tagCount(0xE2):
    # This is app selection stuff
    appLabels = tlv.getTag(0x50)
    appAIDs = tlv.getTag((0x9F, 0x06))
    APPLICATION_SELECTION = [(0x50, ), bytearray(appLabels[0])], [(0x9F, 0x06), bytearray(appAIDs[0])]
  return APPLICATION_SELECTION


# EMV transaction
def processEMV(tid):

    global AMOUNT, DATE, TIME, OFFLINERESPONSE, AMTOTHER, SIGN_RECEIPT, EMV_VERIFICATION, IS_PIN_BYPASSED
    global APPLICATION_SELECTION, APPLICATION_SELECTION_POS
    
    transaction_counter = b'\x00\x01'

    #app_sel_tags = [
    #    [(0x9F, 0x06), bytearray('a000000003101001')],
    #    [(0x50), bytearray('CREDIT')],
    #    [(0x87), b'\x01'],
    #    [(0x9F, 0x06), bytearray('a000000003101002')],
    #    [(0x50), bytearray('DEBIT')],
    #    [(0x87), b'\x01']
    #]
    
    # AID Selection Mechanism
    APPLICATION_SELECTION = -1
    
    start_trans_tag = [
         [(0x9C), TRANSACTION_TYPE],                                              # transaction type
         [(0x9F, 0x02), AMOUNTFORINQUIRY if ISBALANCEINQUIRY else AMOUNT],        # Amount
         [(0x9F, 0x03), AMTOTHER],
         [(0x9A), DATE],                                                          # date
         [(0x9F,0x21), TIME],                                                     # time
         CURRENCY_CODE,                                                           # currency code
         COUNTRY_CODE,                                                            # Country code
         [(0x9F,0x41), transaction_counter ],                                     # transaction counter
         [(0xDF,0xA2,0x18), b'\x00'],                                             # pin entry style
         #[(0xDF,0xA2,0x14), b'\x01'],                                            # Suppress Display
         #[(0xDF, 0xDF, 0x0D), b'\x02'],                                          # Don't force transaction online
         ### ENSURE THIS IS ALWAYS THE LAST ENTRY
         [(0xDF, 0xA2, 0x04), b'\x00' if APPLICATION_SELECTION_POS else b'\x01']  # External Application Selection (POS)
    ]
    start_templ = ( 0xE0, start_trans_tag )
    
    log.log("START TRANSACTION: ***************************************************************************************")
    
    # START TRANSACTION [DE D1]
    conn.send([0xDE, 0xD1, 0x00, 0x00], start_templ)

    # technical fallback requirement
    unsupported_card_index = 1

    while True:
    
        #sleep(1)
        #conn.send([0xD0, 0xFF, 0x00, 0x00])
        status, buf, uns = getEMVAnswer()
        if status != 0x9000:
            if status == 0x9F28:
                unsupported_card_index = unsupported_card_index + 1
                if unsupported_card_index == 2:
                  # empty candidate list
                  log.warning("EMV FALLBACK TYPE: MSR --------------------------------------------------------")

                  return processMagstripeFallback(tid)
                else:
                  displayMsg("\tUNSUPPORTED CARD\tREINSERT", 2)
                  removeEMVCard()
                  # START TRANSACTION [DE D1]
                  conn.send([0xDE, 0xD1, 0x00, 0x00], start_templ)
                  continue
            else:
                log.logerr('Transaction terminated with status ', hex(status))
                return -1
        if uns and status == 0x9000:
            tlv = TLVParser(buf)
            if tlv.tagCount(0xE6) != 0:
                log.log('Multi application card! - continue processing...')
                continue
            else:
                log.log('PROCESS EMV[1]: ignoring unsolicited packet', tlv)
                continue
        else:
        
            tlv = TLVParser(buf)
        
            # APPLICATION SELECTION
            if tlv.tagCount(0xE2):
              if tlv.tagCount(0x50) > 1 and tlv.tagCount((0x9F, 0x06)) > 1:
                  if APPLICATION_SELECTION_POS == True:
                    # has operator made a choice already?
                    if APPLICATION_SELECTION != -1:
                      log.warning('POS DECISION MADE =============================================================')
                      break
                    log.warning('POS DECISION REQUIRED =============================================================')
                    AbortTransaction()
                    APPLICATION_SELECTION = TC_TransactionHelper.ApplicationSelection(conn)
                    log.log("USER SELECTED:", APPLICATION_SELECTION)
                    if APPLICATION_SELECTION == -1:
                      return -1
                    #aidSelection = applicationSelection(tlv)
                    #aidSelection = applicationSelectionAutomatic(tlv)
                    #if aidSelection == 0:
                    #  continue
                    
                    #ResetDevice(0x00)
                    
                    # change app selection request
                    #start_trans_tag.remove(start_trans_tag[-1])
                    #start_trans_tag.append([(0xDF,0xA2,0x04), b'\x01'])
                    
                    # START TRANSACTION [DE D1]
                    conn.send([0xDE, 0xD1, 0x00, 0x00], start_templ)
    
                  continue
                  
            break

    #Let's check VSP
    tlv = TLVParser(buf)
    vspDecrypt(tlv, tid)

    # ENCRYPTED TRACK DATA
    displayEncryptedTrack(tlv)

    #TC_TCLink.saveCardData(tlv)
    #print(">> before continue: ", str(tlv))

    # 1st Generation AC
    continue_tpl = sendFirstGenAC(tlv, tid)
    sleep(5)

    # Template E6 requests for PIN, so allow Template E4 to just submit the transaction (without collecting PIN again)
    hasPINEntry = False
    pinTryCounter = 0x00
    
    while True:
        status, buf, uns = getEMVAnswer()
        if status != 0x9000:
            log.logerr('Transaction terminated with status ', hex(status))
            # Terminal declines when a card replies with a TC (Approve) in response to an ARQC (go online) request in 1st GenAC (DNA)
            if EMV_VERIFICATION == 0x00:
                displayMsg("DECLINED: OFFLINE", 2) 
            return -1
        
        tlv = TLVParser(buf)
        
        if uns and status == 0x9000:
            #print(tlv)
            if tlv.tagCount(0xE6):
                message = tlv.getTag((0xC4))
                if (len(message)):
                    message = str(message[0], 'iso8859-1')
                    log.log(message)
                pinTryCounter = tlv.getTag((0xC5))[0]   
                performUserPINEntry()
                hasPINEntry = True
                continue
            else:
                if buf[0][0] == 0xe6:
                  log.log('E6 PAYLOAD _:', bytes(buf[0]))
                  tagC3Value = TC_TransactionHelper.getValue('c3', hexlify(buf[0]).decode('ascii'))
                  log.log('TAG C3 VALUE:', tagC3Value)
                  if tagC3Value == '0e':
                    IS_PIN_BYPASSED = True
                    log.warning('OPERATOR SELECTED PINBYPASS')
                else:
                  log.log('PROCESS EMV[2]: ignoring unsolicited packet ', tlv)
                continue
        else:
                    
            if tlv.tagCount(0xE3):
                log.log("Transaction approved offline")
                return 1
                
            if tlv.tagCount(0xE4):
            
                # CardSource
                TC_TransactionHelper.reportCardSource(tlv, log)

                # Terminal Capabilites
                appLabel = TC_TransactionHelper.reportTerminalCapabilities(tlv, log)
                if len(appLabel):
                  displayMsg('\t*** APPLICATION ***\t' + appLabel.decode('iso8859-1'), 3)

                # HMAC PAN
                displayHMACPAN(tlv)
                
                cvm_value = getCVMResult(tlv)
                # NOT AN EROR, JUST EASIER TO FIND IN THE TERMINAL OUTPUT
                log.logerr('CVM REQUESTED ______:', cvm_value)
                print('')
                
                # TVR Status
                checkTVRStatus(tlv)
                    
                if cvm_value == "ONLINE PIN" or cvm_value == "ENCRYPTED BY ICC":
                    if hasPINEntry == True:
                        # expect Template E6 already collected PIN: retrieve PIN KSN/ENCRYPTED DATA
                        return OnlinePinInTemplateE6(tlv, EMV_CARD_INSERTED, continue_tpl)
                    # request PIN from user
                    return OnlinePinTransaction(tlv, tid, EMV_CARD_INSERTED, continue_tpl)
                
                # check for OFFLINE PIN ENTRY: KSN/ENCRYPTED DATA PAIR not to be extracted since PIN is OFFLINE verified
                if "ENCRYPTED" in cvm_value or "PLAIN PIN" in cvm_value:
                    hasPINEntry = False

            if tlv.tagCount(0xE5):
                log.log("Transaction declined offline")
                # encrypted track
                displayEncryptedTrack(tlv)
                # TVR status
                checkTVRStatus(tlv)
                return 2
                
            break

    # 2nd Generation AC
    tlv = sendSecondGenAC(tlv, tid)
    
    if tlv == -1:
      return -1
 
    if tlv.tagCount(0xE3):
        log.log("Transaction approved")
        displayMsg("Approved", 3)
        return 1
    elif tlv.tagCount(0xE4):
       # CardSource
       TC_TransactionHelper.reportCardSource(tlv, log)
       # Terminal Capabilites
       appLabel = TC_TransactionHelper.reportTerminalCapabilities(tlv, log)
       if len(appLabel):
          displayMsg('\t*** APPLICATION ***\t' + appLabel.decode('iso8859-1'), 3)

       # HMAC PAN
       displayHMACPAN(tlv)
        
       cvm_value = getCVMResult(tlv)
       # NOT AN EROR, JUST EASIER TO FIND IN THE TERMINAL OUTPUT
       log.logerr('CVM REQUESTED ______:', cvm_value)
       print('')
        
       # TVR Status
       checkTVRStatus(tlv)
       #
    elif tlv.tagCount(0xE5):
        log.logerr('TRANSACTION DECLINED OFFLINE')

        # Check for Contact EMV Capture
        # print(">>> EMV Data 3 ff7f", tlv.tagCount((0xFF,0x7F)))

        # encrypted track
        displayEncryptedTrack(tlv)
        
        if hasPINEntry == True:
            # expect Template E6 already collected PIN: retrieve PIN KSN/ENCRYPTED DATA
            if len(OnlineEncryptedPIN) == 0 or len(OnlinePinKSN) == 0:
                # save EMV Tags
                #TC_TCLink.saveEMVData(tlv, 0xE5)
                OnlinePinInTemplateE6(tlv, EMV_CARD_INSERTED, continue_tpl)
            # save continue tpl in case of PIN retry
            OnlinePinContinueTPL = continue_tpl

        #TC_TCLink.saveCardData(tlv)

        return 6 if hasPINEntry else 2
        
    return 3

def displayMsg(message, pause = 0):
    # DISPLAY [D2, 01]
    conn.send([0xD2, 0x01, 0x00, 0x01], '\x0D\x09'+message)
    status, buf, uns = getAnswer()
    if pause > 0:
        sleep(pause)


def displayCustomMsg(message, pause = 0):
    # DISPLAY [D2, 01]
    conn.send([0xD2, 0x01, message, 0x01])
    status, buf, uns = getAnswer()
    if pause > 0:
        sleep(pause)


def displayEncryptedTrack(tlv):

  # CARDHOLDER NAME - VIPA 6.8.2.17 or above
  if tlv.tagCount((0x5F, 0x20)):
    cardholderName = tlv.getTag((0x5F, 0x20))[0]
    if len(cardholderName):
      log.warning('CARDHOLDER NAME: \"' + str(cardholderName, 'iso8859-1') + '\"')

  if tlv.tagCount((0xFF, 0x7F)):
    sRED = tlv.getTag((0xFF, 0x7F), TLVParser.CONVERT_HEX_STR)
    for i in sRED:
      log.log(i)
    sRED = tlv.getTag((0xFF, 0x7F), TLVParser.CONVERT_HEX_STR)[0].upper()
    if len(sRED):
      log.log("SRED DATA: ", sRED)
      
      ksn  = ''
      iv   = ''
      vipa = ''
      
      # TAG DFDF11
      ksnIndex = sRED.find('DFDF11')
      if ksnIndex != -1:
        dataLen = int(sRED[ksnIndex+6:ksnIndex+8], 16) * 2
        ksn = sRED[ksnIndex+8:ksnIndex+8+dataLen]
        if len(ksn):
          log.log('KSN ______ : ' + ksn)
          log.warning('BDK KEY ID :', ksn[4:10])
          log.warning('BDK TRSM ID:', ksn[10:15])
          
      # TAG DFDF12
      ivIndex = sRED.find('DFDF12')
      if ivIndex != -1:
        dataLen = int(sRED[ivIndex+6:ivIndex+8], 16) * 2
        iv = sRED[ivIndex+8:ivIndex+8+dataLen]
        if len(iv):
          log.log('IV: ' + iv)
      
      # TAG DFDF10
      encryptedTrackIndex = sRED.find('DFDF10')
      if encryptedTrackIndex != -1:
        #log.log("IDX=" + sRED[encryptedTrackIndex+6:encryptedTrackIndex+8])
        #temp = sRED[encryptedTrackIndex+6:encryptedTrackIndex+8]
        #log.log("LENGTH=" + temp)
        dataLen = int(sRED[encryptedTrackIndex+6:encryptedTrackIndex+8], 16) * 2
        encryptedData = sRED[encryptedTrackIndex+8:encryptedTrackIndex+8+dataLen]
        if len(encryptedData):
          vipa = encryptedData
          log.logerr("ENCRYPTED TRACK LENGTH=" + str(dataLen))
          log.log('DATA: ' + encryptedData)
          
        # TVP|ksn:|iv:|vipa:|
        if len(ksn) and len(iv) and len(vipa):
          tclinkStr = 'TVP|ksn:' + ksn + '|iv:' + iv + '|vipa:' + vipa 
          log.logerr(tclinkStr)
          pyperclip.copy(tclinkStr)
          
        encryptionStatusIndex = sRED.find('DFDB0F')
        if encryptionStatusIndex != -1:
          dataLen = int(sRED[encryptionStatusIndex+6:encryptionStatusIndex+8], 16) * 2
          encryptionStatus = sRED[encryptionStatusIndex+8:encryptionStatusIndex+8+dataLen]
          if len(encryptionStatus):
            log.log("ENCRYTION STATUS: " + encryptionStatus)


def displayHMACPAN(tlv):
  sRedTag = tlv.tagCount((0xFF, 0x7C))
  if sRedTag > 0:
    sRED = tlv.getTag((0xFF, 0x7C), TLVParser.CONVERT_HEX_STR)[0].upper()
    # TAG DF837F
    panIndex = sRED.find('DF837F')
    if panIndex != -1:
      dataLen = int(sRED[panIndex+6:panIndex+8], 16) * 2
      panData = sRED[panIndex+8:panIndex+8+dataLen]
      if len(panData):
        log.warning("HMAC PAN TOKEN ______:", panData)
    else:
      log.warning("HMAC PAN TOKEN ______: TAG NOT FOUND")
  else:
    log.warning("HMAC PAN TOKEN ______: NOT REPORTED")


# ---------------------------------------------------------------------------- #
# Contactless Workflow
# ---------------------------------------------------------------------------- #

def Tags2Array(tags):
  tlvp = TLVPrepare()
  arr = tlvp.prepare_packet_from_tags(tags)
  del arr[0]
  return arr


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
def startContactless(preferredAID=''):
    global AMOUNT, AMTOTHER, DATE, TIME, ENABLE_VAS_REPORTING
    
    #vas = "{\"Preload_Configuration\":{\"Configuration_version\":\"1.0\",\"Terminal\":{\"Terminal_Capabilities\":{\"Capabilities\":\"Payment|VAS\"},\"PollTech\":\"AB\",\"PollTime\":15000,\"Source_List\":[{\"Source\":\"ApplePay\"},{\"Source\":\"AndroidPay\"}]}}}"
    vas = '{"Preload_Configuration":{"Configuration_version":"1.0","Terminal":{"Terminal_Capabilities":{"Capabilities":"Payment|VAS"},"PollTech":"AB","PollTime":15000,"Source_List":[{"Source":"ApplePay"},{"Source":"AndroidPay"}]}}}'

    # Start Contactless transaction
    start_ctls_tag = [
        [(0x9C), TRANSACTION_TYPE],     # transaction type
        [(0x9F, 0x02), AMOUNT],         # amount
        [(0x9F, 0x03), AMTOTHER],       # cashback
        [(0x9A), DATE],                 # system date
        [(0x9F, 0x21), TIME],           # system time
        #[(0x9F, 0x41), b'\x00\x01'],   # sequence counter
        #[(0xDF, 0xA2,0x04), b'\x01'],  # Application selection using PINPad
        #[(0xDF, 0xDF, 0x0D), b'\x01'], # Force transaction online
        CURRENCY_CODE,                  # currency code
        COUNTRY_CODE,                   # country code
        #AUTHRESPONSECODE,
        # quick chip as option for NO-PIN M/C Test Case MTIP-51.Test01.Scenario.01f
        QUICKCHIP_ENABLED if USE_QUICKCHIP_MODE else QUICKCHIP_DISABLED
    ]

    # Sale / Purchase with cashback not allowed here
    if TRANSACTION_TYPE != b'\x09':
        start_ctls_tag.append([(0x9C), TRANSACTION_TYPE])
        
    if len(preferredAID):
        # Preferred Application selected
        start_ctls_tag.append(preferredAID)
    # The terminal has to select AID based on Application Priority Indicator (EMV rules).
    # The reader performs the automatic selection according to the application priority indexes found in the device PPSE.
    # This allows for automatic selection (i.e. "single tap"). 
    elif AID_SELECTION_ENABLED:
        # Application Identifier Terminal (AID)
        start_ctls_tag.append([(0x9F, 0x06), b'\x00\x01'])
    
    # VAS Transactions VIPA 6.8.2.17+
    if ENABLE_VAS_REPORTING:
      start_ctls_tag.append([(0xDF, 0xB5, 0x01), vas.encode()])
    
    start_ctls_templ = (0xE0, start_ctls_tag)

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
    #P1 = 0x03 if ENABLE_MiFARE else 0x01
    P1 = 0x21 if ENABLE_VAS_REPORTING else 0x01
    conn.send([0xC0, 0xA0, P1, 0x00], start_ctls_templ)

    log.log('Starting Contactless transaction')


# From a list of AIDS, a selection needs to be made to process Contactless workflows - a second tap is required
def processCtlsAIDList(tlv):
    # BF0C Tag Listing AIDS
    if tlv.tagCount(0xA5):
        fci_value = tlv.getTag((0xA5))[0]

        value = hexlify(fci_value).decode('ascii')
        # log.log("DATA:" + value )

        tlvp = TLVPrepare()
        # even number of bytes
        value += '9000'
        buf = unhexlify(value)
        tlv_tags = tlvp.parse_received_data(buf)
        tags = TLVParser(tlv_tags)

        aidList = []
        lblList = []

        for item in tags:
            value = hexlify(item[1]).decode('ascii')
            # log.log(value)
            # 4f: AID
            aid = TC_TransactionHelper.getValue('4f', value)
            # log.log("AID:" + aid)
            aidList.append(aid)
            # 50: LABEL - OFFSET = 4F+HH+len(aid)
            label = TC_TransactionHelper.getValue('50', value[len(aid) + 4 :])
            label = bytes.fromhex(label)
            label = label.decode('ascii')
            # log.log("LABEL:" + label)
            lblList.append(label)

        # When 9f06 is two bytes long and there is only one AID on the list,
        # it will be selected automatically
        if len(aidList) <= 1:
            return ''

        log.log('We have ', len(lblList), ' applications')

        if len(lblList) != len(aidList):
            log.logerr('Invalid response: AID count ', len(aidList), ' differs from Labels count ', len(lblList))
            exit(-1)

        # TODO: multi-message not allowed
        # sending choice to terminal in ASCII formatted string
        # message = ''
        # for i in range(len(aidList)):
        #    message += "".join("{0:x}".format(ord(c)) for c in lblList[i])
        #    message += '0a'

        # TEST MESSAGE
        # message = '5061676f42414e434f4d41540a4d61657374726f0a'
        # slen =  len(message) // 2
        # length = hex( slen )
        # choice = requestChoice( message, length[2:] )

        # Console workflow
        for i in range(len(aidList)):
            log.log('App', i + 1, ': ' + aidList[i] + ' - [' + lblList[i] + ']')
        sel = -1
        log.log('Select App: ')

        while True:
            # Note: The below will work for up to 9 apps...
            if kbhit():
                try:
                    sel = ord(getch())
                except:
                    print('invalid key!')
                # TC_transtest_all_autoselect_EMV.log.log('key press ', sel)
                if sel > 0x30 and sel <= 0x30 + len(lblList):
                    sel -= 0x30  # to number (0 .. x)
                    break
                elif sel == 27:
                    # ABORT [D0 FF]
                    return AbortTransaction()

                print(' Invalid selection, please pick valid number! ')

            if conn.is_data_avail():
                status, buf, uns = getEMVAnswer()
                if status != 0x9000:
                    log.logerr('Transaction terminated with status ', hex(status))
                    return -1
                break

        # user made a selection
        if sel >= 0:
            sel = sel - 1
            log.log('Selected ', sel)
            PREFERRED_AID = [(0x9F, 0x06), bytes.fromhex(aidList[sel])]
            return PREFERRED_AID


def processCtlsAIDListAutomatic(tlv):
    # BF0C Tag Listing AIDS
    print('')
    print('APPLICATION SELECTION REQUEST ================>')
    if tlv.tagCount(0xA5):
        fci_value = tlv.getTag((0xA5))[0]

        value = hexlify(fci_value).decode('ascii')
        # log.log("DATA:" + value )

        tlvp = TLVPrepare()
        # even number of bytes
        value += '9000'
        buf = unhexlify(value)
        tlv_tags = tlvp.parse_received_data(buf)
        tags = TLVParser(tlv_tags)

        aidList = []
        lblList = []

        for item in tags:
            value = hexlify(item[1]).decode('ascii')
            # log.log(value)
            # 4f: AID
            aid = TC_TransactionHelper.getValue('4f', value)
            # log.log("AID:" + aid)
            aidList.append(aid)
            # 50: LABEL - OFFSET = 4F+HH+len(aid)
            label = TC_TransactionHelper.getValue('50', value[len(aid) + 4 :])
            label = bytes.fromhex(label)
            label = label.decode('ascii')
            # log.log("LABEL:" + label)
            lblList.append(label)

        # When 9f06 is two bytes long and there is only one AID on the list,
        # it will be selected automatically
        if len(aidList) <= 1:
            return ''

        # user made a selection
        sel = 1
        if sel >= 0:
            sel = sel - 1
            log.warning('APPLICATION SELECTED:', aidList[sel])
            PREFERRED_AID = [(0x9F, 0x06), bytes.fromhex(aidList[sel])]
            return PREFERRED_AID


# Processes contactless continue
#
# Terminal displays "NOT AUTHORISED", because transaction was declined from host - 
# ("Continue Contactless Transaction" was sent with
#  TAG C0 = 00 (declined)).
# Transaction was declined, because POS requested it, after that terminal displayed "Approved", 
# because POS sent Display Command with text "Approved".
#
def continueContactless():

    log.log("CONTINUE CLESS-TRANSACTION: GenAC2 -----------------------------------------------------------------------------")

    #Create localtag for transaction
    continue_ctls_tag = [
        ACQUIRER_ID,
        # CO
        # Host Decision – Mandatory:
        # • 00 – Declined
        # • 01 – Approved
        # • 02 – Failed to connect
        #CONTINUE_REQUEST_AAC,                           # Host Decision: 00 = Declined
        CONTINUE_REQUEST_TC,                            # Host Decision: 01 = Approved
        AUTHRESPONSECODE
    ]
    
    # MIFARE IMPLEMENTATION
    if ENABLE_MiFARE:
    # MiFare Tags
      innerMiFareWriteTags = [
        [(0xDF,0xA5, 0x01), b'\x03'],                     # Command code: 03 = W(rite)
        [(0xDF,0xA5, 0x02), b'\x01'],                     # Command Id
        [(0xDF,0xC0, 0x5B), b'\x01'],                     # Authentication key type (0/1)
        [(0xDF,0xC0, 0x5C), b'\xFF\xFF\xFF\xFF\xFF\xFF'], # Authentication key: 6 bytes
        [(0xDF,0xC0, 0x5D), b'\x04'],                     # Starting block
        [(0xDF,0xC0, 0x5E), b'\x03'],                     # Block count
        [(0xDF,0xC0, 0x5F), b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F']
      ]
      innerMiFareReadTags = [
        [(0xDF,0xA5, 0x01), b'\x02'],                     # Command code: 02 = R(ead)
        [(0xDF,0xA5, 0x02), b'\x01'],                     # Command Id
        [(0xDF,0xC0, 0x5B), b'\x01'],                     # Authentication key type (0/1)
        [(0xDF,0xC0, 0x5C), b'\xFF\xFF\xFF\xFF\xFF\xFF'], # Authentication key: 6 bytes
        [(0xDF,0xC0, 0x5D), b'\x04'],                     # Starting block
        [(0xDF,0xC0, 0x5E), b'\x03']                      # Block count
      ]
      continue_ctls_tag.append([(0xDF, 0xC0, 0x30), Tags2Array(innerMiFareWriteTags)])
      continue_ctls_tag.append([(0xDF, 0xC0, 0x30), Tags2Array(innerMiFareReadTags)])

    continue_ctls_templ = ( 0xE0, continue_ctls_tag )
    
    # continue transaction
    conn.send([0xC0, 0xA1, 0x00, 0x00], continue_ctls_templ)
    status, buf, uns = getAnswer()
    log.log('Waiting for Contactless Continue')
    
    while True:
        status, buf, uns = getAnswer(False)
        if uns:
            break
        log.logerr('Unexpected packet detected, ', TLVParser(buf))


def cancelContactless():
    log.logerr("Stopping Contactless transaction")
    # CANCEL CONTACTLESS TRANSACTION [C0 C0]
    conn.send([0xC0, 0xC0, 0x00, 0x00])
    status, buf, uns = getAnswer()
    status, buf, uns = getAnswer(False) # Ignore unsolicited as the answer WILL BE unsolicited... 


# Prompts for card insertion
def promptForCard():
    #Prompt for card
    conn.send([0xD2, 0x01, 0x0D, 0x01])
    status, buf, uns = getAnswer()


def checkTVRStatus(tlv):
    found = False
    tvr = tlv.getTag((0x95))
    if len(tvr):
      found = True
      print('')
      log.attention('TVR (TAG 95):', hexlify(tvr[0]))
      index = 1
      for x in tvr[0]:
        # change x to X for upper: "0x%0*X"
        log.log('BYTE[' + str(index) + ']: ' + "0x%0*x" % (2, x))
        #log.log('BYTE[' + str(index) + ']: ' + "{0:#0{1}x}".format(x, 4))
        #log.log('BINARY :', bin(x).replace("0b", ""))
        for n in range(8, -1, -1):
          bit = (x & (1 << n)) >> n
          if bit == 1:
            #log.log('   BIT :', n + 1)
            TC_TransactionHelper.showTVRFailures(log, index, n + 1)
        index = index + 1
      print('')
    return found


def vipaVersion(tlv):
  vipa = tlv.getTag((0xDF, 0x81, 0x06))
  if len(vipa):
    index = 0
    for iversion in vipa:
      vipaLbl = str(iversion, 'iso8859-1')
      if len(vipaLbl) and vipaLbl == 'VIPA':
        vipaVer = tlv.getTag((0xDF, 0x81, 0x07))
        VIPA_VERSION = str(vipaVer[index], 'iso8859-1')
        return VIPA_VERSION
      index = index + 1
  return 'UNKNOWN'


# ---------------------------------------------------------------------------- #
# Main function
# ---------------------------------------------------------------------------- #
def processTransaction(args):

    global DATE, TIME, EMV_ENABLED, AMOUNT, VIPA_VERSION, VIPA_VAS_VER, ENABLE_VAS_REPORTING
    
    # TIMESTAMP
    now = datetime.datetime.now()
    DATE = bcd(now.year % 100) + bcd(now.month) + bcd(now.day)
    #DATE = b'\x19\x01\x01'
    TIME = bcd(now.hour % 100) + bcd(now.minute) + bcd(now.second)
    
    if args.amount != 0:
      AMOUNT = bcd(args.amount + args.amtother, 6)
      #log.log('TRANSACTION AMOUNT: $', AMOUNT)
      
    req_unsolicited = conn.connect()
    if req_unsolicited:
        #Receive unsolicited
        log.log('Waiting for unsolicited')
        #status, buf, uns = getAnswer(False)
        #log.log('Unsolicited', TLVParser(buf) )

    AbortTransaction()
    
    # Send reset device
    buf = ResetDevice()
    
    # Template EE [OS Version]
    tlv = TLVParser(buf)
   
    VIPA_VERSION = vipaVersion(tlv)
    log.warning('VIPA VERSION: ', VIPA_VERSION)
    if VIPA_VERSION >= VIPA_VAS_VER:
      ENABLE_VAS_REPORTING = True
    log.log('VAS ENABLED : ', ENABLE_VAS_REPORTING)
 
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
    ### ------------------------------------------------------------------------------------------
    # Clarifications added to VIPA manual in version 6.8.2.11.
    # When the ICC notification is disabled (i.e. P1 bit 7) then VIPA will not be able to send 
    # unsolicited response for the changes in card status. However for MSR transaction in UX30x, # POS can simply disable ATR notification (i.e. P1 bit 1) and VIPA will notify the POS 
    # regarding the card insertion and POS can fallback to magstripe.
    ### ------------------------------------------------------------------------------------------
    # P1 - REQUESTS
    # Bit 7 - Disables ICC notifications   
    # Bit 6 - Disables magnetic reader notifications
    # Bit 5 - Enables magnetic track status reporting (tag DFDF6E)
    # Bit 4 - Requests the Track 3 data in the response (tag 5F23)
    # Bit 3 - Requests the Track 2 data in the response (tag 5F22)
    # Bit 2 - Requests the Cardholder name and Track 1 data in the response (tag 5F20 and tag 5F21)
    # Bit 1 - Requests the ATR in the response (tag 63)
    # Bit 0 - Sets the device to report changes in card status
    #
    #P1 = 0x43
    #P1 = 0x7F
    P1 = 0x3F
    # P2 - Monitor card and keyboard status
    # 00 - stop reporting key presses
    # Bit 1 - report function key presses
    # Bit 0 - report enter, cancel and clear key presses
    ## ICC + MSR
    P2 = 0x03
    #
    conn.send([0xD0, 0x60, P1, P2])
    ## TURN OFF ICC
    ##conn.send([0xD0, 0x60, 0xBF, 0x03])
    ## TURN OFF MSR
    #conn.send([0xD0, 0x60, 0x7F, 0x03])
    ## DISABLE ATR + ICC
    ##conn.send([0xD0, 0x60, 0xBD, 0x03])
    
    status, buf, uns = getAnswer(False)
    if (P1 & 0x01): #Test bit 0 is set
        log.log ('Card ICC/MagSwipe armed for unsolicited event')
        
    cardState = EMV_CARD_REMOVED
    if uns:
        # Check for insertion unsolicited message
        tlv = TLVParser(buf)
        if tlv.tagCount(0x48):
            cardState = EMVCardState(tlv)

    # initialize Contactless Reader
    if ENABLE_EMV_CONTACTLESS:
      ctls = initContactless()
    else:
      ctls = False

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
                    log.log('Card read attempts', attempts)
                    if attempts == 1:
                        log.warning("EMV FALLBACK TYPE: TECHNICAL --------------------------------------------------------")
                        processMagstripeFallback(tid)
                        break
                    attempts = attempts + 1
                    cardState = EMVCardState(tlv)
                    magState = MagstripeCardState(tlv)
                    if ctls and (cardState == EMV_CARD_INSERTED or magState == MAGSTRIPE_TRACKS_AVAILABLE): # Ignore failed swipes
                       
                        # Cancel Contactless first
                        cancelContactless()

                        # Decrypt payload 
                        log.logerr('Attempting to decrypt SWIPE...')
                        vspDecrypt(tlv, tid)
                        
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
                                displayEncryptedTrack(tlv)
                                displayHMACPAN(tlv)
                                break
                    log.log("Waiting for next occurrance!")
                    continue
                # Check for unsolicited keyboard status
                if tlv.tagCount((0xDF,0xA2,0x05)):
                    kbd_tag_val = tlv.getTag((0xDF,0xA2,0x05), TLVParser.CONVERT_INT)[0]
                    log.log("Keyboard status, keypress ",hex(kbd_tag_val), 'h')
                    continue
                if tlv.tagCount(0xE3) or tlv.tagCount(0xE5):
                    log.log("Completed contactless EMV transaction!")
                    # todo: vsp decrypt!
                    vspDecrypt(tlv, tid)
                    
                    # HMAC PAN
                    displayHMACPAN(tlv)
                    
                    tranType = 4
                    break
                    
                if tlv.tagCount(0xE4):
                
                    # CardSource
                    TC_TransactionHelper.reportCardSource(tlv, log)

                    # Terminal Capabilites
                    appLabel = TC_TransactionHelper.reportTerminalCapabilities(tlv, log)
                    if len(appLabel):
                      displayMsg('\t*** APPLICATION ***\t' + appLabel.decode('iso8859-1'), 3)
                
                    cvm_value = getCVMResult(tlv)
                    # NOT AN EROR, JUST EASIER TO FIND IN THE TERMINAL OUTPUT
                    log.logerr('CVM REQUESTED ______:', cvm_value)
                    print('')
                
                    # decrypt transaction                
                    vspDecrypt(tlv, tid)

                    # HMAC PAN
                    displayHMACPAN(tlv)
                    
                    if cvm_value == 'ONLINE PIN':
                      return OnlinePinTransaction(tlv, tid, cardState, setFirstGenContinueTransaction()) 
 
                    if EMV_ENABLED == 'y':
                      continueContactless()
                    else:
                      log.logerr("CONTACTLESS EMV NOT ALLOWED!")
                      
                      # abort current transaction
                      AbortTransaction()
                      
                      # EMV transaction not allowed
                      displayCustomMsg(0x04)
                      
                      # close existing connection
                      conn.close()
                      
                      # recursive call
                      return processTransaction()
                      
                    tranType = 5
                    break
                    
                if tlv.tagCount(0xE7):
                    # CardSource
                    TC_TransactionHelper.reportCardSource(tlv, log)
                    vspDecrypt(tlv, tid)
                    displayEncryptedTrack(tlv)
                    displayHMACPAN(tlv)
                    continueContactless()
                    tranType = 3
                    break
                    
                    
                if tlv.tagCount(0xE8):
                  continueContactless()
                  tranType = 3
                  break;
                
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
                            
                # Power on event
                if tlv.tagCount(0xE6):
                  log.warning('POWER ON EVENT')
                  continue
                  
                # VAS Payload
                if tlv.tagCount(0x6F):
                  #preferredAid = processCtlsAIDList(tlv)
                  preferredAid = processCtlsAIDListAutomatic(tlv)
                  if len(preferredAid):
                      startContactless(preferredAid)
                      status, buf, uns = getAnswer()
                      continue                  
                  
            # cannot decide how to proceed with response
            log.logerr("Invalid packet detected, ignoring it!")
            print('E4: ', tlv.tagCount(0xE4))
            print(tlv)
    else:
        log.log("Card already inserted!")
        result = processEMV(tid)
        tranType = 1

    # TVR status
    checkTVRStatus(tlv)

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
    status, buf, uns = getAnswer(False)
    
    #Reset display - regardless of tx type
    conn.send([0xD2, 0x01, 0x01, 0x00])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer()


# ---------------------------------------------------------------------------- #
# Main
# ---------------------------------------------------------------------------- #
if __name__ == '__main__':
    
    # arguments
    arg = util.get_argparser()
    
    arg.add_argument('--action', dest='action', default='sale', 
                     help='TC Action for transaction')
    arg.add_argument('--amount', dest='amount', default='100', type=int, 
                     help='Amount of transaction')
    arg.add_argument('--amtother', dest='amtother', default='0', type=int, 
                     help='Amount other')
    args = util.parse_args()

    log = getSyslog()

    log.logerr("TESTHARNESS v" + VERSION_LBL)

    log.warning('TRANSACTION AMOUNT: $', args.amount)
    log.log('TRANSACTION AMOUNT OTHER: $', args.amtother)
    log.log('TOTAL TRANSACTION AMOUNT: $', args.amount + args.amtother)
        
    conn = connection.Connection()

    utility.register_testharness_script(partial(processTransaction, args))
    utility.do_testharness()
