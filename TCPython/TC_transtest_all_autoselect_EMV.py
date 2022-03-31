#!/usr/bin/python3
'''
Created on 21-06-2012

@authors: Lucjan_B1, Kamil_P1, Matthew_H, Jon_Bianco
'''

from testharness import *
from TC_testharness import *
import TC_testharness.utility as util
from functools import partial
from TC_testharness.tlvparser import TLVParser, tagStorage
from TC_testharness.tlvparser import TLVPrepare
from sys import exit
from TC_testharness.syslog import getSyslog
from TC_testharness.utility import getch, kbhit
from testharness.utility import lrccalc
import testharness.fileops as fops
import TC_TCLink
import TC_TransactionHelper
from binascii import hexlify, unhexlify, b2a_hex
from time import sleep
import sys
import getpass
import datetime
import traceback
import os.path
from os import path
import re

# ----------------------------------------------------------------------------------------------------------- #
# VERSION INFORMATION
#
# 20201208
# 1. Contactless multi-application selection: requires second tap
# 2. ONLINE PIN missing in transaction
# 3. BALANCE INQUIRY - set "--action", "verify" and "--amount", "0000" in launch.json
# VERSION_LBL = '1.0.0.0'
#
# 20201210
# 1. Paypass Purchase with cashback transaction
#    Changes to config files and TestHarness
# VERSION_LBL = '1.0.0.1'
#
# 20201211
# 1. ONLINE PIN PAYLOAD
# 2. CASHBACK PARAMETERIZED OPTION
#    Changes to device config files and TestHarness
# VERSION_LBL = '1.0.0.2'
#
# 20201211
# 1. Added ACTION type validation at transaction start
# 2. Changes to device config files for MasterCard Paypass
# 3. Added partial_auth=y to MSR workflows
# 4. Fixed AMEX QC 039 Online PIN Retry workflow
# VERSION_LBL = '1.0.0.3'
#
# 20201217
# 1. Removed empty pin value in transaction request
# 2. Changes to device config files for MasterCard TAG 9F33
# 3. Missing TAGS for M-TIP MasterCard scenarios
# 4. M-TIP05-USM Test 08 Scenario 01f - TAG 9F02 with cashback value
# VERSION_LBL = '1.0.0.4'
#
# 20201218
# 1. Added Transaction Menu
# 2. Automated SALE+CASHBACK transaction
# 3. COM02 Test 02 Scenario 03 - TAG 9F6E missing in transaction
# VERSION_LBL = '1.0.0.5'
#
# 20201221
# 1. Added Transaction Menu bypass
# 2. VISA ADVT configuration
# VERSION_LBL = '1.0.0.6'
#
# 20201221
# 1. UnionPay configuration
# 2. Fixed ONLINE PIN transaction for Discover
# VERSION_LBL = '1.0.0.7'
#
# 20201221
# 1. Enabled contactless balance inquiry
# 2. Paypass USM19 Test 01 Scenario 01 TAG 9F1D like '48'
# VERSION_LBL = '1.0.0.8'
#
# 20201223
# 1. Corrected AAC and TC tag sequence
# 2. Paypass USM01 Test 16 Scenario 01 - CVM=PIN
# 3. DNA TC-28 - requires mapp.cfg update
# VERSION_LBL = '1.0.0.9'
#
# 20201228
# 1. Remove AAC tag modification code
# 2. Update unattended config icckeys.key and contlemv.cfg
# 3. Fix logging for utility method
# VERSION_LBL = '1.0.0.10'
#
# 20210105
# 1. Fix AMEX QC OFFLINE PIN verify workflows
# VERSION_LBL = '1.0.0.11'
#
# 20210111
# 1. M-TIP10 Test 01 Scenario 01f – Offline decline : Analyst wants receipt to be provided for the test case
# 2. Unattended AXP QXC-04 'PLAIN PIN' message
# 3. Added missing TAG 9F66 to Core request
# VERSION_LBL = '1.0.0.12'
#
# 20210112
# 1. Refund processing support
# 2. Reverted offline decline scenario to not send transaction to Core
# VERSION_LBL = '1.0.0.13'
#
# 20210113
# 1. Removed EMV TAGS from Contactless MSD Transaction: AXP QC 019
# VERSION_LBL = '1.0.0.14'
# 20210114
# 1. UX301 MSR HANDLING ENHANCEMENT
# 2. AXP EP020:AXP EP020[a]|AXP EP020[b] handling
# VERSION_LBL = '1.0.0.15'
#
# 20210115
# 1. E2E CL 17 requires transaction to go ONLINE
# 2. INTERLINK PROCESING AS CREDIT INSTEAD OF DEBIT
# VERSION_LBL = '1.0.0.16'
#
# 20210119
# 1. E2E_49 US QC PIN BYPASS MISSING
# VERSION_LBL = '1.0.0.17'
#
# 20210120
# 1. ADVT US Credit/Debit Multi-Application 2A.1 AID should be A000000003101001
# 2. Added message to indicate PIN ENTRY BYPASS
# VERSION_LBL = '1.0.0.18'
#
# 20210121
# 1. AXP QC 033 - displays 'decline' after APPROVED
# 2. AXP EP 06 Contactless Transaction Limit set to $15.00
# 3. MSI 94 TEST 03 SCENARIO 01 - 'DECLINED: OFFLINE'
# 4. MSR Fallback failing
# VERSION_LBL = '1.0.0.19'
#
# 20210125
# 1. MCD19 Test 01 Scenario 01 TAG 9F1D
# VERSION_LBL = '1.0.0.20'
#
# 20210128
# 1. M-TIP10 Test 01 Scenario 01f – Offline decline: CORE to prevent transaction from going to processor
# 2. 9F66 TAG requires Byte 1 Bit 8 set to 0 to disable MSD
# 3. AXP EP019 - removed 'Not Authorised' message
# 4. MCD19, MCD94 - removed 'Not Authorised' message
# 5. pip install pyperclip
# 6. MSR Credit/Debit Menu Selection (Debit PIN Entry)
# VERSION_LBL = '1.0.0.21'
#
# 20210129
# 1. MSR refunds for both Credit and Debit transactions
# VERSION_LBL = '1.0.0.22'
#
# 20210203
# 1. MCD01 Test 01 Scenario 02: Blind Refund as a mock
# 2. MSR Debit Refunds: Blind Refund as a mock
# VERSION_LBL = '1.0.0.23'
#
# 20210205
# 1. Paypass USM50 Test 01 Scenario 01
# * Returns CARD NOT supported error and doesn’t have receipt
# * fixed configuration issue: MAESTRO TAG DF811B=90
# 3. Paypass COM01 Test 01 Scenario 02
# * Returns CARD NOT supported error and doesn’t have receipt
# * Transaction amount: 10001, MAESTRO TAG DF8118=40
# 4. USM94.02.01 requires TAC_Denial = 00 00 00 00 00
# * TAC Denial/Online settings reversed
# VERSION_LBL = '1.0.0.24'
#
# 1. MSI19.01.01 CVMReqLimit = 00 00
# 2. Bug 16827: Cup Test Card E2E_60 fails with UnicodeDecodeError: 'utf-8' codec can't decode byte
# VERSION_LBL = '1.0.0.25'
#
# 1. ONLINE PIN Transactions sending custid, password, action, amount, operator twice
# 2. Attended CAPK FiServ Update to icckeys.key
# VERSION_LBL = '1.0.0.26'
#
# 1. AMEX AXP QC 033 Missing 'action'
# VERSION_LBL = '1.0.0.27'
#
# 1. AMEX EP 084/085/085 BADDATA missing 'action'
# VERSION_LBL = '1.0.0.28'
#
# 1. VISA CDET 1C.6 - PIN BYPASS
# 2. CDET_US_DEBIT_1C.5 failing to process with code 500
# 3. Collision detection improvement
# 4. Fixed CO response in First Continue Transaction if card is: 00=blacklisted, 01=non-blacklisted
#    PAN exception processing is related to DNA_TC_24 ICC TEST CASE.
# VERSION_LBL = '1.0.0.29'
#
# 1. Fix incorrect TAC_Denial vs TAC_Online VIPA tag
# 2. Fixes CDET_US_DEBIT_1C.5 by modifying TAG 9F34
#VERSION_LBL = '1.0.0.30'
#
# 1. Added additional check for Processor 'errortoprocess' during PIN entry
#VERSION_LBL = '1.0.0.31'
#
# 1. Added additional check for Processor 'responsecode' during PIN entry
#VERSION_LBL = '1.0.0.32'
#
# 1. Added flag for force online transaction. Use for DNA-37 test case
#VERSION_LBL = '1.0.0.33'
#
# 1. For error 9F28, always display 'CARD NOT SUPPORTED'
#VERSION_LBL = '1.0.0.34'
#
# 1. All Contact: TAG 95 (TVR) Byte 1, Bit 5 (card appears in exception file) should not be set
# 2. MasterCard dynamic setup for TAG 9F33 for transaction CVM limits validation. 
#VERSION_LBL = '1.0.0.35'
#
# 1. VISA US COMMON DEBIT SALE+CASHBACK - 1) transaction type included in request, 2) contlemv.cfg - AllowCashback=1
#VERSION_LBL = '1.0.0.36'
#
# 1. 9F33 Modification in script is changed to 0x40 for second byte in unattended devices
#VERSION_LBL = '1.0.0.37'
#
# 1. Added action 'void2' to void transactions
# execute: 
# TC_transtest_all_autoselect_EMV.py --serial COM25   --custid 1117600 --password ipa1234 --action void --transid 097-0000094712 --transaction_menu n --device_pinpad_capable y --amount 200 --validateAmount n
#VERSION_LBL = '1.0.0.38'
#
# 1. Added action 'void2' to void transactions
# execute: 
# TC_transtest_all_autoselect_EMV.py --serial COM25   --custid 1117600 --password ipa1234 --action void --transid 097-0000094712 --transaction_menu n --device_pinpad_capable y --amount 200 --validateAmount n
#
#VERSION_LBL = '1.0.0.39'
#
# 1. Added emv_kernel_version parameter to transaction output
#
#VERSION_LBL = '1.0.0.40'
#
# 1. Added emv_kernel_version for US Debit Common AID: A0000000980840
#
#VERSION_LBL = '1.0.0.41'
#
# 1. Cashback processing as DEBIT instead of CREDIT
#
#VERSION_LBL = '1.0.0.42'
#
# 1. Transmit TAG 9F6C as 'emv_9f6c_ctq'
#
#VERSION_LBL = '1.0.0.43'
#
# 1. Added DISCOVER US-DEBIT AID A0000001524010 to kernel reporting logic.
# 
VERSION_LBL = '1.0.0.44'
#
# 1. Fixed TC_TCLink.processPINTransaction missing argument.
# 
# ----------------------------------------------------------------------------------------------------------

# ---------------------------------------------------------------------------- #
# REGRESSION TESTS TO RUN
### AMEX
#  1. SALE           : Amex AXP QC 004 OFFLINE PIN
#  2. SALE           : Amex AXP QC 008 PIN BYPASS
#  3. SALE           : Amex AXP QC 032 ONLINE PIN
### M/C
#  4. SALE + CASHBACK: Mastercard M-TIP05-USM Test 08 Scenario 01f
#  5. BALANCE INQUIRY: Mastercard M-TIP06 Test 10 Scenario 01
#  6. SALE + CASHBACK: Mastercard PayPass MSI01 Test 09 Scenario 01
#  7. SALE           : Mastercard Paypass USM01 Test 16 Scenario 01
#  8. SALE           : Mastercard Paypass USM12 Test 01 Scenario 02
### VISA
#  9. SALE           : VISA ADVT 7.0aqc Test Case 1a
# 10. SALE           : VISA CDET Debit 1C.2
# ---------------------------------------------------------------------------- #

# ---------------------------------------------------------------------------- #
# GLOBALS
# ---------------------------------------------------------------------------- #

# TRANSACTION TYPE (TAG 9C)
# 0x00 - Sale / Purchase (EMV) - "transaction_type_goods" is used
# 0x01 - Cash Advance (EMV) - "transaction_type_cash" is used
# 0x09 - Sale / Purchase with cashback (EMV) - "transaction_type_goods_with_disbursement" is used
# 0x20 - Return / Refund (EMV) - "transaction_type_returns" is used
# 0x30 - Balance (non-EMV) - "transaction_type_balance_inquiry" is used
# 0x31 - Reservation (non-EMV) - "transaction_type_reservation" is used
# 0x40 - Void
# 0xFE - none (non-EMV) - "transaction_type_" is skipped

TRANSACTION_TYPE = b'\x00'  # SALE TRANSACTION
#TRANSACTION_TYPE = b'\x09'  # SALE WITH CASHBACK TRANSACTION - MTIP05-USM Test 08 Scenario 01f
#TRANSACTION_TYPE = b'\x30'  # BALANCE INQUIRY
#BALANCE INQUIRY - MTIP06_10_01_15A, MTIP06_12_01_15A
ISCASHBACK = TRANSACTION_TYPE == b'\x09'
ISBLINDREFUND = False
ISBALANCEINQUIRY = TRANSACTION_TYPE == b'\x30'
AMOUNTFORINQUIRY = b'\x00\x00\x00\x00\x00\x00'
ISVOIDTRANSACTION = False

# Transaction Type Dictionary
TransactionType = {
    1: [b'\x00', "SALE / PURCHASE"],
    2: [b'\x01', "CASH ADVANCE"],
    3: [b'\x09', "SALE WITH CASHBACK"],
    4: [b'\x20', "RETURN / REFUND"],
    5: [b'\x30', "BALANCE INQUIRY"],
    6: [b'\x31', "RESERVATION"],
    7: [b'\x20', "* BLIND REFUND MOCK *"],
}
TransactionTitle = 'SELECT TYPE:'

# UX == UNATTENDED
DEVICE_UNATTENDED = ""

EMV_CARD_REMOVED = 0
EMV_CARD_INSERTED = 1
MAGSTRIPE_TRACKS_AVAILABLE = 2
MAGSTRIPE_CARD_SWIPE = 3
ERROR_UNKNOWN_CARD = 4

USE_QUICKCHIP_MODE = True
QUICKCHIP_ENABLED = [(0xDF, 0xCC, 0x79), [0x01]]
QUICKCHIP_DISABLED = [(0xDF, 0xCC, 0x79), [0x00]]

ISSUER_AUTH_DATA = [(0x91), [0x37, 0xDD, 0x29, 0x75, 0xC2, 0xB6, 0x68, 0x2D, 0x00, 0x12]]

# iccdata.dat: #65
ACQUIRER_ID = [(0xC2), [0x36, 0x35]]

###
# DNA COMBINATION TO OBTAIN 2nd GENERATE ACC:
#   1. AUTHRESPONSECODE = Z3
#   2. ONLINE ACTION REQUIRED TEMPLATE 0xE4 MUST HAVE args.online == "y"
###

# AUTHRESPONSECODE = [ (0x8A), [0x30, 0x30] ]  # authorization response code of 00
# AUTHRESPONSECODE = [ (0x8A), [0x59, 0x31] ]  # authorization response code of Y1 - offline approved
# AUTHRESPONSECODE = [ (0x8A), [0x59, 0x33] ]  # authorization response code of Y3 - unable to go online, offline approved
# AUTHRESPONSECODE = [ (0x8A), [0x5A, 0x31] ]  # authorization response code of Z1 - offline declined
AUTHRESPONSECODE = [(0x8A), [0x5A, 0x33]]  # authorization response code of Z3 - unable to go online, offline decline

# CURRENCY / COUNTRY CODE
UK = b'\x08\x26'
US = b'\x08\x40'
CH = b'\x01\x56'
CURRENCY_CODE = [(0x5F, 0x2A), US]
COUNTRY_CODE = [(0x9F, 0x1A), US]

# After an AAR (Application Authorisation Referral) or ARQC (Authorisation Request Cryptogram) where the acquirer
# is contacted, the decision is made with tag C0. If the acquirer cannot be contacted or a stand-in authorisation
# is detected, do not send this tag. By not sending the tag, default analysis is carried out.
#
# ‘C0’ must be sent in the next ‘Continue Transaction’ command, set as positive (0x01) to request a TC or negative (0x00) to request an AAC.
CONTINUE_REQUEST_AAC = [(0xC0), [0x00]]  # Online (00)
CONTINUE_REQUEST_TC = [(0xC0), [0x01]]  # Offline (Z3)

ONLINE = 'n'
ISOFFLINE = AUTHRESPONSECODE[1] == [0x5A, 0x33]

# BCD EMV values (must poplate before transaction start)
AMOUNT = b'\x00\x00\x00\x00\x01\x00'
AMTOTHER = b'\x00\x00\x00\x00\x00\x00'
DATE = b'\x20\x10\x01'
TIME = b'\x00\x00\x00'

APPLICATION_SELECTION_POS = False
APPLICATION_AID = ''
APPLICATION_LABEL = ''
APPLICATION_SELECTION = -1

# ---------------------------------------------------------------------------- #
# ONLINE PIN VSS
# Alter from default of 2 to VSS Script index 2 (host_id=3)
host_id_vss = 0x02
# Key Set Id - VSS SLOT (0 - PROD, 8 - DEV)
keyset_id_vss = 0x00

# ---------------------------------------------------------------------------- #
# ONLINE PIN IPP DUPK
host_id_ipp = 0x05
# IPP KEY SLOT
keyset_id_ipp = 0x01

IS_IPP_KEY = True
HOST_ID = host_id_ipp if IS_IPP_KEY else host_id_vss
KEYSET_ID = keyset_id_ipp if IS_IPP_KEY else keyset_id_vss
IPP_PIN_IS_ASCII = True

# ONLINE PIN LENGTHS
PINLEN_MIN = 0x04
PINLEN_MAX = 0x06

OnlineEncryptedPIN = ""
OnlinePinKSN = ""

OnlinePinContinueTPL = []
OFFLINERESPONSE = ""

# FISERVER INVALID PIN RESULT CODE
ONLINEPIN_INVALID = 117

# DISPLAY MESSAGES
DM_9F0D = "INTERNAL ERROR\n\t-\n\tTAG DFDF30"
DM_9F22 = "DEVICE NOT READY\n\tFOR COMMAND"
DM_9F25 = "BAD CARD-\n\tTRANSACTION ABORTED"
DM_9F28 = "CARD NOT SUPPORTED"
DM_9F31 = "PLEASE PRESENT ONE\n\tCARD ONLY"
DM_9F33 = "SEE PHONE FOR\n\tINSTRUCTIONS"
DM_9F34 = "INSERT CARD"
DM_9F35 = "ENTER CONSUMER\n\tDEVICE CVM"
DM_9F36 = "CONTACTLESS CARD LEFT\n\tIN FIELD - REMOVE"
DM_9F41 = "USER CANCELLED\n\tPIN ENTRY"
DM_9F42 = "CASHBACK NOT\n\tALLOWED"
DM_9F43 = "USER CANCELLED"

# PROCESSING
EMV_VERIFICATION = 0

# FINAL ACTIONS
SIGN_RECEIPT = False

# EMV TO MSR FALLBACK
FALLBACK_TYPE = 'technical'

LIST_STYLE_SCROLL = 0x00
LIST_STYLE_NUMERIC = 0x01
LIST_STYLE_SCROLL_CIRCULAR = 0x02

# ---------------------------------------------------------------------------- #
# VAS TRANSACTIONS - REQUIRE VIPA 6.8.2.17 or greater
EnableVASTransactions = False
CLS_TRANSACTIONS = 0x21 if EnableVASTransactions else 0x01

#----------------------------------------------------------------------------#
# EMV Kernel Version Reporting
EMV_KERNEL_CHECKSUM = ''
EMV_L2_KERNEL_VERSION = ''
EMV_CLESS_KERNEL_VERSION = ''

# ---------------------------------------------------------------------------- #
# UTILTIES
# ---------------------------------------------------------------------------- #

def selectTransaction():
    ''' Set data for request '''
    c_tag = tagStorage()
    c_tag.store((0xDF, 0xA2, 0x12), LIST_STYLE_SCROLL)
    # BUG: Unable to push the direct string not bytearray
    c_tag.store((0xDF, 0xA2, 0x11), TransactionTitle)

    i = 1
    for key in TransactionType:
        c_tag.store((0xDF, 0xA2, 0x02), i)
        c_tag.store((0xDF, 0xA2, 0x03), TransactionType[key][1])
        i = i + 1

    ''' Send request '''
    conn.send([0xD2, 0x03, 0x00, 0x01], c_tag.get())
    status, buf, uns = getAnswer()

    # if user cancels, default to 'SALE' Transaction
    if status == 0x9F43:
        return 1

    index = 1  # default to SALE
    tlv = TLVParser(buf)
    if tlv.tagCount((0xDF, 0xA2, 0x02)) == 1:
        selection = tlv.getTag((0xDF, 0xA2, 0x02))[0]
        index = selection[0]

    log.log("TRANSACTION TYPE: '" + TransactionType[index][1] + "' AT INDEX =", index)
    return index

def AbortTransaction():
    log.logerr('Abort Current Transaction')
    conn.send([0xD0, 0xFF, 0x00, 0x00])
    status, buf, uns = getAnswer()
    return -1

def ResetDevice():
    global EMV_L2_KERNEL_VERSION
    # Send reset device
    # P1 - 0x00
    # perform soft-reset, clears all internal EMV collection data and returns Terminal ID,
    #  Serial Number and Application information
    conn.send([0xD0, 0x00, 0x00, 0x01])
    status, buf, uns = getAnswer()
    log.log('Device reset')
    tlv = TLVParser(buf)
    # L2 EMV Contact Kernel: after terminal reset
    EMV_L2_KERNEL_VERSION = TC_TransactionHelper.GetEMVL2KernelVersion(tlv)
    return tlv

# Finalise the script, clear the screen
def performCleanup():
    # DISPLAY [D2 01]
    conn.send([0xD2, 0x01, 0x01, 0x00])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer(True, False)

def vsdSREDTemplateDebugger(tlv, tid):
    # print(">>> ff7f", tlv.tagCount((0xFF,0x7F)))
    if tlv.tagCount((0xFF, 0x7F)):
        # log.log('>>> vsp_tlv bytes', tlv.getTag((0xFF,0x7F))[0])
        tlvp = TLVPrepare()
        vsp_tlv_tags = tlvp.parse_received_data(tlv.getTag((0xFF, 0x7F))[0])
        vsp_tlv = TLVParser(vsp_tlv_tags)
        # vsp_tlv = TLVParser(tlv.getTag((0xFF,0x7F))[0])
        # log.log('>>> buf', buf)
        # log.log('>>> tlv', tlv)
        # log.log('>>> vsp_tlv_tags', vsp_tlv_tags)
        # log.log('>>> vsp_tlv', vsp_tlv)
        if vsp_tlv.tagCount((0xDF, 0xDF, 0x10)):
            print(">>> vsp_tlv DFDF10", hexlify(vsp_tlv.getTag((0xDF, 0xDF, 0x10))[0]))
        if vsp_tlv.tagCount((0xDF, 0xDF, 0x11)):
            print(">>> vsp_tlv DFDF11", hexlify(vsp_tlv.getTag((0xDF, 0xDF, 0x11))[0]))
        if vsp_tlv.tagCount((0xDF, 0xDF, 0x12)):
            print(">>> vsp_tlv DFDF12", hexlify(vsp_tlv.getTag((0xDF, 0xDF, 0x12))[0]))
        if vsp_tlv.tagCount((0xDF, 0xDF, 0x10)) and vsp_tlv.tagCount((0xDF, 0xDF, 0x11)) and vsp_tlv.tagCount((0xDF, 0xDF, 0x12)):
            encryptedtrack = (
                'TVP|iv:' + vsp_tlv.getTag((0xDF, 0xDF, 0x12))[0].hex() + 
                '|ksn:' + vsp_tlv.getTag((0xDF, 0xDF, 0x11))[0].hex() + 
                '|vipa:' + vsp_tlv.getTag((0xDF, 0xDF, 0x10))[0].hex()
            )
            log.log(
                '>>> encryptedtrack=' + str(encryptedtrack)
                + '\\ncustid=' + str(args.custid)
                + '\\npassword=' + str(args.password)
                + '\\naction=' + str(args.action)
                + '\\ndevice_serial=' + str(tid)
            )

# Gets answer from the device, optionally ignoring unsolicited and stopping on errors
def getAnswer(ignoreUnsolicited=True, stopOnErrors=True):
    while True:
        status, buf, uns = conn.receive()
        if uns and ignoreUnsolicited:
            log.log('Unsolicited packet detected: ', TLVParser(buf))
            continue
        #
        # track acceptable errors in EMV Certification Testing
        #
        if (status != 0x9000 and status != 0x9F0D and status != 0x9F36 and 
            status != 0x9F22 and status != 0x9F25 and status != 0x9F28 and 
            status != 0x9F31 and status != 0x9F33 and status != 0x9F34 and 
            status != 0x9F35 and status != 0x9F41 and status != 0x9F42 and 
            status != 0x9F43
        ):
            log.logerr('Pinpad reported error ', hex(status))
            traceback.print_stack()
            if stopOnErrors:
                performCleanup()
                exit(0)
        break
    return status, buf, uns

def getEMVAnswer(ignoreUnsolicited=False):
    return getAnswer(ignoreUnsolicited, False)

# ---------------------------------------------------------------------------- #
# DEVICE CONNECTIVITY AND STATE
# ---------------------------------------------------------------------------- #

def startConnection():
    # instantiate connection
    req_unsolicited = conn.connect()
    if req_unsolicited:
        # Receive unsolicited
        log.log('Waiting for unsolicited')
        # status, buf, uns = getAnswer(False)
        # log.log('Unsolicited', TLVParser(buf) )

    # abort current transaction
    AbortTransaction()

def startMonitoringCardStatus():
    log.log('*** START CARD MONITORING ***')
    ### ------------------------------------------------------------------------------------------
    # Clarifications added to VIPA manual in version 6.8.2.11.
    # When the ICC notification is disabled (i.e. P1 bit 7) then VIPA will not be able to send
    # unsolicited response for the changes in card status. However for MSR transaction in UX30x,
    # POS can simply disable ATR notification (i.e. P1 bit 1) and VIPA will notify the POS
    # regarding the card insertion and POS can fallback to magstripe.
    ### ------------------------------------------------------------------------------------------
    # P1 - REQUESTS
    # Bit 7 - Disables ICC notifications
    # Bit 6 - Disables magnetic reader notifications
    # Bit 5 - Enables magnetic track status reporting (tag DFDF6E)
    # Bit 4 - Requests the Track 3 data in the response (tag 5F23)
    # Bit 3 - Requests the Track 2 data in the response (tag 5F22)
    # Bit 2 - Requests the Track 1 data in the response (tag 5F21)
    # Bit 1 - Requests the ATR in the response (tag 63)
    # Bit 0 - Sets the device to report changes in card status
    #
    P1 = 0x3F
    # P2 - Monitor card and keyboard status
    # 00 - stop reporting key presses
    # Bit 1 - report function key presses
    # Bit 0 - report enter, cancel and clear key presses
    ## ICC + MSR
    P2 = 0x03
    #
    # CARD STATUS [D0, 60]
    conn.send([0xD0, 0x60, P1, P2])

def getCardStatus():
    # P1
    # Bit 0 - Sets the device to report changes in card status
    # CARD STATUS [D0, 60]
    conn.send([0xD0, 0x60, 0x01, 0x00])
    status, buf, uns = getAnswer(False)
    return TLVParser(buf)

def getEMVCardStatus():
    # P1
    # Bit 0 - Sets the device to report changes in card status
    # CARD STATUS [D0, 60]
    conn.send([0xD0, 0x60, 0x01, 0x00])
    status, buf, uns = getAnswer(False)
    tlv = TLVParser(buf)
    return EMVCardState(tlv)

def stopMonitoringKeyPresses():
    # STOP Monitor card and keyboard status
    # P2 - keyboard monitoring
    # 00 - stop reporting key presses
    # Bit 0 - report enter, cancel and clear key presses
    # Bit 1 - report function key presses
    conn.send([0xD0, 0x61, 0x00, 0x00])
    log.log('*** STOP KEYBOARD MONITORING ***')
    status, buf, uns = getAnswer(False)

# ---------------------------------------------------------------------------- #
# TRANSACTION PROCESSING
# ---------------------------------------------------------------------------- #

def displayMsg(message, pause=0):
    # DISPLAY [D2, 01]
    conn.send([0xD2, 0x01, 0x00, 0x01], '\x0D\x09' + message)
    status, buf, uns = getAnswer()
    if pause > 0:
        sleep(pause)

def displayAidChoice(tlv):
    ''' Retrieve application list '''
    appLabels = tlv.getTag(0x50)
    appAIDs = tlv.getTag((0x9F, 0x06))
    appPriority = tlv.getTag((0x87))
    log.log('We have ', len(appLabels), ' applications')

    app_sel_tags = []

    for i in range(len(appLabels)):
        app_sel_tags.append([(0x50), appLabels[i]])
        app_sel_tags.append([(0x87), appPriority[i]])
        app_sel_tags.append([(0x9F, 0x06), appAIDs[i]])

    app_sel_templ = (0xE0, app_sel_tags)

    log.log("CONTINUE TRANSACTION: AID CHOICE --------------------------------------------")
    # CONTINUE TRANSACTION [DE D2]
    conn.send([0xDE, 0xD2, 0x00, 0x00], app_sel_templ)
    log.log('waiting for App Selection...')
    status, buf, uns = getEMVAnswer()
    if status != 0x9000:
        return -1

def requestAIDChoice(tlv):
    ''' Retrieve application list '''
    appLabels = tlv.getTag(0x50)
    appAIDs = tlv.getTag((0x9F, 0x06))
    log.log('We have ', len(appLabels), ' applications:')

    if len(appLabels) != len(appAIDs):
        log.logerr('Invalid response: AID count ', len(appAIDs), ' differs from Labels count ', len(appLabels))
        exit(-1)

    ''' Set selection list '''
    c_tag = tagStorage()
    c_tag.store((0xDF, 0xA2, 0x12), LIST_STYLE_SCROLL)

    # BUG: Unable to push the direct string not bytearray
    c_tag.store((0xDF, 0xA2, 0x11), 'SELECT AN APPLICATION')
    for i in range(len(appLabels)):
        log.log('App ', i + 1, ': AID ', hexlify(appAIDs[i]), ', label ', str(appLabels[i]))
        c_tag.store((0xDF, 0xA2, 0x02), i)
        c_tag.store((0xDF, 0xA2, 0x03), str(appLabels[i]))

    ''' Send request '''
    conn.send([0xD2, 0x03, 0x00, 0x01], c_tag.get())

    status, buf, uns = getEMVAnswer()
    if status != 0x9000:
        return -1

    tlv = TLVParser(buf)
    if tlv.tagCount((0xDF, 0xA2, 0x02)) == 1:
        selection = tlv.getTag((0xDF, 0xA2, 0x02))[0]
        # TC_transtest_all_autoselect_EMV.log.log("USER SELECTED:", selection[0])
        if selection >= 0:
            selection = selection - 1
            log.log('Selected ', selection)
            app_sel_tags = [[(0x50), bytearray(appLabels[selection])], [(0x9F, 0x06), bytearray(appAIDs[selection])], ACQUIRER_ID]
            app_sel_templ = (0xE0, app_sel_tags)

            log.log("CONTINUE TRANSACTION: AID CHOICE --------------------------------------------")
            # CONTINUE TRANSACTION [DE D2]
            conn.send([0xDE, 0xD2, 0x00, 0x00], app_sel_templ)
            log.log('App selected, waiting for response...')

def applicationSelection(tlv):
    # This is app selection
    appLabels = tlv.getTag(0x50)
    appAIDs = tlv.getTag((0x9F, 0x06))
    log.log('We have ', len(appLabels), ' applications')

    if len(appLabels) != len(appAIDs):
        log.logerr('Invalid response: AID count ', len(appAIDs), ' differs from Labels count ', len(appLabels))
        exit(-1)

    for i in range(len(appLabels)):
        log.log('App ', i + 1, ': AID ', hexlify(appAIDs[i]), ', label ', str(appLabels[i]))

    sel = -1

    while True:
        # Note: The below will work for up to 9 apps...
        if kbhit():
            try:
                sel = ord(getch())
            except:
                print('invalid key!')
            # TC_transtest_all_autoselect_EMV.log.log('key press ', sel)
            if sel > 0x30 and sel <= 0x30 + len(appLabels):
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
        app_sel_tags = [
            [(0x50), bytearray(appLabels[sel])], 
            [(0x9F, 0x06), bytearray(appAIDs[sel])], 
            ACQUIRER_ID
        ]
        app_sel_templ = (0xE0, app_sel_tags)

        log.log("CONTINUE TRANSACTION: AID CHOICE --------------------------------------------")
        # CONTINUE TRANSACTION [DE D2]
        conn.send([0xDE, 0xD2, 0x00, 0x00], app_sel_templ)
        log.log('App selected, waiting for response...')

def applicationSelectionWithChoice():
    global APPLICATION_AID, APPLICATION_LABEL, APPLICATION_SELECTION

    if APPLICATION_SELECTION != -1:
        if len(APPLICATION_AID) and len(APPLICATION_LABEL):
            # save application label 
            TC_TCLink.saveEMVASCIITag((APPLICATION_LABEL))
            # build tag for next request        
            app_sel_tags = [
                # POS APPLICATION SELECTION
                APPLICATION_AID, 
                APPLICATION_LABEL,
                ACQUIRER_ID
            ]
            app_sel_templ = (0xE0, app_sel_tags)

            log.log("CONTINUE TRANSACTION: AID CHOICE --------------------------------------------")
            # CONTINUE TRANSACTION [DE D2]
            conn.send([0xDE, 0xD2, 0x00, 0x00], app_sel_templ)
            log.log('POS Application Selected, waiting for response...')

# Checks card status, based on device response
def EMVCardState(tlv):
    res = -1
    # Check for card status
    if tlv.tagCount(0x48):
        ins_tag_val = tlv.getTag(0x48, TLVParser.CONVERT_INT)[0]
        # Byte 0
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

# Checks card status, based on device response
def CardIsEMVCapable(tlv):
    res = False
    # Check for card status
    if tlv.tagCount(0x48):
        ins_tag_val = tlv.getTag(0x48, TLVParser.CONVERT_INT)[0]
        # Byte 1
        # Bit 0: Card successfully swiped
        # Bit 1: Track 1 available
        # Bit 2: Track 2 available
        # Bit 3: Track 3 available
        ins_tag_val &= 0x0005
        if ins_tag_val == 5:
            serviceCode = getMSRTrack2ServiceCode(tlv)
            if serviceCode[0] == '2':
                log.log('Card is EMV Capable')
                res = True
    return res

# Get magstripe status, based on device response
def MagstripeCardState(tlv):
    res = -1
    # Check for card status
    if tlv.tagCount(0x48):
        ins_tag_val = tlv.getTag(0x48, TLVParser.CONVERT_INT)[0]
        swipe_state = (ins_tag_val & 0xFF00) >> 8
        ins_tag_val &= 0x00FF
        if ins_tag_val == 1:
            log.logerr('Magstripe, but no tracks!')
            res = ERROR_UNKNOWN_CARD
        else:
            if swipe_state == 1:
                res = MAGSTRIPE_CARD_SWIPE
            else:
                if ins_tag_val == 0:
                    res = EMV_CARD_REMOVED
                else:
                    res = MAGSTRIPE_TRACKS_AVAILABLE
    return res

# Ask for card removal and waits until card is removed
def removeEMVCard():
    # DISPLAY [D2 01]
    conn.send([0xD2, 0x01, 0x0E, 0x01])
    status, buf, uns = getAnswer(False)
    if status != 0x9000:
        log.logerr('Remove card', hex(status), buf)
        exit(-1)
    log.log('*** REMOVE CARD WAIT ***')
    tlv = ''
    while True:
        status, buf, uns = getAnswer(False)
        if uns:
            tlv = TLVParser(buf)
            cardState = EMVCardState(tlv)
            if cardState == EMV_CARD_REMOVED:
                break
        if len(tlv):
            log.logerr('Bad packet ', tlv)

    return tlv

# Processes magstripe fallback - asks for swipe
def processMagstripeFallback(tid):
    global FALLBACK_TYPE
    # Ask for removal and swipe
    # CARD STATUS [D0 60]
    # P1
    # Bit 7 - Disables ICC Notifications
    # Bit 6 - Disables MSR track reporting
    # Bit 5 - Enables MSR track reporting
    # Bit 4 - Requests Track 3 data in response
    # Bit 3 - Requests Track 2 data in response
    # Bit 2 - Requests Track 1 data in response
    # Bit 1 - Request the ATR in response
    # P1 = 0x1F - ALLOW ALL NOTIFICATIONS
    conn.send([0xD0, 0x60, 0x1F, 0x00])
    while True:
        status, buf, uns = getAnswer(False)  # Get unsolicited
        if uns:
            tlv = TLVParser(buf)
            cardStatus = EMVCardState(tlv)
            if cardStatus == EMV_CARD_INSERTED or cardStatus == ERROR_UNKNOWN_CARD:
                tlv = removeEMVCard()
            break

    # Cancel Contactless first
    cancelContactless()

    # Ask for swipe
    if MagstripeCardState(tlv) == EMV_CARD_REMOVED:
        promptForSwipeCard()
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
        TC_TransactionHelper.vspDecrypt(tlv, tid, log)
        TC_TransactionHelper.displayEncryptedTrack(tlv, log)
        TC_TransactionHelper.displayHMACPAN(tlv, log)
        TC_TCLink.saveCardData(tlv)
        TC_TCLink.setDeviceFallbackMode(FALLBACK_TYPE)
    # We're done!
    return 5

# ---------------------------------------------------------------------------- #
# PIN Workflow
# ---------------------------------------------------------------------------- #

#Allow Pin to be bypass or Aborted, otherwise, wait until PIN is entered from keypad
def performUserPINEntry():

    log.log('PIN Entry is being performed, waiting again')
    print('PIN Entry, press \'A\' to abort, \'B\' to bypass or \'C\' to cancel')

    hasPinEntry = True

    while True:
        # sleep(1)
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
                hasPinEntry = False
                # Wait for confirmation, then break to wait for response
                status, buf, uns = getAnswer(stopOnErrors=False)
                if status == 0x9000:
                    break
                else:
                    continue
            else:
                continue

        if conn.is_data_avail():
            break

    return hasPinEntry

def getPINEntry(tlv):

    global OnlineEncryptedPIN, OnlinePinKSN
    global HOST_ID, KEYSET_ID

    log.log('PIN Entry is being performed, waiting again')
    onlinepin_tag = [
        [(0xDF, 0xDF, 0x17), AMOUNT],  # transaction amount
        [(0xDF, 0xDF, 0x24), b'PLN'],  # transaction currency
        [(0xDF, 0xDF, 0x1C), 0x02],  # transaction currency exponent
        [(0xDF, 0xA2, 0x0E), 0x0F],  # pin entry timeout: default 30 seconds
    ]
    onlinepin_tpl = (0xE0, onlinepin_tag)

    # ONLINE PIN [DE, D6]
    conn.send([0xDE, 0xD6, HOST_ID, KEYSET_ID], onlinepin_tpl)
    status, buf, uns = getEMVAnswer()

    if status != 0x9000:
        return -1
    pin_tlv = TLVParser(buf)
    displayMsg('Processing')

    OnlineEncryptedPIN = pin_tlv.getTag((0xDF, 0xED, 0x6C))[0].hex().upper()
    OnlinePinKSN = pin_tlv.getTag((0xDF, 0xED, 0x03), TLVParser.CONVERT_HEX_STR)[0].upper()
    # adjust KSN for IPP
    if HOST_ID == 0x05 and IPP_PIN_IS_ASCII:
        OnlineEncryptedPIN = bytes.fromhex(OnlineEncryptedPIN).decode('utf-8')
        ksnStr = bytes.fromhex(OnlinePinKSN).decode('utf-8')
        OnlinePinKSN = "{:F>20}".format(ksnStr)
    if len(OnlineEncryptedPIN) and len(OnlinePinKSN):
        log.logwarning("PIN=" + OnlineEncryptedPIN + "|" + OnlinePinKSN)
    return 1

def OnlinePinTransaction(tlv, cardState, continue_tpl, setattempts=0, bypassSecongGen=False):
    global TRANSACTION_TYPE, AMOUNT, PINLEN_MIN, PINLEN_MAX
    global HOST_ID, KEYSET_ID
    global EMV_L2_KERNEL_VERSION, EMV_CLESS_KERNEL_VERSION
    
    # AXP QC 032 REQUIRES 2nd GENERATE AC to report TAGS 8A and 9F27
    if cardState == EMV_CARD_INSERTED and bypassSecongGen == False:
        sendSecondGenAC(continue_tpl)

    log.log('Online PIN mode')

    # If SRED is enabled and pan_cache_timeout is specified in the [vipa] section of MAPP_VSD_SRED.CFG, the last cached PAN will be used for
    # PIN Block Formats that require PAN in case the PAN tag is not supplied.
    onlinepin_tag = [
        [(0xDF, 0xDF, 0x17), AMOUNT],  # transaction amount
        [(0xDF, 0xDF, 0x24), b'PLN'],  # transaction currency
        # transaction currency exponent
        # transaction type
        # pin entry timeout: default 30 seconds
        # min pin length
        # max pin length
        [(0xDF, 0xDF, 0x1C), 0x02],
        [(0xDF, 0xDF, 0x1D), TRANSACTION_TYPE],
        [(0xDF, 0xA2, 0x0E), 0x0F],
        [(0xDF, 0xED, 0x04), PINLEN_MIN],
        [(0xDF, 0xED, 0x05), PINLEN_MAX],
        # 20201119: JIRA TICKET VS-52542 as this option does not work
        # AXP QC 037 - ALLOW PIN BYPASS WITH <GREEN> BUTTON
        # PIN entry type: pressing ENTER on PIN Entry screen (without any PIN digits) will return SW1SW2=9000 response with no data
        [(0xDF, 0xEC, 0x7D), b'\x01'],
    ]
    onlinepin_tpl = (0xE0, onlinepin_tag)

    response = "declined"
    attempts = setattempts

    while response != "approved" and attempts < args.pinattempts:
        # ONLINE PIN [DE, D6]
        conn.send([0xDE, 0xD6, HOST_ID, KEYSET_ID], onlinepin_tpl)
        status, buf, uns = getEMVAnswer()
        if status != 0x9000:
            pin_tlv = TLVParser(buf)
            if pin_tlv.tagCount((0xDF, 0xDF, 0x30)):
                response = pin_tlv.getTag((0xDF, 0xDF, 0x30), TLVParser.CONVERT_HEX_STR)[0].upper()
                if len(response):
                    log.logerr("PIN RETRIEVE RESPONSE=" + response)
            break
        pin_tlv = TLVParser(buf)

        # PIN bypass is allowed as per: AXP QC 037
        encryptedPIN = pin_tlv.getTag((0xDF, 0xED, 0x6C))
        if len(encryptedPIN):
            encryptedPIN = pin_tlv.getTag((0xDF, 0xED, 0x6C))[0].hex().upper()
            if len(encryptedPIN):
                ksn = pin_tlv.getTag((0xDF, 0xED, 0x03), TLVParser.CONVERT_HEX_STR)[0].upper()
                if len(ksn):
                    # adjust KSN for IPP
                    # note: this is not required if scapp.cfg IPP_DATA_FORMAT=1
                    if HOST_ID == 0x05 and IPP_PIN_IS_ASCII:
                        encryptedPIN = bytes.fromhex(encryptedPIN).decode('utf-8')
                        ksnStr = bytes.fromhex(ksn).decode('utf-8')
                        ksn = "{:F>20}".format(ksnStr)
                    displayMsg('Processing ...')
                    TC_TCLink.saveEMVData(tlv, 0xE4, ISCASHBACK)

                    # sale with cashback requires ONLINE ENCRYPTED PIN in TAG 9F34
                    if TRANSACTION_TYPE == b'\x09':
                        cvm_requested = tlv.getTag((0x9F, 0x34))[0]
                        if len(cvm_requested):
                            if cvm_requested[0] == 0x3F:
                                CVM_REQUIRED_SIG = [(0x9F, 0x34), b'\x42\x03\x02']
                                TC_TCLink.saveEMVHEXMapTag((CVM_REQUIRED_SIG))

                    # reset properties as they get recycled with each processing attempt
                    if setattempts == 1 or attempts > 0:
                        TC_TCLink.SetProperties(args, log)

                    # ONLINE PIN Kernel Reporting
                    if EMV_CLESS_KERNEL_VERSION == '':
                         # Card Source
                        entryMode_value = TC_TransactionHelper.reportCardSource(tlv, log)
                        EMV_CLESS_KERNEL_VERSION = TC_TransactionHelper.GetEMVContactlessKernelVersion(conn, tlv, entryMode_value)

                    # send to process online PIN entry
                    response = TC_TCLink.processPINTransaction(encryptedPIN, ksn,  EMV_L2_KERNEL_VERSION, EMV_CLESS_KERNEL_VERSION)

                    # Timeout Reversal (TOR): don't retry PIN entry
                    if response == "error":
                        errorType = TC_TCLink.getErrorType()
                        if errorType == "failtoprocess":
                            log.logerr("PROCESSOR: failed to process")
                            break

                    log.log("PIN response: " + response)
                    if response != "approved":
                        displayMsg('TRANSACTION DECLINED', 3)
                        attempts += 1

                    if response != "approved" and attempts >= args.pinattempts:
                        displayMsg('PIN try limit exceeded', 3)
        else:
            # CDET U.S. Debit 1C.6 - Cardholder cancels or exits from PIN entry
            # 0x02 - timeout
            # 0x04 - host not found (requested in P1 host configuration was not found)
            # 0x14 - cancel
            # 0x15 - bypass (in this case SW1SW2=9000)
            pinBypassed = pin_tlv.getTag((0xDF, 0xDF, 0x30))
            if len(pinBypassed):
                pinBypassed = pin_tlv.getTag((0xDF, 0xDF, 0x30))[0]
                if pinBypassed == b'\x15':
                    log.logwarning("TRANSACTION WITH PIN BYPASS...")
                    CVM_REQUIRED_SIG = [(0x9F, 0x34), b'\x1E\x03\x02']
                    TC_TCLink.saveEMVHEXMapTag((CVM_REQUIRED_SIG))
                    response = TC_TCLink.processEMVTransaction(EMV_L2_KERNEL_VERSION, EMV_CLESS_KERNEL_VERSION)
                    log.log("PINBYPASS response: " + response)
                    break
            # force PIN bypass
            status = 0x9F41
            break

    # user pinbypass
    nextstep = -1
    if status == 0x9F41:
        nextstep = 2
        if cardState == EMV_CARD_INSERTED:
            processPinBypass()

    if cardState == EMV_CARD_INSERTED:
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

def OnlinePinInTemplateE6():

    global OnlineEncryptedPIN, OnlinePinKSN
    global HOST_ID, KEYSET_ID

    # If SRED is enabled and pan_cache_timeout is specified in the [vipa] section
    # of MAPP_VSD_SRED.CFG, the last cached PAN will be used for PIN Block
    # Formats that require PAN in case the PAN tag is not supplied.

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
    onlinepin_tag = [[(0xDF, 0xED, 0x0D), retrieve_pinblock]]
    onlinepin_tpl = (0xE0, onlinepin_tag)

    log.log('Online PIN: retrieving PINBLOCK ---------------------------------------------')
    log.log('HOST_ID=' + str(HOST_ID) + ', KEY_SLOT=' + str(KEYSET_ID))
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

    # obtain PIN Block: KSN and Encrypted data
    encryptedPIN = pin_tlv.getTag((0xDF, 0xED, 0x6C))
    if len(encryptedPIN):
        encryptedPIN = pin_tlv.getTag((0xDF, 0xED, 0x6C))[0].hex().upper()
        if len(encryptedPIN):
            OnlineEncryptedPIN = encryptedPIN
            ksn = pin_tlv.getTag((0xDF, 0xED, 0x03), TLVParser.CONVERT_HEX_STR)[0].upper()
            if len(ksn):
                # adjust KSN for IPP
                if HOST_ID == 0x05 and IPP_PIN_IS_ASCII:
                    OnlineEncryptedPIN = bytes.fromhex(encryptedPIN).decode('utf-8')
                    ksnStr = bytes.fromhex(ksn).decode('utf-8')
                    ksn = "{:F>20}".format(ksnStr)
                OnlinePinKSN = ksn
                log.logwarning("PIN=" + OnlineEncryptedPIN + "|" + OnlinePinKSN)
 
    # send transaction online
    return 6

def processPinBypass():
    log.log("USER REQUESTED PIN BYPASS -------------------------------")
    # indicate PIN bypass
    # conn.send([0xDE, 0xD5, 0xFF, 0x00])
    # status, buf, uns = getAnswer(stopOnErrors = False)

    # cancel active PIN verification process because of PIN bypass request
    # if status == 0x9000:
    pinbypass_tag = [[(0xC3), [0x0E]]]  # PIN Entry bypassed
    pinbypass_tpl = (0xE0, pinbypass_tag)

    log.log("CONTINUE TRANSACTION: GenAC1 ------------------------------------------------")

    conn.send([0xDE, 0xD2, 0x00, 0x00], pinbypass_tpl)
    status, buf, uns = getAnswer(stopOnErrors=False)

# ---------------------------------------------------------------------------- #
# MSR Workflow
# ---------------------------------------------------------------------------- #

def getMSRTrack2ServiceCode(tlv):
    track2 = tlv.getTag((0xDF, 0xDB, 0x06))[0].hex()
    if len(track2):
        worker = bytes.fromhex(track2).replace(b'\xaa', b'\x2a')
        track2Data = worker.decode('utf-8')
        m = re.search('^;([^=]+).([0-9]+).([^:]+)', track2Data)
        if len(m.groups()) >= 3:
            # set DDD format
            serviceCode = m.group(2)[4:7]
            if len(serviceCode):
                log.logwarning('SERVICE CODE:' + serviceCode)
                return serviceCode
    return ''

def setMSRTrack2DataAndExpiry(tlv, save=False):
    track2 = tlv.getTag((0xDF, 0xDB, 0x06))[0].hex()
    if len(track2):
        worker = bytes.fromhex(track2).replace(b'\xaa', b'\x2a')
        track2Data = worker.decode('utf-8')
        m = re.search('^;([^=]+).([0-9]+).([^:]+)', track2Data)
        if len(m.groups()) >= 3:
            # set YYMM to MMYY format
            expiry = m.group(2)[2:4]
            expiry += m.group(2)[:2]
            if len(expiry):
                if save == True:
                    TC_TCLink.saveMSRTrack2AndExpiry(track2, expiry)

# ---------------------------------------------------------------------------- #
# EMV Workflow
# ---------------------------------------------------------------------------- #

def setFirstGenContinueTransaction():

    continue_tran_tag = [
        [(0x9F, 0x02), AMOUNT],  # Amount
        [(0x9F, 0x03), AMTOTHER],  # Amount, other
        CURRENCY_CODE,
        COUNTRY_CODE,
        ACQUIRER_ID,  # TAG C2 acquirer id: ref. iccdata.dat
        [(0xDF, 0xA2, 0x18), [0x00]],  # Pin entry style
        AUTHRESPONSECODE,  # TAG 8A
        CONTINUE_REQUEST_AAC if (ISOFFLINE or ISBALANCEINQUIRY) else CONTINUE_REQUEST_TC,  # TAG C0 object decision: AAC=00, TC=01
        # quick chip as option for NO-PIN M/C Test Case MTIP-51.Test01.Scenario.01f
        QUICKCHIP_ENABLED if USE_QUICKCHIP_MODE else QUICKCHIP_DISABLED
    ]

    return (0xE0, continue_tran_tag)

def sendFirstGenAC(tlv, tid):
    global APPLICATION_LABEL, EMV_VERIFICATION
    global APPLICATION_SELECTION
    
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
        EMV_VERIFICATION = 0x00
        if tlv.tagCount(0x50) >= 1 and tlv.tagCount((0x9F, 0x06)) >= 1:
            # This is app selection stuff
            appLabels = tlv.getTag(0x50)
            appAIDs = tlv.getTag((0x9F, 0x06))
            
            if tlv.tagCount(0x50) == 1 and tlv.tagCount((0x9F, 0x06)) == 1:
                APPLICATION_SELECTION = 1
                
            # set AID
            log.logwarning("APPLICATION SELECTED:", APPLICATION_SELECTION)
            APPLICATION_AID   = [(0x9F, 0x06), bytearray(appAIDs[APPLICATION_SELECTION - 1])]
            APPLICATION_LABEL = [(0x50, ), bytearray(appLabels[APPLICATION_SELECTION - 1])]

            pan = tlv.getTag(0x5A)
            panBlacklisted = False
            if len(pan):
                panBlacklisted = TC_TransactionHelper.isPanBlackListed(conn, log, b2a_hex(pan[0]))

            # The terminal requests an ARQC in the 1st GENERATE AC Command.
            # The card returns an AAC to the 1st GENERATE AC Command.
            # The terminal does not send a 2nd GENERATE AC Command
            # C0 defines if the card is: 00=blacklisted, 01=non-blacklisted
            continue_tran_tag = [
                [(0x9F, 0x02), AMOUNTFORINQUIRY if ISBALANCEINQUIRY else AMOUNT],
                [(0x9F, 0x03), AMTOTHER],
                CURRENCY_CODE,
                COUNTRY_CODE,
                ACQUIRER_ID,                # TAG C2 acquirer id: ref. iccdata.dat
                AUTHRESPONSECODE,  # TAG 8A
                [(0xDF, 0xA2, 0x18), [0x00]],  # Pin entry style
                # note: this tag presence will cause DNA tests to fail - need to evaluate further when to include/exclude
                # DNA TC-37: terminal requests an ARQC in the 1st GenAC and TVR bit (Merchant Forced Transaction Online) Byte4/Bit4 is set to 1
                CONTINUE_REQUEST_AAC if (ISBALANCEINQUIRY or panBlacklisted) else CONTINUE_REQUEST_TC,  # TAG C0 object decision: AAC=00, TC=01
                # quick chip as option for NO-PIN M/C Test Case MTIP-51.Test01.Scenario.01f
                QUICKCHIP_ENABLED if USE_QUICKCHIP_MODE else QUICKCHIP_DISABLED
            ]
            if len(APPLICATION_AID) and len(APPLICATION_LABEL):
                continue_tran_tag.append(APPLICATION_AID)
                continue_tran_tag.append(APPLICATION_LABEL)
            continue_tpl = (0xE0, continue_tran_tag)
            message = str(appLabels[0], 'iso8859-1')
            if tlv.tagCount((0x9F, 0x12)):
                preferred = tlv.getTag((0x9F, 0x12))[0]
                message = message + '\n\n\t* PREFERRED NAME *\n\t' + str(preferred, 'iso8859-1')
                
            if APPLICATION_SELECTION_POS == False:
                displayMsg('* APPLICATION LABEL *\n\t' + message, 1)
                
            # save Application Label
            TC_TCLink.saveEMVASCIITag((APPLICATION_LABEL))
    else:
        continue_tpl = setFirstGenContinueTransaction()

    log.log("CONTINUE TRANSACTION: GenAC1 ------------------------------------------------")
    log.log("ACC REQUEST" if (ISOFFLINE or ISBALANCEINQUIRY) else "TC REQUESTED")

    # CONTINUE TRANSACTION [DE, D2]
    # P1, Bit 0 = 1 - Return after Cardholder verification EMV step.
    conn.send([0xDE, 0xD2, EMV_VERIFICATION, 0x00], continue_tpl)

    return continue_tpl

def sendSecondGenAC(continue_tpl):
    # If we get here, we received Online Request. Continue with positive response.
    log.log("CONTINUE TRANSACTION: GenAC2 ------------------------------------------------")

    # continue_tpl[1].append(ISSUER_AUTH_DATA)

    continue_trans_tag = [
        [(0x9F, 0x02), AMOUNTFORINQUIRY if ISBALANCEINQUIRY else AMOUNT],  # Amount
        [(0x9F, 0x03), AMTOTHER],
        CURRENCY_CODE,
        COUNTRY_CODE,
        ACQUIRER_ID,
        AUTHRESPONSECODE,
        [(0xDF, 0xA2, 0x18), [0x00]],  # PIN Entry style
        [(0xDF, 0xA3, 0x07), [0x03, 0xE8]],
        CONTINUE_REQUEST_AAC if (ISOFFLINE or ISBALANCEINQUIRY) else CONTINUE_REQUEST_TC,  # TAG C0 object decision: AAC=00, TC=01
        # THIS IS CAUSING THE WORKFLOW TO REPORT External Authenticate Command
        # ISSUER_AUTH_DATA
        # quick chip as option for NO-PIN M/C Test Case MTIP-51.Test01.Scenario.01f
        QUICKCHIP_ENABLED if USE_QUICKCHIP_MODE else QUICKCHIP_DISABLED
    ]
    continue2_tpl = (0xE0, continue_trans_tag)

    # CONTINUE TRANSACTION [DE, D2]
    # conn.send([0xDE, 0xD2, 0x01, 0x00], continue_tpl)
    conn.send([0xDE, 0xD2, 0x00, 0x00], continue2_tpl)

    # Ignore unsolicited automatically here
    status, buf, uns = getEMVAnswer(True)
    if status != 0x9000 and status != 0x9F22:
        log.logerr('Online Request has failed', hex(status))
        return -1

    return TLVParser(buf)

def processNoCashbackAllowed(tlv, tid):
    # expects 1st GENERATE AAC
    continue_tpl = sendFirstGenAC(tlv, tid)
    status, buf, uns = getEMVAnswer()
    # expects 2nd GENERATE AAC
    if status == 0x9000:
        sendSecondGenAC(continue_tpl)

def saveEMVHexMapTags(tlv):
    global AMTOTHER
    for tag in tlv:
        TC_TCLink.saveEMVHEXMapTag(tag)

    # TAG 9F03
    amountOther = hexlify(bytearray(AMTOTHER))
    TC_TCLink.saveEMVHEXMapTag(((0x9F, 0x03), amountOther.decode('utf-8').upper()), False)
    TC_TCLink.printEMVHexTags()

# ---------------------------------------------------------------------------- #
# Contactless Workflow
# ---------------------------------------------------------------------------- #

# Inits contactless device
def initContactless():
    # Get contactless count
    ctls = False
    # GET CONTACTLESS STATUS [C0, 00]
    conn.send([0xC0, 0x00, 0x00, 0x00])
    status, buf, uns = getAnswer(True, False)
    if status == 0x9000:
        cnt = TC_TransactionHelper.getDataField(buf, TC_TransactionHelper.CONVERT_INT)
        if cnt >= 1:
            log.log("Detected ", cnt, " contactless devices")
            ctls = True
            # OPEN AND INITIALIZE CONTACTLESS READER [C0, 01]
            conn.send([0xC0, 0x01, 0x00, 0x00])
            status, buf, uns = getAnswer()
            # GET CONTACTLESS STATUS [C0, 00]
            conn.send([0xC0, 0x00, 0x01, 0x00])
            status, buf, uns = getAnswer()
        else:
            log.log('No contactless devices found')
    else:
        log.log('No contactless driver found')
    return ctls

# Start Contactless Transaction
def startContactless(preferredAID=''):
    global AMOUNT, AMTOTHER, DATE, TIME
    
    # Start Contactless transaction
    start_ctls_tag = [
        [(0x9C), TRANSACTION_TYPE], # transaction type: for Sale+Cashback, ensure AID sets CashbackAllowed = 1
        [(0x9F, 0x02), AMOUNT],     # amount
        [(0x9F, 0x03), AMTOTHER],   # cashback
        [(0x9A), DATE],             # system date
        [(0x9F, 0x21), TIME],       # system time
        CURRENCY_CODE,              # currency code
        COUNTRY_CODE                # country code
    ]

    # to process ARQ in First Generate AC
    if ISBALANCEINQUIRY:
        start_ctls_tag.append([(0x95), b'\x00\x00\x00\x00\x00'])

    if TRANSACTION_TYPE == b'\x09':
        start_ctls_tag.append([(0xC1), b'\x01'])

    if len(preferredAID):
        # Preferred Application selected
        start_ctls_tag.append(preferredAID)
    else:
        # Application Identifier Terminal (AID)
        start_ctls_tag.append([(0x9F, 0x06), b'\x00\x01'])

    if EnableVASTransactions:
        vas = "{\"Preload_Configuration\":{\"Configuration_version\":\"1.0\",\"Terminal\":{\"Terminal_Capabilities\":{\"Capabilities\":\"Payment|VAS\"},\"PollTech\":\"AB\",\"PollTime\":15000,\"Source_List\":[{\"Source\":\"ApplePay\"},{\"Source\":\"AndroidPay\"}]}}}"
        start_ctls_tag.append([(0xDF, 0xB5, 0x01), vas.encode()])

    start_ctls_templ = (0xE0, start_ctls_tag)

    #NOTE: VIPA 6.8.2.17 is REQUIRED FOR VAS TRANSACTIONS
    
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
    conn.send([0xC0, 0xA0, CLS_TRANSACTIONS, 0x00], start_ctls_templ)

    log.log('Starting Contactless transaction')

# from a list of AIDS, a selection needs to be made to process Contactless workflows - a second tap is required
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

# Processes contactless continue
def processCtlsContinue():

    continue_ctls_tag = [ACQUIRER_ID]
    if ISBALANCEINQUIRY == True:
        continue_ctls_tag.append(CONTINUE_REQUEST_AAC)
    else:
        continue_ctls_tag.append(AUTHRESPONSECODE)
        continue_ctls_tag.append(CONTINUE_REQUEST_TC)

    continue_ctls_templ = (0xE0, continue_ctls_tag)

    log.log("CONTINUE CONTACTLESS TRANSACTION: GenAC1 -----------------------------")
    log.log("ACC REQUEST" if (ISOFFLINE or ISBALANCEINQUIRY) else "TC REQUESTED")

    # CONTINUE CONTACTLESS TRANSACTION [C0 A1]
    conn.send([0xC0, 0xA1, 0x00, 0x00], continue_ctls_templ)

    status, buf, uns = getAnswer()
    log.log('Waiting for Contactless Continue')
    while True:
        status, buf, uns = getAnswer(False)
        if uns:
            break
        log.logerr('Unexpected packet detected, ', TLVParser(buf))

# Cancel contactless reader
def cancelContactless():
    collision = False
    log.logerr("Stopping Contactless transaction")
    # CANCEL CONTACTLESS TRANSACTION [C0 C0]
    conn.send([0xC0, 0xC0, 0x00, 0x00])
    # capture possible DFC036
    # DFDF30=FA (unsolicited notification), DFC03B=0A (index in contl_hints.cfg)
    # 0A - Card collision (more than 1 card present in the field)
    status, buf, uns = getAnswer(False)
    tlv = TLVParser(buf)
    if tlv.tagCount((0xDF, 0xC0, 0x36)):
        outcome = tlv.getTag((0xDF, 0xC0, 0x36), TLVParser.CONVERT_HEX_STR)[0].upper()
        if outcome == '0A':
            log.logerr("CARD COLLISION - CANCELLING CONTACTLESS")
            collision = True

    # Ignore unsolicited as the answer WILL BE unsolicited...
    status, buf, uns = getAnswer(False)
    tlv = TLVParser(buf)
    if tlv.tagCount((0xDF, 0xDF, 0x30)):
        # response = tlv.getTag((0xdf,0xdf,0x30))[0]
        response = tlv.getTag((0xDF, 0xDF, 0x30), TLVParser.CONVERT_HEX_STR)[0].upper()
        if response == 'FB':
            log.log("Contactless transaction aborted successfully, no error")
            return False
        log.log("Contactless transaction aborted with error=0x" + response)

    # ctls still active
    return collision

# ---------------------------------------------------------------------------- #
# EMV Contact Workflow
# ---------------------------------------------------------------------------- #

def processEMV(tid):

    global AMOUNT, DATE, TIME, OFFLINERESPONSE, AMTOTHER, SIGN_RECEIPT, EMV_VERIFICATION, TRANSACTION_TYPE
    global OnlinePinContinueTPL, EMV_CLESS_KERNEL_VERSION
    global APPLICATION_AID, APPLICATION_LABEL, APPLICATION_SELECTION, APPLICATION_SELECTION_POS
    
    transaction_counter = b'\x00\x01'

    # Create localtag for transaction
    start_trans_tag = [
        [(0x9C), TRANSACTION_TYPE],
        [(0x9F, 0x02), AMOUNTFORINQUIRY if ISBALANCEINQUIRY else AMOUNT],
        [(0x9F, 0x03), AMTOTHER],
        [(0x9A), DATE],
        [(0x9F, 0x21), TIME],
        CURRENCY_CODE,
        COUNTRY_CODE,
        [(0x9F, 0x41), transaction_counter],                                    # transaction counter
        [(0xDF, 0xA2, 0x18), b'\x00'],                                          # pin entry style
        [(0xDF, 0xA2, 0x14), b'\x01'],                                          # Suppress Display
        [(0xDF, 0xA2, 0x04), b'\x00' if APPLICATION_SELECTION_POS else b'\x01'] # External Application Selection (POS)
    ]

    if ONLINE == 'y': 
        # When DFDF0D is not provided, transaction is performed offline.
        # When DFDF0D is provided with value 1, transaction is forced online and TVR byte 4 bit 4 is set.
        # When DFDF0D is provided with value 2, transaction is not forced online.
        # When DFDF0D is provided with value 3, transaction is forced online and TVR byte 4 bit 4 is not set.
        start_trans_tag.append([(0xDF, 0xDF, 0x0D), b'\x01'])
        log.log("START TRANSACTION: FORCED ONLINE ????????????????????????????????????")
        
    start_templ = (0xE0, start_trans_tag)

    # IPA5 transaction sequence counter
    transaction_counter = hexlify(bytearray(transaction_counter))
    TC_TCLink.saveEMVHEXMapTag(((0x9F, 0x41), transaction_counter.decode('utf-8').upper()), False)

    log.log("START TRANSACTION: ***************************************************************************************")

    # -------------------------------------------------------------------------
    # START TRANSACTION [DE D1]
    conn.send([0xDE, 0xD1, 0x00, 0x00], start_templ)

    # set default state
    APPLICATION_SELECTION = -1

    while True:
        # sleep(1)
        # conn.send([0xD0, 0xFF, 0x00, 0x00])
        status, buf, uns = getEMVAnswer()
        if status != 0x9000:
            if status == 0x9F28:
                log.logerr("TECHNICAL FALLBACK")
                displayMsg(DM_9F28, 3)
                return processMagstripeFallback(tid)
            else:
                if status == 0x9F25:
                    displayMsg(DM_9F25, 2)

                if status == 0x9F42:
                    displayMsg(DM_9F42, 2)
                    processNoCashbackAllowed(TLVParser(buf), tid)

                if TRANSACTION_TYPE != b'\x09':
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

            # AID Selection Prompt
            if tlv.tagCount(0xE2) and tlv.tagCount(0x50) > 1 and tlv.tagCount((0x9F, 0x06)) > 1:
                if APPLICATION_SELECTION_POS == True:
                    # has operator made a choice already?
                    if APPLICATION_SELECTION != -1:
                        log.logwarning('POS DECISION MADE =============================================================')
                        applicationSelectionWithChoice()
                        continue
                    log.logwarning('POS DECISION REQUIRED =============================================================')
                    AbortTransaction()
                    APPLICATION_SELECTION = TC_TransactionHelper.ApplicationSelection(conn)
                    log.log("USER SELECTED:", APPLICATION_SELECTION)
                    if APPLICATION_SELECTION == -1:
                        return -1
                    
                    # save selected application
                    appAIDs = tlv.getTag((0x9F, 0x06))  
                    appLabels = tlv.getTag(0x50)
                    if len(appAIDs) and len(appLabels):
                        APPLICATION_AID   = [(0x9F, 0x06), bytearray(appAIDs[APPLICATION_SELECTION - 1])]
                        APPLICATION_LABEL = [(0x50, ), bytearray(appLabels[APPLICATION_SELECTION - 1])]

                    #ResetDevice(0x00)
                    
                    # change app selection request
                    #start_trans_tag.remove(start_trans_tag[-1])
                    #start_trans_tag.append([(0xDF,0xA2,0x04), b'\x01'])
                    
                    # START TRANSACTION [DE D1]
                    conn.send([0xDE, 0xD1, 0x00, 0x00], start_templ)
                else:
                    applicationSelection(tlv)
                    log.logwarning('TERMINAL DECISION MADE =============================================================')

                # continue with transaction after application selected
                continue

            break

    # Let's check VSP
    tlv = TLVParser(buf)
    TC_TransactionHelper.vspDecrypt(tlv, tid, log)
    TC_TransactionHelper.displayEncryptedTrack(tlv, log)
    TC_TransactionHelper.displayHMACPAN(tlv, log)

    # Check for Contact EMV Capture
    # print(">>> EMV Data 1 ff7f", tlv.tagCount((0xFF,0x7F)))
    TC_TCLink.saveCardData(tlv)
    print(">> before continue: ", str(tlv))

    # save miscellaneous tags
    saveEMVHexMapTags(tlv)

    # -------------------------------------------------------------------------
    # 1st Generation AC
    continue_tpl = sendFirstGenAC(tlv, tid)

    # Template E6 requests for PIN, so allow Template E4 to just submit the transaction (without collecting PIN again)
    hasPINEntry = False
    pinTryCounter = 0x00
    bypassRequested = False

    while True:
        # process response
        status, buf, uns = getEMVAnswer()

        if status != 0x9000:
            log.logerr('Transaction terminated with status ', hex(status))
            # Terminal declines when a card replies with a TC (Approve) in response to an ARQC (go online) request in 1st GenAC (DNA)
            if EMV_VERIFICATION == 0x00:
                displayMsg("DECLINED: OFFLINE", 2)
            return -1

        tlv = TLVParser(buf)

        if uns and status == 0x9000:
            # print(tlv)
            # device has entered a wait state
            if tlv.tagCount(0xE6):
                message = tlv.getTag((0xC4))
                if len(message):
                    message = str(message[0], 'iso8859-1')
                    log.log(message)
                pinTryCounter = tlv.getTag((0xC5))[0]
                hasPINEntry = performUserPINEntry()
                bypassRequested = False if hasPINEntry else True

                # let device proceed to next step
                continue

            else:
                # PIN Entry Bypass - unsolicited packet in format: [01 40 09 E6 05 C3 01 0E C4 00 90 00 33]
                if hasPINEntry or buf[0][0] == 0xE6:
                    # check for user bypassing PIN entry: <YELLOW> key
                    if tlv.tagCount(0xE0):
                        keypress = tlv.getTag((0xDF, 0xA2, 0x05))
                        if len(keypress) and keypress[0][0] == 0x08:
                            hasPINEntry = False
                            bypassRequested = True
                            log.logwarning("PIN ENTRY HAS BEEN BYPASSED")
                            # VERIFY PIN [DE D5]
                            conn.send([0xDE, 0xD5, 0xFF, 0x01])
                            # Wait for confirmation, then break to wait for response
                            status, buf, uns = getAnswer(stopOnErrors=False)
                            continue
                    elif buf[0][2] == 0xC3:
                        tranStatus = buf[0][4]
                        if tranStatus == 0x0E:
                            hasPINEntry = False
                            log.logwarning("PIN ENTRY HAS BEEN BYPASSED")
                else:
                    log.log('Ignoring unsolicited packet ', tlv)
                continue
        else:
            print(">> after continue first pass: ", str(tlv))

            # validate this is necessary: tags missing 8A and 9F27 in card log
            if tlv.tagCount(0xE0):
                if ISOFFLINE:
                    TC_TCLink.saveEMVData(tlv, 0xE0, ISCASHBACK)

                if tlv.tagCount((0x9F, 0x34)) >= 1:

                    cvm_value = TC_TransactionHelper.getCVMResult(tlv)
                    # NOT AN EROR, JUST EASIER TO FIND IN THE TERMINAL OUTPUT
                    log.logerr('CVM REQUESTED _______:', cvm_value)
                    print('')
 
                    # if cvm_value == "ONLINE PIN":
                    #   return OnlinePinTransaction(tlv, EMV_CARD_INSERTED, continue_tpl)

                    if cvm_value == "SIGNATURE":
                        SIGN_RECEIPT = True


            if tlv.tagCount(0xE2):
                #TC_TransactionHelper.vspDecrypt(tlv, tid, log)
                #TC_TransactionHelper.displayEncryptedTrack(tlv, log)
                #TC_TransactionHelper.displayHMACPAN(tlv, log)
                TC_TCLink.saveEMVData(tlv, 0xE3, ISCASHBACK, ISBLINDREFUND)
                        
            if tlv.tagCount(0xE4):

                TC_TCLink.saveEMVData(tlv, 0xE4, ISCASHBACK)

                # Card Source
                entryMode_value = TC_TransactionHelper.reportCardSource(tlv, log)

                if EMV_CLESS_KERNEL_VERSION == '':
                    EMV_CLESS_KERNEL_VERSION = TC_TransactionHelper.GetEMVContactlessKernelVersion(conn, tlv, entryMode_value)
                    
                # check Terminal Capabilities reports correctly - CONTACTLESS WORKFLOW
                TC_TransactionHelper.reportTerminalCapabilities(tlv, log)

                cvm_value = TC_TransactionHelper.getCVMResult(tlv)

                # NOT AN EROR, JUST EASIER TO FIND IN THE TERMINAL OUTPUT
                log.logerr('CVM REQUESTED _______:', cvm_value)
                print('')
                 
                # TVR Status
                TC_TransactionHelper.checkTVRStatus(tlv, log)
                      
                # if cvm_value == "ONLINE PIN":
                #    hasPINEntry = getOnlinePIN(tlv)
                #    if hasPINEntry:
                #         # send to process online PIN entry
                #        response = TC_TCLink.processPINTransaction(OnlineEncryptedPIN, OnlinePinKSN)
                #        log.log("PIN response: "+ response)
                #        displayMsg(response.upper(), 3)
                #        return -1

                # review: should we always send the transaction online?
                # DNA: requires 2nd GENERATE AC decline (AAC)
                # if args.online == "y" and cvm_value == "ONLINE PIN":
                if cvm_value == "ONLINE PIN":
                    if hasPINEntry == True:
                        # expect Template E6 already collected PIN: retrieve PIN KSN/ENCRYPTED DATA
                        OnlinePinInTemplateE6()
                        # save continue tpl in case of PIN retry
                        OnlinePinContinueTPL = continue_tpl

                        break

                    # request PIN from user
                    if bypassRequested == False:
                        return OnlinePinTransaction(tlv, EMV_CARD_INSERTED, continue_tpl)

                # check for OFFLINE PIN ENTRY: KSN/ENCRYPTED DATA PAIR not to be extracted since PIN is OFFLINE verified
                if "ENCRYPTED" in cvm_value or "PLAIN PIN" in cvm_value:
                    hasPINEntry = False

                if cvm_value == "SIGNATURE":
                    SIGN_RECEIPT = True

                # if cvm_value == "PLAIN PIN":
                # verify PIN entry
                # verifyOfflinePIN(pinTryCounter)
                # set 2nd GENERATE AAC request
                # if ISBALANCEINQUIRY == False:
                # set2ndGenACC(continue_tpl)

                break

            if tlv.tagCount(0xE3):
                if ISBLINDREFUND:
                    log.log("Transaction is blind refund")
                    TC_TCLink.saveCardData(tlv)
                    TC_TCLink.saveEMVData(tlv, 0xE3, ISCASHBACK, True)
                    # dynamic validation for MasterCard above floor limit and CVM
                    if tlv.tagCount((0x84)):
                        if  tlv.tagCount((0x95)):
                            TC_TCLink.setTVRStates(tlv.getTag((0x84))[0], tlv.getTag((0x95))[0])
                        if tlv.tagCount((0x9F, 0x34)):
                            TC_TCLink.setCVMLimitStates(tlv.getTag((0x84))[0], tlv.getTag((0x9F, 0x34))[0])
                    return 8
                else:
                    log.log("Transaction approved offline")
                    displayMsg("APPROVED", 2)
                    return -1

            if tlv.tagCount(0xE5):
                log.logerr('TRANSACTION DECLINED OFFLINE')
                displayMsg("DECLINED: OFFLINE", 2)
                
                # TVR Status
                TC_TransactionHelper.checkTVRStatus(tlv, log)
                 
                # M-TIP10 Test 01 Scenario 01f – Offline decline : Analyst wants receipt to be provided for the test case
                if tlv.tagCount((0x5F, 0x20)):
                    cardholderName = tlv.getTag((0x5F, 0x20))[0]
                    if len(cardholderName):
                        cardholderName = str(cardholderName, 'iso8859-1')
                        if cardholderName == "MTIP10 MCD 13A":
                            TC_TCLink.saveCardData(tlv)
                            TC_TCLink.saveEMVData(tlv, 0xE5, ISCASHBACK)
                            return 2
                return -1

            break

    # -------------------------------------------------------------------------
    # 2nd Generation AC
    tlv = sendSecondGenAC(continue_tpl)

    if tlv == -1:
        return -1

    if tlv.tagCount(0xE3):
        log.log("Transaction approved offline")
        # Check for Contact EMV Capture
        # print(">>> EMV Data 2 ff7f", tlv.tagCount((0xFF,0x7F)))
        TC_TCLink.saveCardData(tlv)
        displayMsg("APPROVED", 2)
        return -1

    if tlv.tagCount(0xE4) and ISOFFLINE:  # Online Action Required

        log.log("CONTINUE TRANSACTION: GenAC2 [TEMPLATE E4] ----------------------------------")

        TC_TCLink.saveEMVData(tlv, 0xE4, ISCASHBACK)

        # -------------------------------------------------------------------------
        # 2nd GenAC
        tlv = sendSecondGenAC(continue_tpl)

        if tlv == -1:
            return -1

        # retrieve PIN entered
        if hasPINEntry == True:
            # expect Template E6 already collected PIN: retrieve PIN KSN/ENCRYPTED DATA
            OnlinePinInTemplateE6()
            # save continue tpl in case of PIN retry
            OnlinePinContinueTPL = continue_tpl

        if tlv.tagCount(0xE4):
            TC_TCLink.saveEMVData(tlv, 0xE4, ISCASHBACK)
        elif tlv.tagCount(0xE5):
            TC_TCLink.saveEMVData(tlv, 0xE5, ISCASHBACK)
            
        return 3

    if tlv.tagCount(0xE5):
        log.logerr('TRANSACTION DECLINED OFFLINE')

        # Check for Contact EMV Capture
        # print(">>> EMV Data 3 ff7f", tlv.tagCount((0xFF,0x7F)))

        if hasPINEntry == True:
            # expect Template E6 already collected PIN: retrieve PIN KSN/ENCRYPTED DATA
            if len(OnlineEncryptedPIN) == 0 or len(OnlinePinKSN) == 0:
                # save EMV Tags
                TC_TCLink.saveEMVData(tlv, 0xE5, ISCASHBACK)
                OnlinePinInTemplateE6()
            # save continue tpl in case of PIN retry
            OnlinePinContinueTPL = continue_tpl

        TC_TCLink.saveCardData(tlv)

        return 6 if hasPINEntry else 2

    # Check for Contact EMV Capture
    # print(">>> EMV Data 4 ff7f", tlv.tagCount((0xFF,0x7F)))
    TC_TCLink.saveCardData(tlv)

    return 3

# Prompts for card insertion
def promptForCard():
    # DISPLAY [D2, 01]
    conn.send([0xD2, 0x01, 0x0D, 0x01])
    status, buf, uns = getAnswer()

# Prompts for card reinsertion
def promptForReinsertCard():
    # DISPLAY [D2, 01]
    conn.send([0xD2, 0x01, 0x14, 0x01])
    status, buf, uns = getAnswer()

def promptForSwipeCard():
    # DISPLAY [D2, 01]
    conn.send([0xD2, 0x01, 0x2B, 0x01])
    status, buf, uns = getAnswer()

def TransactionVoid():
    global EMV_L2_KERNEL_VERSION, EMV_CLESS_KERNEL_VERSION
    
    response = TC_TCLink.processEMVTransaction(EMV_L2_KERNEL_VERSION, EMV_CLESS_KERNEL_VERSION)
    ### not getting 'approved'
    if response == "accepted":
        sleep(3)
        count = 1
        # wait for status=='approved'
        print('\nWaiting for approval...')
        while(count <= 5):
            count = count + 1
            response = TC_TCLink.getStatusResponse()
            print('STATUS  :', response)
            if response == "approved":
                count = 10
            else:
                sleep(1)
                 
        if response == "approved":
            log.log('VOID request approved')
            TC_TCLink.showTCLinkResponse()

# ---------------------------------------------------------------------------- #
# Main function
# ---------------------------------------------------------------------------- #

def processTransaction(args):

    global AMOUNT, DATE, TIME, ONLINE, OFFLINERESPONSE, AMTOTHER, DEVICE_UNATTENDED
    global TRANSACTION_TYPE, ISBALANCEINQUIRY, FALLBACK_TYPE, ISVOIDTRANSACTION
    global OnlineEncryptedPIN, OnlinePinKSN, OnlinePinContinueTPL
    global EMV_L2_KERNEL_VERSION, EMV_KERNEL_CHECKSUM,  EMV_CLESS_KERNEL_VERSION

    TC_TCLink.SetProperties(args, log, TRANSACTION_TYPE == b'\x09')

    if args.amtother != 0:
        AMOUNT = TC_TransactionHelper.bcd(args.amount + args.amtother, 6)
        AMTOTHER = TC_TransactionHelper.bcd(args.amtother, 6)
    else:
        AMOUNT = TC_TransactionHelper.bcd(args.amount, 6)

    now = datetime.datetime.now()
    DATE = TC_TransactionHelper.bcd(now.year % 100) + TC_TransactionHelper.bcd(now.month) + TC_TransactionHelper.bcd(now.day)
    TIME = TC_TransactionHelper.bcd(now.hour % 100) + TC_TransactionHelper.bcd(now.minute) + TC_TransactionHelper.bcd(now.second)
    # print("Amount", str(AMOUNT), "vs", str(b'\x00\x00\x00\x00\x01\x00'))
    # print("Date", str(DATE), "Time", str(TIME))

    if ISVOIDTRANSACTION:
        return TransactionVoid()

    # RESET DEVICE [D0, 00]
    tlv = ResetDevice()

    tid = tlv.getTag((0x9F, 0x1E))

    if len(tid):
        tid = str(tid[0], 'iso8859-1')
        TC_TCLink.setDeviceSerial(tid)
        log.log('Terminal TID:', tid)
    else:
        tid = ''
        log.logerr('Invalid TID (or cannot determine TID)!')

    deviceUnattended = tlv.getTag((0xDF, 0x0D))
    if len(deviceUnattended):
        deviceUnattended = str(deviceUnattended[0], 'iso8859-1')
        isUnattended = deviceUnattended.upper().find("UX")
        if isUnattended == 0:
            deviceUnattended = "y"
        else:
            deviceUnattended = "n"
        TC_TCLink.setDeviceUnattendedMode(deviceUnattended)
        log.log('DEVICE UNATTENDED:', deviceUnattended)
    else:
        deviceUnattended = ''
        log.logerr('Invalid DEVICE (or cannot determine TYPE)!')

    # KERNEL LAST 4 BYTES
    #log.log('BUF LEN =', len(buf[0]))
    EMV_KERNEL_CHECKSUM = TC_TransactionHelper.GetEMVKernelChecksum(conn)

    # SUMMARY REPORT
    print('')
    print('--------------------------------------------------')
    log.logerr('KERNEL CHECKSUM: ' + EMV_KERNEL_CHECKSUM)
    log.logerr('KERNEL EMV C-L2: ' + EMV_L2_KERNEL_VERSION)
    #log.logerr('TARGET CLES-AID: ' + aidValue)
    #log.logerr('KERNEL EMV CVER: ' + EMV_CLESS_KERNEL_VERSION)
    
    # DISPLAY [D2 01]
    conn.send([0xD2, 0x01, 0x01, 0x01])
    status, buf, uns = getAnswer()

    # CARD STATUS [D0 60]
    startMonitoringCardStatus()
    status, buf, uns = getAnswer(False)

    cardState = EMV_CARD_REMOVED
    if uns:
        # Check for insertion unsolicited message
        tlv = TLVParser(buf)
        if tlv.tagCount(0x48):
            cardState = EMVCardState(tlv)

    ctls = initContactless()
    if cardState != EMV_CARD_INSERTED:
        if ctls:
            startContactless()
            status, buf, uns = getAnswer()
        else:
            promptForCard()
        log.log('**** WAIT FOR CARD INSERTION / TAP / SWIPE ****')

        tranType = 0
        result = 0
        msrSwipeCount = 0
        ignoreSwipe = False

        while True:
            status, buf, uns = getAnswer(False, False)  # Get unsolicited ONLY
            if uns and status == 0x9000:
                # Check for insertion unsolicited message
                tlv = TLVParser(buf)

                if tlv.tagCount(0x48):
                    cardState = EMVCardState(tlv)
                    magState = MagstripeCardState(tlv)

                    # normal MSR workflow
                    if magState == MAGSTRIPE_CARD_SWIPE:
                        tlv = removeEMVCard()
                        if tlv.tagCount(0x48):
                            cardState = EMVCardState(tlv)
                            magState = MagstripeCardState(tlv)

                    # Ignore failed swipes
                    if ctls and (cardState == EMV_CARD_INSERTED or magState == MAGSTRIPE_TRACKS_AVAILABLE):
                        # Cancel Contactless first
                        collision = cancelContactless()
                        ctls = False
                        if collision == True:
                            buf = tlv = ''
                            continue

                    if cardState == EMV_CARD_INSERTED:
                        log.log("Card inserted, process EMV transaction!")
                        result = processEMV(tid)
                        if result == 5:  # msr fallback result
                            tranType = 2
                        elif result == 6:
                            tranType = 6
                        elif result == 8:
                            tranType = 8
                        else:
                            if result != -1:
                                tranType = 1
                            else:
                                tlv = getCardStatus()
                        break
                    else:
                        if cardState == ERROR_UNKNOWN_CARD:
                            log.log('Unknown card type ')
                            displayMsg("UNKNOWN CARD TYPE\n\tREMOVE AND RETRY", 2)
                            if msrSwipeCount == args.msrfallback:
                                log.log('Entering MSR Fallback')
                                msrSwipeCount = 1
                                processMagstripeFallback(tid)
                                tranType = 2
                                break
                            removeEMVCard()
                            promptForReinsertCard()
                            log.log('**** WAIT FOR CARD INSERTION / TAP / SWIPE ****')
                            msrSwipeCount += 1
                            continue
                    if not ignoreSwipe:
                        if magState == ERROR_UNKNOWN_CARD:
                            log.logerr('Swipe has failed, there are no tracks!')
                            continue
                        else:
                            if magState == MAGSTRIPE_TRACKS_AVAILABLE:
                                msrSwipeCount += 1
                                if msrSwipeCount > args.msrfallback or CardIsEMVCapable(tlv) == False:
                                    if msrSwipeCount > args.msrfallback:
                                        log.log('Entering MSR Fallback')
                                    TC_TransactionHelper.vspDecrypt(tlv, tid, log)
                                    if tlv.tagCount((0xDF, 0xDB, 0x06)):
                                        setMSRTrack2DataAndExpiry(tlv)
                                    tranType = 2
                                    break
                                else:
                                    log.log(f'Card swiped! {msrSwipeCount}/{args.msrfallback} until MSR fallback.')
                                    promptForReinsertCard()
                                    log.log('**** WAIT FOR CARD INSERTION / TAP / SWIPE ****')
                                    continue
                            else:
                                # consider this a possible EMV fallback scenario for Verifone ICC Testing
                                msrSwipeCount += 1
                                log.log(f'Card swiped! {msrSwipeCount}/{args.msrfallback} until MSR fallback.')
                                if msrSwipeCount == args.msrfallback:
                                    log.log('Entering MSR Fallback')
                                    promptForSwipeCard()
                                    log.log('**** WAIT FOR CARD SWIPE ****')
                                    processMagstripeFallback(tid)
                                    tranType = 2
                                    break
                                else:
                                    if TC_TransactionHelper.displayEncryptedTrack(tlv, log) == True:
                                        break
                                    else:
                                        promptForReinsertCard()
                                        log.log('**** WAIT FOR CARD INSERTION / TAP / SWIPE ****')

                    log.log("Waiting for next occurrance!")
                    continue

                # Check for unsolicited keyboard status
                if tlv.tagCount((0xDF, 0xA2, 0x05)):
                    kbd_tag_val = tlv.getTag((0xDF, 0xA2, 0x05), TLVParser.CONVERT_INT)[0]
                    log.log("Keyboard status, keypress ", hex(kbd_tag_val), 'h')
                    if kbd_tag_val == 27:
                        tranType = -1
                        break
                    continue

                if args.action != 'credit':
                    TC_TCLink.saveCardData(tlv)

                # TAG FF7F
                # vsdSREDTemplateDebugger(tlv, tid)

                # TEMPLATE E3: TRANSACTION APPROVED
                if tlv.tagCount(0xE3):  # E3 = transaction approved
                    log.log("Approved contactless EMV transaction!")
                    displayMsg("APPROVED", 2)

                    if args.action == 'credit':
                        tranType = 7
                        # dynamic validation for MasterCard CVM limit
                        if tlv.tagCount((0x84)) > 0 and tlv.tagCount((0x9F, 0x34)):
                            TC_TCLink.setCVMLimitStates(tlv.getTag((0x84))[0], tlv.getTag((0x9F, 0x34))[0])                        
                    else:
                        if args.action == 'credit2':
                            # dynamic validation for MasterCard CVM limit
                            if tlv.tagCount((0x84)) > 0 and tlv.tagCount((0x9F, 0x34)):
                                TC_TCLink.setCVMLimitStates(tlv.getTag((0x84))[0], tlv.getTag((0x9F, 0x34))[0])                        
                                
                        # todo: vsp decrypt!
                        TC_TransactionHelper.vspDecrypt(tlv, tid, log)
                        TC_TransactionHelper.displayEncryptedTrack(tlv, log)
                        TC_TransactionHelper.displayHMACPAN(tlv, log)
                        TC_TCLink.saveEMVData(tlv, 0xE3, ISCASHBACK, ISBLINDREFUND)
                        tranType = 4
                    break

                # TEMPLATE E4: ONLINE ACTION REQUIRED
                if tlv.tagCount(0xE4):

                    # Card Source
                    entryMode_value = TC_TransactionHelper.reportCardSource(tlv, log)
                    
                    if EMV_CLESS_KERNEL_VERSION == '':
                        EMV_CLESS_KERNEL_VERSION = TC_TransactionHelper.GetEMVContactlessKernelVersion(conn, tlv, entryMode_value)

                    # Terminal Capabilites
                    TC_TransactionHelper.reportTerminalCapabilities(tlv, log)

                    # dynamic validation for MasterCard above floor limit and CVM
                    if tlv.tagCount((0x84)):
                        if  tlv.tagCount((0x95)):
                            TC_TCLink.setTVRStates(tlv.getTag((0x84))[0], tlv.getTag((0x95))[0])
                        if tlv.tagCount((0x9F, 0x34)):
                            TC_TCLink.setCVMLimitStates(tlv.getTag((0x84))[0], tlv.getTag((0x9F, 0x34))[0])

                    # cryptogram reset for TRACK2DATA with non-compliant length
                    #if tlv.tagCount((0x84)) and tlv.tagCount((0x57)) and tlv.tagCount((0x9F, 0x27)):
                    #    TC_TCLink.SetTrack2NonCompliantLength(tlv.getTag((0x84))[0], tlv.getTag((0x57))[0], tlv.getTag((0x9F, 0x27))[0])
                    
                    TC_TransactionHelper.vspDecrypt(tlv, tid, log)
                    TC_TransactionHelper.displayEncryptedTrack(tlv, log)
                    TC_TransactionHelper.displayHMACPAN(tlv, log)
                    TC_TCLink.saveEMVData(tlv, 0xE4, ISCASHBACK)

                    # ADDED 08312020. Extract 9f34 tag (online pin entry required?)
                    if tlv.tagCount((0x9F, 0x34)) >= 1:
                        cvm_result = tlv.getTag((0x9F, 0x34))[0]
                        encrypted_pin = cvm_result[0] & 0x0F
                        # Indicate CVM type
                        switcher = {
                            1: "PLAIN PIN BY ICC",
                            2: "ONLINE PIN",
                            14: "SIGNATURE",
                            15: "NO CVM PERFORMED"
                        }
                        cvm_value = switcher.get(encrypted_pin, "UNKNOWN CVM TYPE")

                        # NOT AN EROR, JUST EASIER TO FIND IN THE TERMINAL OUTPUT
                        log.logerr('CVM REQUESTED _______:', cvm_value)
                        print('')
                         
                        # VISA: In the instance of a cash or cashback transaction an online PIN is always required,
                        # regardless of what CVM method might be indicated in the CTQ (tag '9F6C')
                        if TRANSACTION_TYPE == b'\x09' and cvm_value != "ONLINE PIN":
                            encrypted_pin = 0x02

                        if encrypted_pin == 0x02:
                            return OnlinePinTransaction(tlv, cardState, setFirstGenContinueTransaction())

                        # Plaintext PIN verification performed by ICC
                        #if encrypted_pin == 0x01:
                        #    getPINEntry(tlv)

                    # VAS Processing
                    if tlv.tagCount((0xC6)):
                        walletId = TC_TransactionHelper.displayWalletId(tlv)
                        if len(walletId):
                            log.logwarning('VAS WALLET ID:', bytes.fromhex(walletId).decode('utf-8'))

                    if cardState != EMV_CARD_INSERTED:
                        processCtlsContinue()
                        tranType = 5

                    break

                # TEMPLATE E5: TRANSACTION DECLINED
                if tlv.tagCount(0xE5):
                    log.logerr('TRANSACTION DECLINED OFFLINE')
                    tranType = 4
                    TC_TCLink.saveEMVData(tlv, 0xE5, ISCASHBACK)
                    # E2E CL 17: requires TO GO ONLINE
                    # performCleanup()
                    # return
                    break

                # TEMPLATE E7: CONTACTLESS MAGSTRIPE TRANSACTION
                if tlv.tagCount(0xE7):
                    # Card Source
                    entryMode_value = TC_TransactionHelper.reportCardSource(tlv, log)
                    
                    if EMV_CLESS_KERNEL_VERSION == '':
                        EMV_CLESS_KERNEL_VERSION = TC_TransactionHelper.GetEMVContactlessKernelVersion(conn, tlv, entryMode_value)
                        
                    # Terminal Capabilites
                    TC_TransactionHelper.reportTerminalCapabilities(tlv, log)
                    TC_TransactionHelper.vspDecrypt(tlv, tid, log)
                    TC_TransactionHelper.displayEncryptedTrack(tlv, log)
                    TC_TransactionHelper.displayHMACPAN(tlv, log)
                    # Contactless MSD does not include EMV Payload
                    # TC_TCLink.saveEMVData(tlv, 0xE7, ISCASHBACK)
                    processCtlsContinue()
                    tranType = 3
                    break

                if status != 0x9000:
                    if status == 0x9F33:  # Fallforward to ICC / Swipe
                        promptForCard()
                        # No need to exit the loop - swipe is not active now
                        continue
                    else:
                        if status == 0x9F34:  # Fallforward to ICC only
                            promptForCard()
                            # No need to exit the loop - ctls is not active now, but we have to disable swipes
                            ignoreSwipe = True
                            continue

            # check for termination state

            # 0x9f28: unsupported card
            # 0x9f35: consumer CVM - contactless workflow
            if status == 0x9F28 or status == 0x9F35:
                if status == 0x9F28:
                    displayMsg(DM_9F28, 3)
                    if deviceUnattended == "n":
                        cancelContactless()
                        ctls = False
                        # throw away the buffer
                        buf = tlv = ''
                        # re-arm device without exiting
                        continue

                if status == 0x9F35:
                    displayMsg(DM_9F35, 3)
                    # re-arm device without exiting
                    continue
                log.log('*** COMPLETED WITH EXPECTED ERROR IN STATE ***')
                log.logerr('Pinpad reported error ', hex(status))
                performCleanup()
                return

            if status == 0x9F31:
                displayMsg(DM_9F31, 3)
                log.log('*** COMPLETED WITH EXPECTED ERROR IN STATE ***')
                log.logerr('Pinpad reported error ', hex(status))
                performCleanup()
                return

            if status == 0x9F33:
                tlv = TLVParser(buf)
                # TEMPLATE A5: CUSTOM TEMPLATE
                if tlv.tagCount(0xA5):
                    if tlv.tagCount((0x9F, 0x38)):
                        pdol_value = tlv.getTag((0x9F, 0x38))[0]
                        if len(pdol_value) > 2:
                            if pdol_value[0] == 0x9F:
                                switcher = {
                                    0x02: "Amount Authorized:",
                                    0x35: "TERMINAL TYPE:",
                                    0x66: "Terminal Transaction Qualifier (TTQ):",
                                    0x6E: "CLESS ENHANCED CAPABILITIES:",
                                }
                                pdol_type_value = switcher.get(pdol_value[1], "UNKNOWN PDOL TYPE")
                                log.logerr(pdol_type_value, pdol_value[2], "bytes")

                                if len(pdol_value) > 5:
                                    if pdol_value[3] == 0x9F:
                                        switcher = {
                                            0x02: "Amount Authorized:",
                                            0x35: "TERMINAL TYPE:",
                                            0x66: "Terminal Transaction Qualifier (TTQ):",
                                            0x6E: "CLESS ENHANCED CAPABILITIES:",
                                        }
                                        pdol_type_value = switcher.get(pdol_value[4], "UNKNOWN PDOL TYPE")
                                        log.logerr(pdol_type_value, pdol_value[5], "bytes")
                    performCleanup()
                return

            if status == 0x9F34:
                # Test Case Requires to Indicate a DECLINE state for the transaction
                displayMsg("DECLINED: OFFLINE", 5)

                # displayMsg(DM_9F34)
                log.log('*** COMPLETED WITH EXPECTED ERROR IN STATE ***')
                log.logerr('Pinpad reported error ', hex(status))

                # Restart request for card insertion only
                promptForCard()
                # No need to exit the loop - ctls is not active now, but we have to disable swipes
                ignoreSwipe = True
                continue

            if status == 0x9F41:
                displayMsg(DM_9F41, 3)
                processPinBypass()
                continue

            if tlv.tagCount(0x6F):
                preferredAid = processCtlsAIDList(tlv)
                if len(preferredAid):
                    startContactless(preferredAid)
                    status, buf, uns = getAnswer()
                    continue
                break

            log.logerr("Invalid packet detected, ignoring it!")
            print('E4: ', tlv.tagCount(0xE4))
            print(tlv)
    else:
        log.log("Card already inserted!")
        result = processEMV(tid)
        if args.online == "y":
            return
        tranType = 1

    #
    # After loop - DON'T ENTER WHEN PREVIOUS RESULTS INDICATE FAILURE
    #
    if result != -1:

        if tranType == 1:
            # If card still inserted, ask for removal
            cardState = getEMVCardStatus()
            if cardState == EMV_CARD_INSERTED:
                removeEMVCard()
        else:
            # Delay for some CLess messaging to complete; may be able to replace with loop awaiting card removed from field
            sleep(0.500)

        if tranType != 6 and args.action != 'credit':
            # Check for Card data
            TC_TCLink.saveCardData(tlv)

            # MSR workflow now asks for Credit/Debit selection (Debit collects PIN)
            if tranType != 2 and tranType != -1:
                # DISPLAY [D2 01] - Processing Transaction
                conn.send([0xD2, 0x01, 0x02, 0x01])
                sleep(3)

        if EMV_CLESS_KERNEL_VERSION == '':
            # Card Source
            entryMode_value = TC_TransactionHelper.reportCardSource(tlv, log)
            EMV_CLESS_KERNEL_VERSION = TC_TransactionHelper.GetEMVContactlessKernelVersion(conn, tlv, entryMode_value)
                        
        # Check for Contact EMV Capture
        # print(">>> tranType", tranType, "ff7f", tlv.tagCount((0xFF,0x7F)))
        # print(">>> tranType", tranType)
        response = ""
        if tranType == 1:
            response = TC_TCLink.processEMVTransaction(EMV_L2_KERNEL_VERSION, EMV_CLESS_KERNEL_VERSION)
        # Check for swipe
        elif tranType == 2:
            TC_TransactionHelper.displayEncryptedTrack(tlv, log)
            choice = TC_TransactionHelper.selectCreditOrDebit(conn, log)
            # refunds don't need pin block
            if choice == 2 and args.action != "credit":
                getPINEntry(tlv)
            # DISPLAY [D2 01] - Processing Transaction
            conn.send([0xD2, 0x01, 0x02, 0x01])
            response = TC_TCLink.processMSRTransaction(OnlineEncryptedPIN, OnlinePinKSN, args.action == 'credit', ISBLINDREFUND)
        # Check for contactless magstripe
        elif tranType == 3:
            response = TC_TCLink.processCLessMagstripeTransaction()
        # Check for Offline approve/decline
        elif tranType == 4:  # Should tags be captured for an Offline Decline case and sent to TCLink?
            response = TC_TCLink.processEMVTransaction(EMV_L2_KERNEL_VERSION, EMV_CLESS_KERNEL_VERSION, ISBLINDREFUND)
        # Check for CLess
        elif tranType == 5:
            response = TC_TCLink.processEMVTransaction(EMV_L2_KERNEL_VERSION, EMV_CLESS_KERNEL_VERSION, ISBLINDREFUND)
        # online PIN transaction
        elif tranType == 6:
            log.log('PROCESS ONLINE PIN TRANSACTION: -------------------------------------------------------------------')
            response = TC_TCLink.processPINTransaction(OnlineEncryptedPIN, OnlinePinKSN, EMV_L2_KERNEL_VERSION, EMV_CLESS_KERNEL_VERSION)
            log.log("PIN response: " + response)
            # should there be a retry after first pin entry failure?
            if response != "approved":
                errorType = "declined"
                nextstep = 0
                if response == "error":
                    errorType = TC_TCLink.getErrorType()
                    if errorType == "failtoprocess":
                        log.logerr("PROCESSOR: failed to process")
                        removeEMVCard()
                        response = '' 
                if errorType == "declined":
                    responseCode = TC_TCLink.getResponseCode()
                    # FISERV RESPONSE CODE: 117 - Incorrect PIN or PIN length error
                    if len(responseCode):
                        code = int(responseCode)
                        if code == ONLINEPIN_INVALID:
                            displayMsg('Invalid PIN:' + response, 3)
                            nextstep = OnlinePinTransaction(tlv, cardState, OnlinePinContinueTPL, 1, True)
                            if nextstep == -1:
                                response = ''
                    removeEMVCard()
                elif errorType == "cantconnect":
                    removeEMVCard()
            else:
                # delay to complete
                removeEMVCard()
        # CREDIT transaction
        elif tranType == 7:
            log.log('PROCESS CREDIT TRANSACTION: ------------------------------------------------------------------------')
            response = TC_TCLink.processCreditTransaction()
        elif tranType == 8:
            response = TC_TCLink.processEMVTransaction(EMV_L2_KERNEL_VERSION, EMV_CLESS_KERNEL_VERSION, True)
            removeEMVCard()
        # offline transaction
        elif tranType == 0:
            response = "OFFLINE: " + OFFLINERESPONSE

        declinetype = ""

        # Transaction Status
        if len(response):
            if response == "decline":
                declinetype = TC_TCLink.getDeclineType()
                if len(declinetype):
                    response = response + ": " + declinetype
            else:
                if response == "error":
                    response = "decline: error"
            displayMsg(response.upper(), 3)
            if response == 'approved' and SIGN_RECEIPT:
                displayMsg("PLEASE SIGN RECEIPT", 3)
    else:
        if EMVCardState(tlv) == EMV_CARD_INSERTED:
            removeEMVCard()

    #
    # RETURN DEVICE TO USABLE STATE BEFORE EXITING
    #
    stopMonitoringKeyPresses()

    # DISPLAY [D2 01]
    conn.send([0xD2, 0x01, 0x01, 0x00])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer()

# -------------------------------------------------------------------------------------- #
# MAIN APPLICATION ENTRY POINT
# -------------------------------------------------------------------------------------- #
if __name__ == '__main__':

    log = getSyslog()

    log.logerr("TESTHARNESS v" + VERSION_LBL)

    arg = util.get_argparser()
    arg.add_argument('--custid', dest='custid', default='1152701', type=int, 
                     help='TC CustID for transaction')
    arg.add_argument('--password', dest='password', default='testipa1', 
                     help='TC Password for transaction')
    arg.add_argument('--action', dest='action', default='sale', 
                     help='TC Action for transaction')
    arg.add_argument('--amount', dest='amount', default='100', type=int, 
                     help='Amount of transaction')
    arg.add_argument('--amtother', dest='amtother', default='0', type=int, 
                     help='Amount other')
    arg.add_argument('--operator', dest='operator', default=getpass.getuser(), 
                     help='Operator for transaction')
    arg.add_argument('--transid', dest='transid', default='', 
                     help='Transaction Identifier') 
    arg.add_argument('--lanenumber', dest='lanenumber', default=None, 
                     help='Lane Number for transaction')
    arg.add_argument('--online', dest='online', default=None, 
                     help='Online PIN')
    arg.add_argument('--pinattempts', dest='pinattempts', default=1, type=int, 
                     help='Online PIN attempts allowed')
    arg.add_argument('--msrfallback', dest='msrfallback', default=3, type=int,
                     help='Insert attempts allowed before MSR fallback')
    arg.add_argument('--device_pinpad_capable', dest='device_pinpad_capable', default='n', 
                     help='UNATTENDED device pin capability only')
    arg.add_argument('--validateAmount', dest='validateAmount', default='y', 
                     help='Ask user to validate amount')
    arg.add_argument('--partialauth', dest='partialauth', default='n', 
                     help='Partial authorization')
    arg.add_argument('--transaction_menu', dest='transaction_menu', default='y', 
                     help='display transaction menu')

    args = util.parse_args()

    # instantiate connection to device
    conn = connection.Connection()
    startConnection()

    # selection transaction type from menu
    if args.transaction_menu == 'y':
        transactionType = selectTransaction()
        displayMsg('\tTRANSACTION TYPE\r\n\t' + TransactionType[transactionType][1])
        TRANSACTION_TYPE = TransactionType[transactionType][0]
    else:
        transactionType = 1

    if args.online == 'y':
        online_confirm = input('Transaction should be forced online (y/n):')
        if online_confirm == 'y':
            ONLINE = 'y'

    if TRANSACTION_TYPE == b'\x20':
        ISBLINDREFUND = True if transactionType == 7 else False
        transId = TC_TCLink.getTransIdFromFile()
        if len(transId) == 0:
            log.logerr('CANNOT ISSUE REFUND: NO TRANSACTION HAS YET BEEN RUN.')
            exit(0)
        log.logwarning('LAST TRANSACTION ID: ' + transId)
        if ISBLINDREFUND:
            args.action = "credit2"
        else:
            args.action = "credit"
    # set balance inquiry in launch.json
    elif TRANSACTION_TYPE == b'\x30':
        args.action = "verify"
        ISBALANCEINQUIRY = True
        log.log('BALANCE INQUIRY? - TRANSACTION TYPE=' + hexlify(TRANSACTION_TYPE).decode('ascii'))
    elif TRANSACTION_TYPE == b'\x09':
        ISCASHBACK = True
        
    # VOID TRANSACTION
    if args.action == 'void' or args.action == 'void2':
        transId = TC_TCLink.getTransIdFromFile()
        if len(transId) == 0:
            transId = args.transid
            TC_TCLink.setTransIdFromArgument(transId)
            if len(transId) == 0:
                log.logerr('CANNOT ISSUE REFUND: NO TRANSACTION HAS YET BEEN RUN.')
                exit(0)
        log.logwarning('VOID TRANSACTION WITH TRANSID:', transId)
        ISVOIDTRANSACTION = True

    # Transaction Amount
    if args.validateAmount == 'y':
        TransactionAmount = input("ENTER AMOUNT (" + str(args.amount) + "): ")

        if len(TransactionAmount) > 1 or ISBALANCEINQUIRY:
            value = int(TransactionAmount)
            if value > 0 or ISBALANCEINQUIRY:
                args.amount = value

    # check amount > cashback
    if transactionType == 3:
        amount = int(args.amount)
        cashback = int(args.amtother)
        if cashback >= amount:
            log.logerr("AMOUNT-CASHBACK CANNOT BE 0 or LESS", args.amtother)
            exit(0)

    if args.amount != 0:
        log.log('TRANSACTION AMOUNT: $', args.amount)
        if transactionType == 3:
            log.log('CASHBACK AMOUNT   : $', args.amtother)

    if args.amtother != 0:
        log.log('TRANSACTION AMOUNT OTHER: $', args.amtother)
        log.log('TOTAL TRANSACTION AMOUNT: $', args.amount + args.amtother)

    log.logwarning(
        'TRANSACTION TYPE  : "' + TransactionType[transactionType][1] +
        '", CODE=' + hexlify(TRANSACTION_TYPE).decode('ascii') +
        ', ACTION=' + args.action.upper()
    )
    sleep(2)

    # print('custid=' + str(args.custid) + ",password=" + str(args.password) + ",action=" + str(args.action))
    # print('DEVICE PINPAD CAPABLE=' + str(args.device_pinpad_capable))

    utility.register_testharness_script(partial(processTransaction, args))
    while True:
        utility.do_testharness()
        exit(0)
        TransactionAmount = input("Ctrl+C to quit or ENTER NEW AMOUNT (" + str(args.amount) + "): ")
        if len(TransactionAmount) > 1 or ISBALANCEINQUIRY:
            value = int(TransactionAmount)
            if value > 0 or ISBALANCEINQUIRY:
                args.amount = value
                
# -------------------------------------------------------------------------------------- #
