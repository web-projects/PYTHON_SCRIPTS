#!/usr/bin/python3
'''
Created on 03-12-2020

@authors: Jon_B
'''

from testharness import *
from testharness.syslog import getSyslog
from binascii import hexlify, unhexlify, b2a_hex
from testharness.tlvparser import TLVParser


def showTVRFailures(log, index, bit):

    switcher = {
        5: (showTVRByte5Failures, (log, bit)),
        4: (showTVRByte4Failures, (log, bit)),
        3: (showTVRByte3Failures, (log, bit)),
        2: (showTVRByte2Failures, (log, bit)),
        1: (showTVRByte1Failures, (log, bit))
    }
    func, args = switcher.get(index, (None, None))
    if func is not None:
      return func(*args)


def showTVRByte1Failures(log, bit):
    #log.log('TVR-Byte1-BIT =', bit)
    # Indicate TVR type
    switcher = {
        8: "Offline data authentication was not performed",
        7: "SDA failed",
        6: "ICC data missing",
        5: "Card appears on terminal exception file",
        4: "DDA failed",
        3: "CDA failed",
        2: "RFU",
        1: "RFU"
    }
    tvr_value = switcher.get(bit, "UNKNOWN TVR TYPE")
    
    log.logerr('         [' + tvr_value + ']')

def showTVRByte2Failures(log, bit):
    #log.log('TVR-Byte2-BIT =', bit)
    # Indicate TVR type
    switcher = {
        8: "ICC and terminal have different application versions",
        7: "Expired application",
        6: "Application not yet effective",
        5: "Requested service not allowed for card product",
        4: "New card",
        3: "RFU",
        2: "RFU",
        1: "RFU"
    }
    tvr_value = switcher.get(bit, "UNKNOWN TVR TYPE")
    
    log.logerr('         [' + tvr_value + ']')


def showTVRByte3Failures(log, bit):
    #log.log('TVR-Byte3-BIT =', bit)
    # Indicate TVR type
    switcher = {
        8: "Cardholder verification was not successful",
        7: "Unrecognized CVM",
        6: "PIN Try Limit exceeded",
        5: "PIN entry required and PIN pad not present or not working",
        4: "PIN entry required, PIN pad present, but PIN was not entered",
        3: "Online PIN entered",
        2: "RFU",
        1: "RFU"
    }
    tvr_value = switcher.get(bit, "UNKNOWN TVR TYPE")
    
    log.logerr('         [' + tvr_value + ']')


def showTVRByte4Failures(log, bit):
    #log.log('TVR-Byte4-BIT =', bit)
    # Indicate TVR type
    switcher = {
        8: "Transaction exceeds floor limit",
        7: "Lower consecutive offline limit exceeded",
        6: "Upper consecutive offline limit exceeded",
        5: "Transaction selected randomly for online processing",
        4: "Merchant forced transaction online",
        3: "RFU",
        2: "RFU",
        1: "RFU"
    }
    tvr_value = switcher.get(bit, "UNKNOWN TVR TYPE")
    
    log.logerr('         [' + tvr_value + ']')


def showTVRByte5Failures(log, bit):
    #log.log('TVR-Byte4-BIT =', bit)
    # Indicate TVR type
    switcher = {
        8: "Default TDOL used",
        7: "Issuer authentication failed",
        6: "Script processing failed before final GENERATE AC",
        5: "Script processing failed after final GENERATE AC",
        4: "RFU",
        3: "RFU",
        2: "RFU",
        1: "RFU"
    }
    tvr_value = switcher.get(bit, "UNKNOWN TVR TYPE")
    
    log.logerr('         [' + tvr_value + ']')
    
def reportCardSource(tlv, log):
  if tlv.tagCount((0x9F, 0x39)):
    entryMode = tlv.getTag((0x9F, 0x39))
    if len(entryMode):
       entryMode = ord(entryMode[0])
       #log.logerr('MODE=', entryMode)
       switcher = {
             91: "CLESS-MSR",
             90: "MSR",
              8: "Amex Wallet",
              7: "Contactless-ICR",
              5: "Contact-ICR",
              4: "OCR",
              3: "Barcode",
              1: "Manual",
              0: "Unspecified"
          }
       entryMode_value = switcher.get(entryMode, "UNKNOWN ENTRY MODE")
       print('')
       log.warning('ENTRY MODE:', entryMode_value)
       if entryMode == 7:
        if tlv.tagCount((0xC6)):
          vasTag = tlv.getTag((0xC6), TLVParser.CONVERT_HEX_STR)[0].upper()
          #log.log('VAS TAG:', vasTag)
          vasIdIndex = vasTag.find('DFC601')
          if vasIdIndex != -1:
            dataLen = int(vasTag[vasIdIndex+6:vasIdIndex+8], 16) * 2
            vasId = vasTag[vasIdIndex+8:vasIdIndex+8+dataLen]
            # vasId = NULL
            if len(vasId) == 8 and vasId == '6E756C6C':
              log.log('CARDSOURCE: CARD')
            else:
              log.log('CARDSOURCE: APP')
        else:
          log.warning('CARSOURECE: CARD')
  else:
    log.warning('ENTRY MODE: UNKNOWN')