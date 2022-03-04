#!/usr/bin/python3
'''
Created on 03-12-2020

@authors: Jon_B
'''

from testharness import *
from testharness.syslog import getSyslog
from binascii import hexlify, unhexlify, b2a_hex
from testharness.tlvparser import TLVParser
from testharness.utility import check_status_error

# Contactless Kernel Version
AID_LISTS = {
  'firstdatarapidconnect': {
    'amexCardAidList': [
      'A00000002501', 'AK'
    ],
    'discoverCardAidList': [
      'A0000001523010', 'DK' 
    ],
    'jcbCardAidList': [
      'A0000000651010', 'KK' 
    ],    
    'masterCardAidList': [
      'A0000000041010', 'MK' 
    ],
    'visaCardAidList': [
      'A0000000031010', 'VK' 
    ]
  }
}

#----------------------------------------------------------
# EMV Contactless Kernel Version
#----------------------------------------------------------

def GetEMVKernelChecksum(conn):
    kernelChecksum = 'NO KERNEL CHECKSUM'
    ''' 
    Main EMV parameters which affect kernel configuration checksum:
        1. Terminal Type (9F35)
        2. Terminal Capabilities (9F33)
        3. Terminal Additional Capabilities (9F40)
    '''
    # VISA AID
    # a000000003101001
    # a0 00 00 00 03 10 10
    aid = b'\xa0\x00\x00\x00\x03\x10\x10'
    #c_tag = tagStorage()
    #c_tag.store((0x9F, 0x06), aid)
    #c_tag.store((0x9F, 0x06, 0x0E), aid)
    tags = [
      [(0x9F, 0x06), aid ]
    ]
    e0_templ = ( 0xE0, tags )

    #Send Get EMV Hash Values
    ''' iccdata.dat and icckeys.key required with RELEASE firmware '''
    conn.send([0xDE, 0x01, 0x00, 0x00], e0_templ)

    status, buf, uns = conn.receive()
    check_status_error( status )

    if len(buf[0]) > 24:
      kernelChecksum = buf[0][24:].decode('utf-8').upper()
    return kernelChecksum
    

def GetEMVL2KernelVersion(tlv):
  kernelValue = 'NOT FOUND'
  l2kernelTag  = tlv.getTag((0xDF, 0x81, 0x06))
  index = 0
  for value in l2kernelTag:
    if value == b'ADK_EMV_CT_Kern':
      kernelTagValue  = tlv.getTag((0xDF, 0x81, 0x07))[index]
      kernelValue = str(kernelTagValue, 'iso8859-1')
      #log.log('L2 KERNEL:', kernelValue)
      break;
    index = index + 1
  return kernelValue


def GetEMVClessKernelIdentifier(aid):
    emvClessKernel = ''
    
    for cardBrand in AID_LISTS['firstdatarapidconnect']:
      #log.log('---------------------------', cardBrand)
      #for aidValue in AID_LISTS['firstdatarapidconnect'][cardBrand]:
      #  log.log('CLESS AID:', aidValue)
      aidValue = AID_LISTS['firstdatarapidconnect'][cardBrand]
      #log.log('CLESS AID:', aidValue[0])
      #log.log('CLESS KER:', aidValue[1])
      if aidValue[0] == aid:
        emvClessKernel = aidValue[1]
        break
    return emvClessKernel


def PrintAllMEVClessKernelValues(tlv):
    if tlv.tagCount(0xE1) and tlv.tagCount((0xdf,0xc0,0x28)):
        emvVerTag = tlv.getTag((0xdf,0xc0,0x28), TLVParser.CONVERT_STR)[0]
        #log.logerr('CONTACTLESS KERNEL VERSION: ', emvVerTag)
        for line in emvVerTag.split(';'):
          tokens = line.split()
          print(tokens)


def GetEMVClessKernelVersion(conn, aidValue):
    clessKernelVersion = '0488'

    clessKernelId = GetEMVClessKernelIdentifier(aidValue)
    if len(clessKernelId):
      # contactless status
      # P1
      # 00 - ((no bits) and P2 = 00) Retrieve additional device count
      # Bit 0 - Retrieve device firmware revision (tag DFC022)
      # Bit 1 - Retrieve device name (tag DFC020)
      # Bit 2 - Retrieve device serial number (tag DFC021)
      # Bit 3 - Retrieve device initialization status (tag DFC023)
      # Bit 4 - Retrieve device display capabilities (tag DFC024)
      # Bit 5 - Retrieve device sound capabilities (tag DFC025)
      # Bit 6 - Retrieve device LED capabilities (tag DFC026)
      # Bit 7 - Retrieve additional Kernel information (tag DFC028)
      P1 = 0x80
      # P2
      # Bit 0 - Retrieve L1 driver version (tag DFC029)
      P2 = 0x00
      print('')
      #log.warning('contactless status __________________________________________')
      conn.send([0xC0, 0x00, P1, P2])
      status, buf, uns = conn.receive()
      check_status_error( status )
      
      tlv = TLVParser(buf)
      
      # contactless EMV Kernel values - all supported card brands
      #PrintAllMEVClessKernelValues(tlv)

      if tlv.tagCount(0xE1) and tlv.tagCount((0xdf, 0xc0, 0x28)):
          emvVerTag = tlv.getTag((0xdf, 0xc0, 0x28), TLVParser.CONVERT_STR)[0]
          #log.logerr('CONTACTLESS KERNEL VERSION: ', emvVerTag)
          for line in emvVerTag.split(';'):
            if line.startswith(clessKernelId):
              clessKernelVersion = line
              #log.log('CLESS-KERNEL VER:', clessKernelVersion)
              break;
              
    return clessKernelVersion


def GetEMVContactlessKernelVersion(conn, tlv, entryMode_value):
    if entryMode_value == 'CLESS-MSR' or entryMode_value == 'Contactless-ICR':
        aidTagValue = tlv.getTag((0x9F, 0x06))[0].hex().upper()
        if len(aidTagValue):
            return GetEMVClessKernelVersion(conn, aidTagValue)  


#----------------------------------------------------------
# TVR Processing
#----------------------------------------------------------

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


def reportTerminalCapabilities(tlv, log):
  appLabel = ''
  if (tlv.tagCount(0x50)):
    appLabel = tlv.getTag(0x50)[0]
    if len(appLabel):
      log.warning('APPLICATION:', appLabel.decode('iso8859-1'))
    
  if tlv.tagCount((0x9F,0x33)):
    termCaps = tlv.getTag((0x9F, 0x33))
    if (len(termCaps)):
        log.logerr("TERMINAL CAPABILITIES:", hexlify(termCaps[0]).decode('ascii')) 
  else:
    log.warning('TERMINAL CAPABILITIES: [UNKNOWN]')
    
  return appLabel


def reportCardSource(tlv, log):
  if tlv.tagCount((0x9F,0x39)):
    entryMode = tlv.getTag((0x9F, 0x39))
    if len(entryMode):
       entryMode = ord(entryMode[0])
       #log.logerr('POS MODE=', entryMode)
       switcher = {
            145: "CLESS-MSR",           # HEX 0x91
            144: "MSR",                 # HEX 0x90
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
       log.warning('POS ENTRY MODE ______:', entryMode_value)
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
    log.warning('POS ENTRY MODE: TAG 9F39 MISSING FROM TLV')


def getValue(tag, value):
    tagValue = ''
    tagIndex = value.find(tag)
    if tagIndex != -1:
        offset = len(tag) + 2
        dataLen = int(value[tagIndex+2:tagIndex+4], 16) * 2
        tagValue = value[tagIndex+offset:tagIndex+offset+dataLen]
    return tagValue
