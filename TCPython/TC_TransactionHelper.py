#!/usr/bin/python3
'''
Created on 03-12-2020

@authors: Jon_Bianco
'''

from testharness import *
from TC_testharness import *
import TC_testharness.utility as util
from functools import partial
from TC_testharness.tlvparser import TLVParser, tagStorage
from TC_testharness.tlvparser import TLVPrepare
from sys import exit
from testharness.syslog import getSyslog
from TC_testharness.syslog import getSyslog
from TC_testharness.utility import getch, kbhit, check_status_error
import testharness.fileops as fops
import TC_TCLink
from binascii import hexlify, unhexlify, b2a_hex
from time import sleep
import sys
import getpass
import datetime
import traceback
import os.path
from os import path

# pip install pyperclip
import pyperclip

# ---------------------------------------------------------------------------- #
# GLOBALS
# ---------------------------------------------------------------------------- #

CONVERT_INT = 1
CONVERT_STRING = 2

# ---------------------------------------------------------------------------- #
# Contactless Kernel Version
# ---------------------------------------------------------------------------- #
AID_LISTS = {
  'firstdatarapidconnect': {
    'amexCardAidList': [
      'A00000002501', 'AK'
    ],
    'chinaUnionPayCardAidList': [
      'A0000003330101', 'CK'
    ],    
    'discoverCardAidList': [
      'A0000001523010', 'DK'
    ],
    'discoverUSCreditCardAidList': [
      'A0000001524010', 'DK' 
    ],    
    'jcbCardAidList': [
      'A0000000651010', 'JK' 
    ],
    'masterCardAidList': [
      'A0000000041010', 'MK' 
    ],
    'maestroCardAidList': [
        'A0000000043060', 'MK'
    ],
    'USmaestroCardAidList': [
        'A0000000042203', 'MK'
    ],
       'visaCardAidList': [
      'A0000000031010', 'VK' 
    ],
      'visaUSDebitCardAidList': [
      'A0000000980840', 'VK' 
    ]
  }
}

# ---------------------------------------------------------------------------- #
# UTILTIES
# ---------------------------------------------------------------------------- #

# Terminal exception file for pan - ENSURE FILE IS UNIX LINE TERMINATED (EOL)
# PAN.TXT file is used as an exception file(blacklist) to specify primary account numbers. It is used at
# the terminal risk management stage and if a match is found in the exception file, bit 5 in byte1 of
# TVR is set indicating ???card number appears on hotlist???.
# There must be a pan number on each line of file. There might be whitespaces around it. Pan should
# not contain any non-digit character and its length should be between 7-19.
def getFile(conn, log, filename , local_fn):
    try:
        log.log("GETFILE:", filename)
        progress = partial(util.display_console_progress_bar, util.get_terminal_width())
        fops.getfile(conn, log, filename, local_fn, progress)
        return True
    except Exception:
        log.logerr("FILE NOT FOUND:", filename)
        return False

def loadBlackList(conn, log):
    fileName = "PAN.txt"
    # is there a local copy already
    fileExists = path.exists(fileName)
    # if not, get it from the device
    if fileExists == False:
        fileExists = getFile(conn, log, fileName, fileName)
    if fileExists == True:
        data = open(fileName, "rb").read()
        if len(data):
            return data.split()
    return ""

def isPanBlackListed(conn, log, pan):
    BLACK_LIST = loadBlackList(conn, log)
    if len(BLACK_LIST):
        for value in BLACK_LIST:
            # PAN FORMAT: ######aaaaaa####
            if value[0:6] == pan[0:6] and value[12:16] == pan[12:16]:
                return True
    return False

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
        #print('idx0 type ', type(idx0[0]))
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

def vspIsEncrypted(tlv, log):
    vsp_tag_val = tlv.getTag((0xDF,0xDF,0x6F))
    if len(vsp_tag_val):
        vsp_tag_val = tlv.getTag((0xDF,0xDF,0x6F), TLVParser.CONVERT_INT)[0]
        if vsp_tag_val != 0:
            log.log('VSP Encryption detected, flag ', hex(vsp_tag_val), '!')
            return True
        else:
            log.log('VSP present, but transaction unencrypted!')
    return False

def displayEncryptedTrack(tlv, log):
    if tlv.tagCount((0xFF, 0x7F)):
        sRED = tlv.getTag((0xFF, 0x7F), TLVParser.CONVERT_HEX_STR)[0].upper()
        if len(sRED):
            #log.log("SRED DATA: " + sRED)
            
            ksn  = ''
            iv   = ''
            vipa = ''
            
            # TAG DFDF11
            ksnIndex = sRED.find('DFDF11')
            if ksnIndex != -1:
                dataLen = int(sRED[ksnIndex+6:ksnIndex+8], 16) * 2
                ksn = sRED[ksnIndex+8:ksnIndex+8+dataLen]
                if len(ksn):
                    log.log('KSN : ' + ksn)
    
            # TAG DFDF12
            ivIndex = sRED.find('DFDF12')
            if ivIndex != -1:
                dataLen = int(sRED[ivIndex+6:ivIndex+8], 16) * 2
                iv = sRED[ivIndex+8:ivIndex+8+dataLen]
                if len(iv):
                    log.log('IV  : ' + iv)
            
            encryptedTrackIndex = sRED.find('DFDF10')
            if encryptedTrackIndex != -1:
                #log.log("IDX=" + sRED[encryptedTrackIndex+6:encryptedTrackIndex+8])
                temp = sRED[encryptedTrackIndex+6:encryptedTrackIndex+8]
                #log.log("LENGTH=" + temp)
                dataLen = int(sRED[encryptedTrackIndex+6:encryptedTrackIndex+8], 16) * 2
                encryptedData = sRED[encryptedTrackIndex+8:encryptedTrackIndex+8+dataLen]
                if len(encryptedData):
                    vipa = encryptedData
                    log.logwarning("VIPA: [" + str(dataLen) + " CHARS IN LENGTH]")
                    #log.log(encryptedData)
                    
                    # TVP|ksn:|iv:|vipa:|
                    if len(ksn) and len(iv) and len(vipa):
                        tclinkStr = 'TVP|ksn:' + ksn + '|iv:' + iv + '|vipa:' + vipa 
                        log.logerr(tclinkStr)
                        pyperclip.copy(tclinkStr)
                            
                    return True
    return False

# Decrypts VSP - encrypted data
def vspDecrypt(tlv, tid, log):
    if not vspIsEncrypted(tlv, log):
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
            if len(pan_d): 
                log.log('Decrypted PAN: ', pan_d)
            if len(expiry_d): 
                log.log('Decrypted Expiry: ', expiry_d)
            if len(t2eq_d): 
                log.log('Decrypted T2EQ: ', t2eq_d)
            if len(t2dd_d): 
                log.log('Decrypted T2DD: ', t2dd_d)
            if len(t1dd_d): 
                log.log('Decrypted T1DD: ', t1dd_d)
            return True
        except exceptions.logicalException as exc:
            log.logerr('Cannot decrypt! Error ', exc)
            log.logerr('Cannot decrypt!')
            return False
    else:
        log.log('Magstripe')
        t1 = tlv.getTag((0x5F, 0x21), TLVParser.CONVERT_STR)
        if len(t1): t1 = t1[0]
        else: t1 = ''
        t2 = tlv.getTag((0x5F, 0x22), TLVParser.CONVERT_STR)
        if len(t2): t2 = t2[0]
        else: t2 = ''
        if len(pan): 
            log.log('PAN: ', pan)
        if len(expiry): 
            log.log('Expiry: ', expiry)
        if len(t1): 
            log.log('T1: ', t1)
        if len(t2): 
            log.log('T2: ', t2)

        try:
            pan_d, expiry_d, t1_d, t2_d = enc.decrypt(pan, expiry, t1, t2, eparms)
            if len(pan_d): 
                log.log('Decrypted PAN: ', pan_d)
            if len(expiry_d): 
                log.log('Decrypted Expiry: ', expiry_d)
            if len(t1_d): 
                log.log('Decrypted T1: ', t1_d)
            if len(t2_d): 
                log.log('Decrypted T2: ', t2_d)
            return True
        except exceptions.logicalException as exc:
            log.logerr('Cannot decrypt! Error ', exc)
            log.logerr('Cannot decrypt!')
            return False

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

def getValue(tag, value):
    tagValue = ''
    tagIndex = value.find(tag)
    if tagIndex != -1:
        offset = len(tag) + 2
        dataLen = int(value[tagIndex+2:tagIndex+4], 16) * 2
        tagValue = value[tagIndex+offset:tagIndex+offset+dataLen]
    return tagValue

def displayEncryptedTrack(tlv, log):
    
  if (tlv.tagCount((0xFF, 0x7F))):
    sRED = tlv.getTag((0xFF, 0x7F), TLVParser.CONVERT_HEX_STR)[0].upper()
    if len(sRED):
        log.log("SRED DATA: " + sRED)
        
        ksn  = ''
        iv   = ''
        vipa = ''
        
        # TAG DFDF11
        ksnIndex = sRED.find('DFDF11')
        if ksnIndex != -1:
            dataLen = int(sRED[ksnIndex+6:ksnIndex+8], 16) * 2
            ksn = sRED[ksnIndex+8:ksnIndex+8+dataLen]
            if len(ksn):
                log.log('KSN: ' + ksn)
        
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

def displayHMACPAN(tlv, log):
    sRedTag = tlv.tagCount((0xFF, 0x7C))
    if sRedTag > 0:
        sRED = tlv.getTag((0xFF, 0x7C), TLVParser.CONVERT_HEX_STR)[0].upper()
        if len(sRED):
            # TAG DF837F
            panIndex = sRED.find('DF837F')
            if panIndex != -1:
                dataLen = int(sRED[panIndex+6:panIndex+8], 16) * 2
                panData = sRED[panIndex+8:panIndex+8+dataLen]
                if len(panData):
                    log.logwarning("HMAC PAN:", panData)  
            else:
                log.logwarning("HMAC PAN: TAG NOT FOUND")
    else:
        log.logwarning("HMAC PAN: NOT REPORTED")

def displayWalletId(tlv):
    walletId = ''
    if tlv.tagCount((0xC6)):
        # TAG DFC601 - wallet identifier
        vas = tlv.getTag((0xC6), TLVParser.CONVERT_HEX_STR)[0].upper()
        vasIndex = vas.find('DFC601')
        if vasIndex != -1:
            dataLen = int(vas[vasIndex+6:vasIndex+8], 16) * 2
            walletId = vas[vasIndex+8:vasIndex+8+dataLen]
    return walletId

def reportTerminalCapabilities(tlv, log):
    if tlv.tagCount((0x9F, 0x33)):
        termCaps = tlv.getTag((0x9F, 0x33))
        if len(termCaps):
            log.logwarning("TERMINAL CAPABILITIES:", hexlify(termCaps[0]).decode('ascii'))
    else:
        log.logwarning('TERMINAL CAPABILITIES: [UNKNOWN]')

def reportCardSource(tlv, log):

  entryMode_value = 'UNKNOWN'
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
       log.logwarning('POS ENTRY MODE ______:', entryMode_value)
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
          log.logwarning('CARSOURECE: CARD')
  else:
    log.logwarning('POS ENTRY MODE: [UNKNOWN]')

  return entryMode_value

#--------------------------------------------------------------------------------------------------------------------#
# EMV Contactless Kernel Version
#--------------------------------------------------------------------------------------------------------------------#

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

def checkTVRStatus(tlv, log):
    found = False
    tvr = tlv.getTag((0x95))
    if len(tvr):
      found = True
      print('')
      log.logwarning('TVR (TAG 95):', hexlify(tvr[0]))
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
            showTVRFailures(log, index, n + 1)
        index = index + 1
      print('')
    return found

#----------------------------------------------------------
# APPLICATION SELECTION
#----------------------------------------------------------

LIST_STYLE_SCROLL = 0x00
LIST_STYLE_NUMERIC = 0x01
LIST_STYLE_SCROLL_CIRCULAR = 0x02

def ApplicationSelection(conn):
  selected = -1
  # Set data for request '''
  c_tag = tagStorage()
  c_tag.store( (0xDF, 0xA2, 0x12), LIST_STYLE_SCROLL )
  #BUG: Unable to push the direct string not bytearray
  c_tag.store((0xDF,0xA2,0x11), 'PROCESS AS')
  c_tag.store((0xDF, 0xA2, 0x02), 0x01)
  c_tag.store((0xDF, 0xA2, 0x03), b'1. Credit')
  c_tag.store((0xDF, 0xA2, 0x02), 0x02)
  c_tag.store((0xDF, 0xA2, 0x03), b'2. Debit')
  # clear key inhibited
  #c_tag.store((0xDF, 0xA2, 0x15), 0x00)

  # Send request
  conn.send([0xD2, 0x03, 0x00, 0x01] , c_tag.get())
  
  is_unsolicited = True
  
  # wait to response
  while is_unsolicited:
      status, buf, is_unsolicited = conn.receive()
      check_status_error( status )

  tlv = TLVParser(buf)
  if tlv.tagCount((0xDF, 0xA2, 0x02)) == 1:
    selection = tlv.getTag((0xDF, 0xA2, 0x02))[0]
    selected = selection[0]

  return selected

def selectCreditOrDebit(conn, log):

    SelectionType = {1: ["DEBIT"], 2: ["CREDIT"]}
    # Set data for request
    c_tag = tagStorage()
    c_tag.store((0xDF, 0xA2, 0x12), LIST_STYLE_SCROLL)
    # BUG: Unable to push the direct string not bytearray
    c_tag.store((0xDF, 0xA2, 0x11), "PROCESS AS")

    i = 1
    for key in SelectionType:
        c_tag.store((0xDF, 0xA2, 0x02), i)
        c_tag.store((0xDF, 0xA2, 0x03), SelectionType[key][0])
        i = i + 1

    # Send request
    conn.send([0xD2, 0x03, 0x00, 0x01], c_tag.get())
    
    # Wait for selection
    status, buf, uns = conn.receive()

    # default to SALE
    choice = 1

    # if user cancels, default to 'CREDIT' Transaction
    if status == 0x9F43:
        return choice

    if status == 0x9000:
        tlv = TLVParser(buf)
        if tlv.tagCount((0xDF, 0xA2, 0x02)) == 1:
            selection = tlv.getTag((0xDF, 0xA2, 0x02))[0]
            choice = selection[0]
    log.logwarning("PROCESS AS:", SelectionType[choice][0])
    
    return choice

# -------------------------------------------------------------------------------------- #
