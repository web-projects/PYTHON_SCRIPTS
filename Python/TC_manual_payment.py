#!/usr/bin/python3
'''
Created on 08-05-2020

@authors: Jon Bianco
'''

from testharness import *
from testharness.tlvparser import TLVParser,TLVPrepare, tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from binascii import hexlify, unhexlify

# pip install pyperclip
import pyperclip

# P1
ENTRY_PAN            = 1 << 0
ENTRY_EXPIRY_DATE    = 1 << 1
ENTRY_EFFECTIVE_DATE = 1 << 2
ENTRY_CVV2           = 1 << 3

#P2
BACKLIGHT            = 1 << 0
TRACK2_FORMAT        = 1 << 1

#dfdf12-08-c0fb7bb50f745928
#dfdf11-0a-ffff9876543211000b51
#dfdf10-20-329856c51a2d7df3edb864a0c50a3fa2fd97c189c613d0d93b411e9bf152e9e7dfdb0f0400000000

# -----------------------------------------------------------------
# SRED ENCRYPTED TAG FF7F
#
# DFDF10: ENCRYPTED DATA 
# DFDF11: KSN
# DFDF12: IV DATA
#
# TVP|ksn:|iv:|vipa:|
#
# -----------------------------------------------------------------
def tclinkFormat(tlv):
  tokenTemplate = tlv.getTag((0xFF, 0x7F))
  if len(tokenTemplate) == 0:
    return

  parsed = TLVPrepare().parse_received_data(tokenTemplate[0] + b'\x90\x00')
  #log.log("STEP1:", parsed)
  tokenTLV = TLVParser(parsed)
  # TAG DFDF10
  encryptedData = tokenTLV.getTag((0xDF, 0xDF, 0x10))[0]
  #log.log("DFDF10:", encryptedData)
  if len(encryptedData) == 0:
      log.logerr("Encrypted DATA not found")
      return
  vipa = hexlify(encryptedData).decode('ascii').upper()
  #log.log("DFDF10:", vipa)
  # TAG DFDF11
  ksnData = tokenTLV.getTag((0xDF, 0xDF, 0x11))[0]
  #log.log("DFDF11:", ksnData)
  if len(ksnData) == 0:
      log.logerr("KSN not found")
      return
  ksn = hexlify(ksnData).decode('ascii').upper()
  #log.log("DFDF11:", ksn)
  # TAG DFDF12
  ivData = tokenTLV.getTag((0xDF, 0xDF, 0x12))[0]
  #log.log("DFDF12:", ivData)
  if len(ivData) == 0:
      log.logerr("IV not found")
      return
  iv = hexlify(ivData).decode('ascii').upper()
  #log.log("DFDF12:", iv)
  
  # TVP|ksn:|iv:|vipa:|
  tclinkStr = 'TVP|ksn:' + ksn + '|iv:' + iv + '|vipa:' + vipa 
  log.logerr(tclinkStr)
  pyperclip.copy(tclinkStr)


# formats track2 as ;PAN=expire;cvv
def formatTrack2(tlv):
    tag_pan_data = (0xDF, 0xDB, 0x01)
    tag_cvv_data = (0xDF, 0xDB, 0x02)
    tag_expiry_data = (0xDF, 0xDB, 0x03)
   
    if (tlv.tagCount(tag_pan_data) == 1):
        pan_val = tlv.getTag(tag_pan_data)[0]
        pan_str = hexlify(pan_val).decode('utf-8').upper()
        if (tlv.tagCount(tag_cvv_data) == 1):
            cvv_val = tlv.getTag(tag_cvv_data)[0]
            cvv_str = hexlify(cvv_val).decode('utf-8').upper()
            if (tlv.tagCount(tag_expiry_data) == 1):
                expiry_val = tlv.getTag(tag_expiry_data)[0]
                expiry_str = hexlify(expiry_val).decode('utf-8').upper()
                t2_str = ';' + pan_str + '=' + expiry_str + ';' + cvv_str
                log.log("----------------------------------------------")
                log.log("TRACK2:", t2_str)
                log.log("----------------------------------------------")

# Gets answer from the device, optionally ignoring unsolicited and stopping on errors
def getAnswer(ignoreUnsolicited = True, stopOnErrors = True):
    while True:
        status, buf, uns = conn.receive()
        if uns and ignoreUnsolicited:
            log.log('Unsolicited packet detected: ', TLVParser(buf))
            continue
        if status != 0x9000:
            log.logerr('Pinpad reported error ', hex(status))
            if stopOnErrors:
                performCleanup()
                exit(-1)
        break
    return status, buf, uns

#
# Main function
def processManualEntry():
    req_unsolicited = conn.connect()
    if req_unsolicited:
        #Receive unsolicited
        log.log('Waiting for unsolicited')
        #status, buf, uns = getAnswer(False)
        #log.log('Unsolicited', TLVParser(buf) )

    #Send abort command
    conn.send([0xD0, 0xFF, 0x00, 0x00])
    status, buf, uns = getAnswer()
    
    #Send device reset
    conn.send([0xD0, 0x00, 0x00, 0x00])
    status, buf, uns = getAnswer()

    manual_entry_tag = [
      [ (0xDF, 0x83, 0x05), b'\x10' ],
    ]
    manual_pan_templ = ( manual_entry_tag )

    #Send manual PAN entry
    # P1
    # Bit 0 - PAN entry
    # Bit 1 - Application Expiration Date entry
    # Bit 2 - Application Effective Date entry
    # Bit 3 - CVV2 / CID entry (up to 4 characters)
    #p1 = ENTRY_PAN | ENTRY_EXPIRY_DATE | ENTRY_CVV2
    p1 = ENTRY_PAN | ENTRY_EXPIRY_DATE
    
    # P2
    # Bit 0 - Backlight
    # Bit 1 - Generate track 2 of the following format:
    #         ;PAN=expiryeffectivediscretionary?LRC
    #p2 = BACKLIGHT | TRACK2_FORMAT
    p2 = BACKLIGHT
    
    # P1 = 00, PAN and Expiration Date entries are performed
    #conn.send([0xD2, 0x14, 0x00, p2])

    conn.send([0xD2, 0x14, p1, p2], manual_pan_templ)
    
    status, buf, uns = conn.receive()
    
    tlv = TLVParser(buf)
     
    # format track2
    formatTrack2(tlv)
    
    # TCLink format
    tclinkFormat(tlv)
    
    #Reset display - regardless of tx type
    conn.send([0xD2, 0x01, 0x01, 0x00])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer()
        
if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection()

    utility.register_testharness_script(processManualEntry)
    utility.do_testharness()


