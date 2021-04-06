#!/usr/bin/python3
'''
Created on 03-12-2020

@authors: Jon_B
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
from TC_testharness.utility import getch, kbhit
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
# UTILTIES
# ---------------------------------------------------------------------------- #

# Terminal exception file for pan - ENSURE FILE IS UNIX LINE TERMINATED (EOL)
# PAN.TXT file is used as an exception file(blacklist) to specify primary account numbers. It is used at
# the terminal risk management stage and if a match is found in the exception file, bit 5 in byte1 of
# TVR is set indicating “card number appears on hotlist”.
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
    
# -------------------------------------------------------------------------------------- #
