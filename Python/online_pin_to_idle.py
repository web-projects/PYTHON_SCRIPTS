from testharness import *
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from testharness.tlvparser import TLVParser, tagStorage
from binascii import hexlify, unhexlify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import os.path
from time import sleep

TRANSACTION_TYPE = b'\x00' # SALE TRANSACTION

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


''' Online PIN, deciphers received data '''
def OnlinePIN():
    global TRANSACTION_TYPE, HOST_ID, KEYSET_ID
    
    ''' First create connection '''
    req_unsolicited = conn.connect()
    ''' If unsolicited read it'''
    if req_unsolicited:
      status, buf, uns = conn.receive()
      check_status_error( status )

    # DISPLAY [D2, 01] - Processing Transaction - index 02
    conn.send([0xD2, 0x01, 0x02, 0x01])
    status, buf, uns = conn.receive()
    sleep(2)
    
    ''' Set command '''
    PINLEN_MIN = 4
    PINLEN_MAX = 6
    
    # If SRED is enabled and pan_cache_timeout is specified in the [vipa] section
    # of MAPP_VSD_SRED.CFG, the last cached PAN will be used for PIN Block
    # Formats that require PAN in case the PAN tag is not supplied.
    
    AMOUNT   = b'\x00\x00\x00\x00\x15\x00'
    ENTRY_TO = b'\x01\x68'
    
    onlinepin_tag = [
        [(0xDF, 0xDF, 0x1D), TRANSACTION_TYPE]  # transaction type
        ,[(0xDF, 0xDF, 0x17), AMOUNT]           # transaction amount
        ,[(0xDF, 0xDF, 0x24), b'PLN']           # transaction currency
        ,[(0xDF, 0xDF, 0x1C), 0x02]             # transaction currency exponent
        ,[(0xDF, 0xA2, 0x0E), ENTRY_TO]         # pin entry timeout: default 30 seconds
        ,[(0xDF, 0xED, 0x04), PINLEN_MIN]       # min pin length
        ,[(0xDF, 0xED, 0x05), PINLEN_MAX]       # max pin length
        ,[(0xDF, 0xED, 0x07), b'\x01']          # PIN Cancel 
        ,[(0xDF, 0xEC, 0x7D), b'\x01']          # PIN entry type: if 0x01 then pressing ENTER on PIN Entry screen (without any PIN digits) will return SW1SW2=9000 response with no data
    ]
    onlinepin_tpl = (0xE0, onlinepin_tag)    
    
    log.log("HOST ID ____:", str(HOST_ID))
    log.log("KEYSET ID __:", str(KEYSET_ID))
    
    # ONLINE PIN [DE, D6]
    conn.send([0xDE, 0xD6, HOST_ID, KEYSET_ID], onlinepin_tpl)
    log.log("Get online PIN sent")
    
    log.log('*** PIN ENTRY WAIT ***')
    status, buf, uns = conn.receive()
    log.log("Get online PIN received")
    check_status_error( status )
    
    tlv = TLVParser(buf)
    
    if (tlv.tagCount( (0xDF, 0xED, 0x6C) ) == 1 and tlv.tagCount( (0xDF, 0xED, 0x03) ) == 1 ):
        encryptedPIN = tlv.getTag((0xDF, 0xED, 0x6C))[0]
       
        hexStrKSN = tlv.getTag((0xDF, 0xED, 0x03), TLVParser.CONVERT_HEX_STR)[0].upper()
        ksn = "{:F>20}".format(hexStrKSN)

        # adjust KSN for IPP
        if len(encryptedPIN) and ISIPPKEY:
          ksnStr = bytes.fromhex(ksn).decode('utf-8')
          ksn = "{:F>20}".format(ksnStr) 
          log.log("KSN:", ksn)
          encryptedPINStr = tlv.getTag((0xDF, 0xED, 0x6C))[0].hex().upper()
          if len(encryptedPINStr):
            pinStr = bytes.fromhex(encryptedPINStr).decode('utf-8')
            log.log("Encrypted PIN:", pinStr)
        else:
          log.log("KSN:", ksn)
          log.log("Encrypted PIN:", hexlify(encryptedPIN))
    else:
        log.logerr("Invalid data!")


if __name__ == '__main__':
   log = getSyslog()
   conn = connection.Connection();
   utility.register_testharness_script( OnlinePIN )
   utility.do_testharness()

