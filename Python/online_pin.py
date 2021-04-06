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

# TRANSACTION TYPE (TAG 9C)
# 0x00 - Sale / Purchase (EMV) - "transaction_type_goods" is used
# 0x01 - Cash Advance (EMV) - "transaction_type_cash" is used
# 0x09 - Sale / Purchase with cashback (EMV) - "transaction_type_goods_with_disbursement" is used
# 0x20 - Return / Refund (EMV) - "transaction_type_returns" is used
# 0x30 - Balance (non-EMV) - "transaction_type_balance_inquiry" is used
# 0x31 - Reservation (non-EMV) - "transaction_type_reservation" is used
# 0xFE - none (non-EMV) - "transaction_type_" is skipped

TRANSACTION_TYPE = b'\x00' # SALE TRANSACTION
#TRANSACTION_TYPE = b'\x30' # BALANCE INQUIRY - MTIP06_10_01_15A, MTIP06_12_01_15A

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


def possible_cancel(conn,log,host_id):
    input("ENTER to CANCEL")
#    conn.send([0xd0, 0xff, 0x00, 0x00])
#    status, buf, uns = conn.receive()
#    if status != 0x9000:
#        log.logerr('cancel fail!')
#        exit(-1)
    conn.send([0xde, 0xd6, host_id, 0x01])
    status, buf, uns = conn.receive()
    if status != 0x9000:
        log.logerr('cancel fail!')
        exit(-1)

''' Online PIN, deciphers received data '''
def OnlinePIN():

    global TRANSACTION_TYPE, HOST_ID, KEYSET_ID
    
    ''' First create connection '''
    req_unsolicited = conn.connect()
    ''' If unsolicited read it'''
    if req_unsolicited:
      status, buf, uns = conn.receive()
      check_status_error( status )

    #Send clear display and turn-on backlight
    conn.send([0xD2, 0x01, 0x01, 0x01])
    status, buf, uns = conn.receive()

    ''' Send data '''
    
    PINLEN_MIN = 4
    PINLEN_MAX = 6
    
    # If SRED is enabled and pan_cache_timeout is specified in the [vipa] section
    # of MAPP_VSD_SRED.CFG, the last cached PAN will be used for PIN Block
    # Formats that require PAN in case the PAN tag is not supplied.
    PANDATA = b'\x54\x13\x33\x00\x89\x00\x00\x39'
    #PANDATA = b'\x20\x9c\x6e\x4f\xe2\x0a\xa0\x4b'
    
    AMOUNT   = b'\x00\x00\x00\x00\x32\x50'
    ENTRY_TO = b'\x01\x68'
    
    ###c_tag = tagStorage()
    #BUG: Unable to push the direct string not bytearray
    ##c_tag.store( (0xDF, 0xDF, 0x17), AMOUNT )     # transaction amount
    ##c_tag.store( (0xDF, 0xDF, 0x24), b'PLN' )     # transaction currency
    ##c_tag.store( (0xDF, 0xDF, 0x1C), 0x02 )       # transaction currency exponent
    ##c_tag.store( (0xDF, 0xA2, 0x0E), entryto )    # pin entry timeout
    ##c_tag.store( (0xDF, 0xEC, 0x05), 0x00 )       # pin try flag
    ##c_tag.store( (0xDF, 0xED, 0x04), pinlen_min ) # min pin length
    ##c_tag.store( (0xDF, 0xED, 0x05), pinlen_max ) # max pin length
    ##c_tag.store( (0x5A), pan )
    ##onlinepin_tpl = c_tag.getTemplate(0xE0)
    
    onlinepin_tag = [
        [(0xDF, 0xDF, 0x1D), TRANSACTION_TYPE]  # transaction type
        ,[(0xDF, 0xDF, 0x17), AMOUNT]           # transaction amount
        ,[(0xDF, 0xDF, 0x24), b'PLN']           # transaction currency
        ,[(0xDF, 0xDF, 0x1C), 0x02]             # transaction currency exponent
        ,[(0xDF, 0xA2, 0x0E), ENTRY_TO]         # pin entry timeout: default 30 seconds
        ,[(0xDF, 0xED, 0x04), PINLEN_MIN]       # min pin length
        ,[(0xDF, 0xED, 0x05), PINLEN_MAX]       # max pin length
        #,[(0x5A), PANDATA]                      # PAN DATA
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
    # possible_cancel(conn,log, HOST_ID)
    status, buf, uns = conn.receive()
    log.log("Get online PIN received")
    check_status_error( status )
    
    tlv = TLVParser(buf)
    
    if (tlv.tagCount( (0xDF, 0xED, 0x6C) ) == 1 and tlv.tagCount( (0xDF, 0xED, 0x03) ) == 1 ):
        log.log("PAN:", hexlify(PANDATA).decode('ascii'))
        #encryptedPIN = tlv.getTag((0xDF, 0xED, 0x6C), TLVParser.CONVERT_HEX_STR)[0].upper()
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

        
        # We have KSN, let's find key
        keyTable = { 
                     'F8765432100002C00228' : 'CDA4448CD1A4C697B52E2276B3E7D29B',
                     'F8765432100000E00032' : 'B470D85485961B4717A0805583E5FF6C',
                     'F8765432100000E00033' : 'D52ADFDB812403FAA0E474135A4EC023',
                     'FFFF095301019DA0004C' : '8A3591AC0DEFE9D1F88DFCB898E736A0',
                     'FFFF095301019DA0004D' : '8A3591AC0DEFE9D1F88DFCB898E736A0',
                     'FFFF095301019DA0004E' : '8A3591AC0DEFE9D1F88DFCB898E736A0',
                     'FFFF095301019DA0004F' : '8A3591AC0DEFE9D1F88DFCB898E736A0'
                   }
        if not ksn in keyTable:
            raise exceptions.logicalException("Cannot find key in static table - please inject Security keys again!!!")
            
        key = keyTable[ksn]
        log.log("Encrypted Key:", key)
        #encryptedPIN = unhexlify(encryptedPIN)
        open("pin.dat", "wb").write(encryptedPIN)
        if os.path.isfile("pindec.dat"):
            os.remove("pindec.dat")

        vscmd = "openssl"
        #args = ' ' + "des-ede -nosalt -nopad -d -in pin.dat -out pindec.dat -k " + key
        args = ' ' + "des-ede -p -nosalt -nopad -d -in pin.dat -out pindec.dat -K " + key + " -iv 0000000000000000"
        log.log("calling openssl ", vscmd, ", params: ", args)
        if os.system(vscmd + args):
            raise exceptions.logicalException("Openssl call failed.")
        
        dec = open("pindec.dat", "rb").read()
        log.log("Decrypted PIN block: ", hexlify(dec))
        pinLen = dec[0] & 0x0F
        log.log("PIN length detected: ", pinLen)
        if (pinLen < 4 or pinLen > 12):
            raise exceptions.logicalException("Invalid PIN Block length!")
        if (pinLen % 2): pinLen += 1
        pinLen = (int)(pinLen / 2)

        #pan = bytearray(pan[-6:]) # Take last 12 PAN digits
        PANDATA = bytearray(unhexlify((hexlify(bytearray(PANDATA))[-13:])[:12]))
        PANDATA.reverse()
        encodedPIN = bytearray(dec)
        encodedPIN.reverse()
        appendCnt = len(encodedPIN)-len(PANDATA)
        #print('encoded pin: ', hexlify(encodedPIN))
        #print('pan: ', hexlify(PANDATA))
        clearPIN = bytearray()
        for idx in range(len(PANDATA)):
            #print('encpin val ', encodedPIN[idx], '; pan val ', PANDATA[idx])
            val = encodedPIN[idx]
            val ^= PANDATA[idx]
            clearPIN.append(val)

        encodedPIN.reverse()
        while (appendCnt > 0):
            appendCnt -= 1
            clearPIN.append(encodedPIN[appendCnt])
        clearPIN.reverse()
        log.log("PIN block: ", hexlify(clearPIN))
        clearPIN = clearPIN[1:pinLen+1]
        PIN = str(hexlify(clearPIN)).replace("f", "")
        log.loginfo('PIN entered: ', PIN)
        os.remove("pin.dat")
        os.remove("pindec.dat")

        #Reset display
        conn.send([0xD2, 0x01, 0x01, 0x01])
        log.log('*** RESET DISPLAY ***')
        status, buf, uns = getAnswer()

    else:
        log.logerr("Invalid data!")

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

def EDE_operation(key,validation_data):
    backend = default_backend()
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(validation_data) + encryptor.finalize()
    return ct

def pad_pan(strpan, final_length, pad_digit):
    pad_len = final_length - len(strpan)
    if pad_len<0:
        print("final_length: ", final_length, "is less than length of strpan: ", strpan, "no padding")
        return strpan
    print("pad_len = ", pad_len)
    print("type(pad_digit) = ", type(pad_digit))
    print("type(strpan) = ", type(strpan))
    return strpan + (pad_len * pad_digit)

def decimize2(strhexpin, dec_table):
    ret =""
    for single_char in strhexpin:
        ret += str(dec_table[int(single_char,16)])
    return ret
    
def ibm3624_intermediate_pin(pan_as_str,  key_as_str, dec_tab):
    padded_pan = pad_pan(pan_as_str, 16, 'F')
    validation_data = bytes.fromhex(padded_pan)
    key = bytes.fromhex(key_as_str)
    ct = EDE_operation(key,validation_data)
    dec_pin = decimize2(ct.hex(),dec_tab)
    return dec_pin


def ibm3624_pin_generation(pan_as_str, assigned_pin_length, key_as_str, dec_tab):
    ret = ibm3624_intermediate_pin(pan_as_str,  key_as_str, dec_tab)
    return ret[:assigned_pin_length]

def subtract_mod_10(A_dec_str,B_dec_str, n):
    """
    counts the digit by digit difference (A_dec - B_dec) mod 10 up to n starting from leftmost digit
    """
    ret =""
    for i in range(0,n):
        a_digit = int(A_dec_str[i])
        b_digit = int(B_dec_str[i])
        if a_digit<b_digit:
            a_digit+=10
        ret+=str(a_digit - b_digit)

    return ret

def ibm3624_offset_data_generation(pan_as_str, assigned_pin_length, key_as_str, dec_tab, cust_sel_pin_as_str):
    intermediate_pin_str = ibm3624_intermediate_pin(pan_as_str,  key_as_str, dec_tab)
    offset_data = subtract_mod_10(cust_sel_pin_as_str,intermediate_pin_str, assigned_pin_length)
    return offset_data
def computeOffset(Pan, Pvk, Pin, DecTab):
    pan_str = Pan.hex()
    pvk_str = Pvk.hex()
    pin_str = Pin.hex()
    dec_tab_str = DecTab.hex()
    return unhexlify(ibm3624_offset_data_generation(pan_str, 4, pvk_str, dec_tab_str, pin_str))
    
def ibm3624_pin_block_generation(Pin, Pvk, PaddingChar):
    PaddingChar = bytes((PaddingChar[0]<<4 | PaddingChar[0])&0xFF)
    validation_data = Pin + (16-len(Pin)) * PaddingChar
    print("validation_data= ")
    backend = default_backend()
    cipher = Cipher(algorithms.TripleDES(Pvk), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(validation_data) + encryptor.finalize()
    return ct

def encrypt_pvk_with_master(master_key, kcv, pvk):
    log.log("Checking master key")
    validation_data = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    data_to_validate = EDE_operation(master_key,validation_data)
    print("data_to_validate = ", data_to_validate)
    print("kcv = ", kcv)
    data_to_validate = data_to_validate[0:3]
    if data_to_validate == kcv:
        print("master key is valid")
    else:
        print("master key is invalid")
        return None
    return EDE_operation(master_key, pvk)
    
def update_key_command(conn, host_id, pvk_enc):
    log.log("Updating the PVK using Master session key, host_id is", host_id)
    #pvk_enc=b'\x65\xF3\x8A\xFD\x1B\x85\xDB\xB6\xCB\xFC\xD9\xCD\xD1\x46\xAC'
    
    c_tag = tagStorage()
    c_tag.store( (0xDF, 0xEC, 0x46), 0x01 )
    c_tag.store( (0xDF, 0xEC, 0x2E), pvk_enc )
    conn.send([0xC4, 0x0A, host_id, 0x01] , c_tag.getTemplate(0xE0))
    status, buf, uns = conn.receive()
    log.log("Received key update status")
    check_status_error( status )

def decrypt_key(master_key, encrypted_component):
    backend = default_backend()
    cipher = Cipher(algorithms.TripleDES(master_key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    ct = decryptor.update(encrypted_component) + decryptor.finalize()
    return ct
   
def OnlinePIN_IBM3624():
    """
    This script tests implementation of PIN IBM3624 with offset.
    1. The script establishes connection to VIPA
    2. Sends the data required for PIN validation, namely the PAN and offset.
    3. The customer enters the PIN on VIPA pinpad and the pinpad responds with the information wether PIN is correct or improper
    """
    amount = b'\x00\x00\x00\x00\x00\x00'
    pin = b'\x12\x34'
    pvk = b'\x79\x73\xc0\x90\x5a\xc3\xbe\x59\xd9\xf8\x53\x80\x53\x8a\x99\x3e'
    master_key = b'\x54\x9B\x6E\x13\xB5\x45\xA8\x7F\xA4\x32\x13\xF8\xE5\xBC\x85\x0D'
    kcv = b'\x1D\x85\xE5'
    padding_char = b'\x0F'
    pvk_enc = encrypt_pvk_with_master(master_key, kcv, pvk)
    #pin_block = ibm3624_pin_block_generation(pin, pvk, padding_char)
    log.log("amount is: ",hexlify(amount))
    log.log("Valid pin is: ", hexlify(pin))
    log.log("Secret PVK formely injected is:", hexlify(pvk))
    log.log("Encrypted PVK is:", hexlify(pvk_enc))
    
    #log.log("pin block is: ", hexlify(pin_block))


    ''' First create connection '''
    req_unsolicited = conn.connect()
    ''' If unsolicited read it'''
    if req_unsolicited:
            status, buf, uns = conn.receive()
            check_status_error( status )

    host_id = 9
    
    update_key_command(conn, host_id, pvk_enc)
    
    c_tag = tagStorage()
    #BUG: Unable to push the direct string not bytearray
    c_tag.store( (0xDF, 0xEC, 0x05), 0x00 )  # pin try flag
    c_tag.store( (0xDF, 0xED, 0x05), 0x04 )  # max pin length
    c_tag.store( (0xDF, 0xED, 0x04), 0x04 )  # min pin length
    c_tag.store( (0xDF, 0xDF, 0x17), amount)
    #c_tag.store( (0xDF, 0xDF, 0x24), b'PLN') # currency code
    #c_tag.store( (0xDF, 0xDF, 0x1C), 2) # currency exponent
    c_tag.store( (0xDF, 0xED, 0x08), 6) # PIN_BLOCK_FORMAT_IBM3624
    #c_tag.store( (0xDF, 0xED, 0x12), decim_table)
    c_tag.store( (0xDF, 0xED, 0x12), b'\x0F' )      #Now treat it as a padding.
    #c_tag.store( (0xDF, 0xED, 0x11), ibm3624_pin_offset)
    c_tag.store( (0xDF, 0xEC, 0x7D), 0x02)  # PIN entry type

    #c_tag.store( (0x5A), pan )
    conn.send([0xDE, 0xD6, host_id, 0x00] , c_tag.getTemplate(0xE0))
    log.log("Verify IBM3624 pin sent")
    status, buf, uns = conn.receive()
    log.log("Received verification status")
    check_status_error( status )

    tlv = TLVParser(buf)

    if tlv.tagCount((0xDF, 0xED, 0x6C)) == 1:
        pin_block = tlv.getTag((0xDF, 0xED, 0x6C))[0]
        log.log("Pin block is: ", bytes(pin_block))
        log.log("PVK is: ", pvk.hex())
        entered_pin = decrypt_key(pvk, bytes(pin_block))
        log.log("Entered pin is: ", entered_pin.hex() )
    else:
        log.log("No valid response from Vipa")
    

if __name__ == '__main__':
   log = getSyslog()
   conn = connection.Connection();
   utility.register_testharness_script( OnlinePIN )
#   utility.register_testharness_script( OnlinePIN_IBM3624)
   utility.do_testharness()
#    master_key = b'\x54\x9B\x6E\x13\xB5\x45\xA8\x7F\xA4\x32\x13\xF8\xE5\xBC\x85\x0D'
#    encrypted_component = b'\xFF\x65\xF3\x8A\xFD\x1B\x85\xDB\xB6\xCB\xFC\xD9\xCD\xD1\x46\xAC'
#    decrypted_key = decrypt_key(master_key, encrypted_component).hex()
#    print("decrypted_key = ", decrypted_key)
