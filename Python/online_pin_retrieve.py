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

# ---------------------------------------------------------------------------- #
# ONLINE PIN VSS DUPKT

host_id_vss = 0x02;
# Key Set Id - VSS SLOT (0 - PROD, 8 - DEV)
keyset_id_vss = 0x00
    
# ---------------------------------------------------------------------------- #
# ONLINE PIN IPP DUPKT

host_id_ipp = 0x05
# IPP KEY SLOT
keyset_id_ipp = 0x01
    
ISIPPKEY = False    
HOST_ID = host_id_ipp if ISIPPKEY else host_id_vss
KEYSET_ID = keyset_id_ipp if ISIPPKEY else keyset_id_vss 

OnlineEncryptedPIN = ""
OnlinePinKSN = ""


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
        if status != 0x9000 and status != 0x9f0d and status != 0x9F36 and status != 0x9f21  and status != 0x9f22 and status != 0x9f25 and status != 0x9f28 and status != 0x9f31 and status != 0x9f33 and status != 0x9f34 and status != 0x9f35 and status != 0x9f41 and status != 0x9f42 and status != 0x9f43:
            log.logerr('Pinpad reported error ', hex(status))
            traceback.print_stack()
            if stopOnErrors:
                performCleanup()
                exit(-1)
        break
    return status, buf, uns


def getEMVAnswer(ignoreUnsolicited=False):
    return getAnswer(ignoreUnsolicited, False)
    

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
    onlinepin_tag = [
        [(0xDF, 0xED, 0x0D), retrieve_pinblock]
    ]
    onlinepin_tpl = (0xE0, onlinepin_tag)
 
    log.log('Online PIN: retrieving PINBLOCK ---------------------------------------------')
    log.log('HOST_ID=' + str(HOST_ID) + ', KEY_SLOT=' + str(KEYSET_ID))
    
    # ONLINE PIN [DE, D6]
    conn.send([0xDE, 0xD6, HOST_ID, KEYSET_ID], onlinepin_tpl)
    status, buf, uns = getEMVAnswer()
    
    if status != 0x9000:
        log.logerr("STATUS ERROR=", status)
        if status == 0x9f21:
          log.logerr("PIN BLOCK FORMAT ERROR")
        else:
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
                if HOST_ID == 0x05:
                    ksn = bytes.fromhex(ksn).decode('utf-8')
                    ksn = 'F' + ksn 
                OnlinePinKSN = ksn
                
    # send transaction online
    return 6

    
''' Online PIN, deciphers received data '''
def OnlinePIN():
    
    ''' First create connection '''
    req_unsolicited = conn.connect()
    ''' If unsolicited read it'''
    if req_unsolicited:
      status, buf, uns = conn.receive()
      check_status_error( status )

    #Send clear display and turn-on backlight
    conn.send([0xD2, 0x01, 0x01, 0x01])
    status, buf, uns = conn.receive()

    # DFED0D
    # Flags for the entry. The following bits are checked:
    # • Bit 0 = bypass KSN incrementation in case of DUKPT support
    # • Bit 4 = PIN confirmation request: PINblock is not returned, check Return code (DFDF30) for PIN confirmation result
    # • Bit 5 = use Flexi PIN entry method (see information on Flexi PIN entry below) - only VOS and VOS2 platforms
    # • Bit 6 = PIN already entered, only processing request
    # • Bit 7 = PIN collected, no further processing required
    retrieve_pinblock = b'\x40'
    
    onlinepin_tag = [
      [(0xDF, 0xED, 0x0D), retrieve_pinblock],
      [(0xDF, 0xED, 0x08), b'\x00']
    ]
    onlinepin_tpl = (0xE0, onlinepin_tag)    
    
    # Alter from default of 2 to VSS Script index 2 (host_id=3)
    host_id = 0x02;	
    # Key Set Id - VSS SLOT (0 - PROD, 8 - DEV)
    keyset_id = 0x00
  
    # ONLINE PIN IPP DUPK
    host_id = 0x05
    # IPP KEY SLOT
    keyset_id = 0x01
    
    log.log("HOST ID __:", str(host_id))
    log.log("KEYSET ID :", str(keyset_id))
    
    log.log('ONLINE PIN: retrieving PINBLOCK ---------------------------------------------')

    # ONLINE PIN [DE, D6]
    conn.send([0xDE, 0xD6, host_id, keyset_id], onlinepin_tpl)
    
    status, buf, uns = getEMVAnswer()
    
    if status != 0x9000:
        tlv = TLVParser(buf)
        if tlv.tagCount((0xDF, 0xDF, 0x30)):
            response = tlv.getTag((0xDF, 0xDF, 0x30), TLVParser.CONVERT_HEX_STR)[0].upper()
            if len(response):
                log.logerr("PIN RETRIEVE RESPONSE=" + response)    
        return -1

    tlv = TLVParser(buf)
    
    if (tlv.tagCount( (0xDF, 0xED, 0x6C) ) == 1 and tlv.tagCount( (0xDF, 0xED, 0x03) ) == 1 ):
        log.log("PAN:", hexlify(PANDATA).decode('ascii'))
        #encryptedPIN = tlv.getTag((0xDF, 0xED, 0x6C), TLVParser.CONVERT_HEX_STR)[0].upper()
        encryptedPIN = tlv.getTag((0xDF, 0xED, 0x6C))[0]
        hexStrKSN = tlv.getTag((0xDF, 0xED, 0x03), TLVParser.CONVERT_HEX_STR)[0].upper()
        ksn = bytes.fromhex(hexStrKSN).decode('utf-8')
        ksn = 'F' + ksn
        log.log("KSN:", ksn)
        log.log("Encrypted PIN:", hexlify(encryptedPIN))
        
        # We have KSN, let's find key
        keyTable = { 
                     'F8765432100002C00228' : 'CDA4448CD1A4C697B52E2276B3E7D29B',
                     'F876543210040B80000D' : '95AE08362CAB43B04B37DF554D1ADCB0',
                     'F876543210040B80000E' : '6E49046B297FD801F81DA7FFBC29081E',
                     'F876543210040B80000F' : 'AE4E03DF5166FE579DB2329E8F2D11B4'
                   }
        if not ksn in keyTable:
            raise exceptions.logicalException("Cannot find key in static table - please inject Security keys again!!!")
            
        key = keyTable[ksn]
        log.log("Key: ", key)
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
    

def retrieveOnlinePIN():

  ''' First create connection '''
  req_unsolicited = conn.connect()
  ''' If unsolicited read it'''
  if req_unsolicited:
    status, buf, uns = conn.receive()
    check_status_error( status )
      
  #Send clear display
  conn.send([0xD2, 0x01, 0x00, 0x01], '
\tRetrieving

\tONLINE PIN...')
  status, buf, uns = getAnswer()
    
  OnlinePinInTemplateE6()

  #Reset display
  conn.send([0xD2, 0x01, 0x01, 0x01])
  log.log('*** RESET DISPLAY ***')
  status, buf, uns = getAnswer()
  
  
if __name__ == '__main__':
  log = getSyslog()
  conn = connection.Connection();
  utility.register_testharness_script( retrieveOnlinePIN )
  #utility.register_testharness_script( OnlinePIN )
  #utility.register_testharness_script( OnlinePIN_IBM3624)
  utility.do_testharness()
#    master_key = b'\x54\x9B\x6E\x13\xB5\x45\xA8\x7F\xA4\x32\x13\xF8\xE5\xBC\x85\x0D'
#    encrypted_component = b'\xFF\x65\xF3\x8A\xFD\x1B\x85\xDB\xB6\xCB\xFC\xD9\xCD\xD1\x46\xAC'
#    decrypted_key = decrypt_key(master_key, encrypted_component).hex()
#    print("decrypted_key = ", decrypted_key)
