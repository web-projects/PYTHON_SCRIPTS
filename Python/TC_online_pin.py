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
    ''' First create connection '''
    req_unsolicited = conn.connect()
    ''' If unsolicited read it'''
    if req_unsolicited:
            status, buf, uns = conn.receive()
            check_status_error( status )

    #host_id = 5;	# Alter from default of 2 to VSS Script index 2 (host_id=3)
    host_id = 2;	# Alter from default of 2 to VSS Script index 2 (host_id=3)

    ''' Send data '''

    pan = b'\x54\x13\x33\x00\x89\x00\x00\x39'
    amount = b'\x00\x00\x00\x01\x23\x00'
    c_tag = tagStorage()
    #BUG: Unable to push the direct string not bytearray
    c_tag.store( (0xDF, 0xEC, 0x05), 0x00 )  # pin try flag
    c_tag.store( (0xDF, 0xED, 0x05), 0x08 )  # max pin length
    c_tag.store( (0xDF, 0xED, 0x04), 0x04 )  # min pin length
    c_tag.store( (0xDF, 0xDF, 0x17), amount)
#    c_tag.store( (0xDF, 0xDF, 0x24), b'PLN')
    c_tag.store( (0xDF, 0xDF, 0x24), (0x08, 0x26))
    c_tag.store( (0xDF, 0xDF, 0x1C), 2)
    #c_tag.store( (0x5A), pan )
    conn.send([0xDE, 0xD6, host_id, 0x01] , c_tag.getTemplate(0xE0))
    log.log("Get online PIN sent")
    log.log('*** PIN ENTRY WAIT ***')
#    possible_cancel(conn,log,host_id)
    status, buf, uns = conn.receive()
    log.log("Get online PIN received")
    check_status_error( status )
    tlv = TLVParser(buf)
    if (tlv.tagCount( (0xDF, 0xED, 0x6C) ) == 1 and tlv.tagCount( (0xDF, 0xED, 0x03) ) == 1 ):
        #encryptedPIN = tlv.getTag((0xDF, 0xED, 0x6C), TLVParser.CONVERT_HEX_STR)[0].upper()
        encryptedPIN = tlv.getTag((0xDF, 0xED, 0x6C))[0]
        ksn = tlv.getTag((0xDF, 0xED, 0x03), TLVParser.CONVERT_HEX_STR)[0].upper()
        log.log("Encrypted PIN: ", hexlify(encryptedPIN))
        log.log("KSN: ", ksn)
        # We have KSN, let's find key
        keyTable = { 
                     '98765432100000200001' : '735A979BEBC52902907AAF9CDEFD699D',
                     '98765432100000200002' : '79DC299FCF97DB1FCF53B1CB54D11477',
                     '98765432100000200003' : '555AE3F1EB663B3B07DD9FA138406F2D',
                     '98765432100000200004' : '9666492A463E1A00A62B937F8685D48F',
                     '98765432100000200005' : 'CE0C44BD82F2226F9337CAA4DF4CA187',
                     '98765432100000200006' : 'BAC6F131BAD7737418865A8D6D1255FF',
                     '98765432100000200007' : '14A556644AC458CC70D98AAD4A4F106C',
                     '98765432100000200008' : '9D5E25AC50510CC4915BB6F4E45B2B59',
                     '98765432100000200009' : '1A0FAB367FE1A1BD08633899A69D023B',
                     '9876543210000020000A' : '4FAC960C39A46E446EBCE594CC759B80',
                     '9876543210000020000B' : 'B3F12012F35E468A7FCB9E64658909B9',
                     '9876543210000020000C' : '7AFD8A982A916EA2B7423A77252FADDB',
                     '9876543210000020000D' : '69FE08C67532ABAA3ECF6344C8C0B8E7',
                     '9876543210000020000E' : 'EFFCE6F6D0E55C48A8C96B51AAC29086',
                     '9876543210000020000F' : '7522E1F6DAA992652E2600505D955E3B',
                     '98765432100000200010' : 'E687255B03B7EAA1B3F22718EB60FC0E',
                     '98765432100000200011' : '661E87DB263AD9AC07967DF0C7792AFA',
                     '98765432100000200012' : '7E319DE1D93C7565339E3B7430CD8C5C',
                     '98765432100000C00043' : '7D62212AEBA5E3C71FD891EA1053F600',
                     '98765432100000C00044' : '25EFF52FB969B8A4A404E05B5D990529',
                     '98765432100000C00045' : '9A65DB336CAE30DC615C96D251087AC2',
                     '98765432100000C00046' : '6CB88AE7A49E00EFE55647F35CA95595',
                     '98765432100000C00047' : '9DFEEBC526CD8D724818E4CC51D6B269',
                     '98765432100000C00048' : 'DF3621F5D627AA03239D6C9559971391',
                     '98765432100000C00049' : '5603FF52A1E067278A8D9A004DD970C7',
                     'F8765432100000E00019' : '738BFB4DA129DFA741F9C248E6E4B54E',
                     'F8765432100000E0001A' : '5BDFEA6581868844B5AF78DFB4AF56BA',
                     'F8765432100000E0001B' : '326089ADC2A2C50BA70D1FFCF4F5AE5E',
                     'FFFF987654011A600002' : ''
                    
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
        pan = bytearray(unhexlify((hexlify(bytearray(pan))[-13:])[:12]))
        pan.reverse()
        encodedPIN = bytearray(dec)
        encodedPIN.reverse()
        appendCnt = len(encodedPIN)-len(pan)
        #print('encoded pin: ', hexlify(encodedPIN))
        #print('pan: ', hexlify(pan))
        clearPIN = bytearray()
        for idx in range(len(pan)):
            #print('encpin val ', encodedPIN[idx], '; pan val ', pan[idx])
            val = encodedPIN[idx]
            val ^= pan[idx]
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
  # c_tag.store( (0xDF, 0xDF, 0x24), b'PLN') # currency code
  # c_tag.store( (0xDF, 0xDF, 0x1C), 2) # currency exponent
    c_tag.store( (0xDF, 0xED, 0x08), 6) # PIN_BLOCK_FORMAT_IBM3624
  #  c_tag.store( (0xDF, 0xED, 0x12), decim_table)
    c_tag.store( (0xDF, 0xED, 0x12), b'\x0F' )      #Now treat it as a padding.
  # c_tag.store( (0xDF, 0xED, 0x11), ibm3624_pin_offset)

  # c_tag.store( (0x5A), pan )
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
