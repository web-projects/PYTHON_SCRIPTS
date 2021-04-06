from testharness import *
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from testharness.tlvparser import TLVParser, tagStorage
from binascii import hexlify, unhexlify
from functools import partial
from time import sleep, strftime
import testharness.utility as util
import testharness.fileops as fops
import os
import gvrsim

# Global variables
ux_certificates = []
crypto3 = ''
session_key = ''

def get_cert_file():
    c_tag = tagStorage()
    c_tag.store( (0xDF, 0x83, 0x10), 0x00000000 )
    conn.send([0xC5, 0x06, 0x01, 0x00], c_tag.getTemplate(0xE0))
    status, buf, uns = conn.receive()
    if status == 0x9000:
        tlv = TLVParser(buf)
        if tlv.tagCount( (0xDF, 0x83, 0x12 ) ) == 1:
            fname = tlv.getTag( (0xDF, 0x83, 0x12) )[0]
            log.log("Cert file ", fname)
        else:
            log.logerr("Error, no cert name!")
    else:
        log.logerr("Bad response ", status)


''' Gets Ux300 device certificates '''
def get_vfi_certificate():
    certNo = 0x00000001
    global ux_certificates
    ux_certificates.clear()
    while True:
        c_tag = tagStorage()
        #BUG: Unable to push the direct string not bytearray
        c_tag.store( (0xDF, 0x83, 0x10), int(certNo) )
        conn.send([0xC5, 0x06, 0x00, 0x00] , c_tag.getTemplate(0xE0))
        status, buf, uns = conn.receive()
        if status == 0x9000:
            tlv = TLVParser(buf)
            if tlv.tagCount( (0xDF, 0x83, 0x11) ) == 1:
                log.log("Success")
                key = tlv.getTag( (0xDF, 0x83, 0x11) )[0]
                log.log("Key: ", hexlify(key))
                ux_certificates.append(key)
                certNo += 1
            else:
                log.logerr("Failure")
        else:
            break
        sleep(1)
    #check_status_error( status )
    log.log("We have ", len(ux_certificates), " UX certificates")
    #log.log("UX certs: ", ux_certificates)
    return len(ux_certificates)

def put_file(filename):
    progress = partial( util.display_console_progress_bar, util.get_terminal_width() )

    try:
        fops.updatefile( conn, log, filename, progress=progress )
    except exc.invResponseException as e:
        log.logerr( "Unable to use updatefile fallback to putfile" )
        fops.putfile( conn, log, filename, progress=progress )

def store_certificate(filename, level):
    put_file(filename)
    c_tag = tagStorage()
    c_tag.store( (0xDF, 0x83, 0x12), os.path.basename(filename).lower() )
    c_tag.store( (0xDF, 0x83, 0x10), level )
    conn.send([0xC5, 0x07, 0x00, 0x00], c_tag.getTemplate(0xE0))
    status, buf, uns = conn.receive()
    return status == 0x9000

''' Put GVR certificates '''
def store_gvr_certificates():
    if not store_certificate('keys/gvr/GVR_CHAIN_1.crt', 1):
        log.logerr("Cannot store file1")
        return -1
    if not store_certificate('keys/gvr/UPM_TLS_PEER_IDENTITY.crt', 2):
        log.logerr("Cannot store file2")
        return -2
    return 1

''' exchanges keys for N-S '''
def key_exchange():
    res = get_vfi_certificate()
    res = 1
    if res <= 0:
        log.logerr("Initialization FAILED, terminating")
        return -1
    # Use gvrsim library here
    gvrsim.update_dev_certificate_chain( ux_certificates )
    
    res = store_gvr_certificates()
    if res <= 0:
        log.logerr("GVR initialization FAILED, terminating")
        return -2
    return 1

''' Initializes NS protocol '''
def init_ns():
    # Initialize NS
    crypto1 = gvrsim.initiate_ns( ux_certificates )
    if len(crypto1) == 0:
        log.logerr("Init NS failed!")
        return -1
    log.log("crypto1: ", hexlify(crypto1))
    # Verify NS
    c_tag = tagStorage()
    c_tag.store( (0xDF, 0xEC, 0x0F), crypto1 )
    conn.send([0xC5, 0x0A, 0x00, 0x00], c_tag.getTemplate(0xE0))
    status, buf, uns = conn.receive()
    if status != 0x9000:
        log.logerr("Resolve NS failed!")
        return -2
    # Check crypto2
    tlv = TLVParser(buf)
    if tlv.tagCount( (0xDF, 0xEC, 0x7B) ) != 1:
        log.logerr("Crypto2 missing!")
        return -3
    log.log("Verify NS success")
    crypto2 = tlv.getTag( (0xDF, 0xEC, 0x7B) )[0]
    log.log("Crypto2: ", hexlify(crypto2))
    # Read UPM Key
    exp, mod = gvrsim.read_upm_pubkey()
    if len(mod) == 0:
        log.logerr("Read UPM public key failed")
        return -4
    # Finalize NS
    global crypto3
    crypto3 = gvrsim.finalize_ns(mod, bytes(crypto2))
    if len(crypto3) == 0:
        log.logerr("Finalize NS failed")
        return -5
    log.log("Crypto3: ", hexlify(crypto3))
    # Verify NS
    c_tag.clear()
    c_tag.store( (0xDF, 0xEC, 0x0F), crypto3 )
    conn.send([0xC5, 0x0B, 0x00, 0x00], c_tag.getTemplate(0xE0))
    status, buf, uns = conn.receive()
    if status != 0x9000:
        log.logerr("Verify NS failed!")
        return -2
    # We are done!
    return 1

''' Gets session key from Vault '''
def get_session_key(key_type):
    global crypto3
    global session_key
    if len(crypto3) == 0:
        log.logerr("N-S not initialized!")
        return -1
    session_key = ''
    c_tag = tagStorage()
    c_tag.store( (0xDF, 0xEC, 0x0F), crypto3 )
    conn.send([0xC5, 0x00, key_type, 0x00], c_tag.getTemplate(0xE0))
    status, buf, uns = conn.receive()
    if status != 0x9000:
        log.logerr("Cannot get session key!")
        return -2
    # Got it
    tlv = TLVParser(buf)
    if tlv.tagCount( (0xDF, 0xEC, 0x2E) ) == 1:
        log.log("Session key received")
        session_key = tlv.getTag( (0xDF, 0xEC, 0x2E) )[0]
        log.log("Session key: ", hexlify(session_key))
        return 1
    else:
        log.logerr("Failure")
        return -3

''' Reads ARS password from keyboard and encrypts it '''
def get_ars_password():
    global session_key
    if len(session_key) == 0:
        log.logerr("Session key not established!")
        return ""
    passwd = input("Enter ARS password: ")
    if len(passwd) <= 0:
        log.logerr("ARS password not entered!")
        return ""
    ars_crypto = gvrsim.encrypt_password(bytes(session_key), passwd)
    if len(ars_crypto): return ars_crypto
    else:
        log.logerr("Encryption error!")
        return ""

''' Changes or verifies ARS password '''
def transmit_password(set_new_key, password_no):
    # Get ARS password and encrypt them
    ars = get_ars_password()
    if len(ars) == 0:
        log.logerr("ARS password not entered!")
        return -2
    c_tag = tagStorage()
    if (password_no == 1): c_tag.store( (0xDF, 0xEC, 0x2E), ars )
    else: c_tag.store( (0xDF, 0xEC, 0x2F), ars )
    INS = 0x01
    if set_new_key: INS = 0x02
    conn.send([0xC5, INS, 0x00, 0x00], c_tag.getTemplate(0xE0))
    status, buf, uns = conn.receive()
    if status != 0x9000:
        log.logerr("Cannot verify ARS password(s)!")
        return -3
    if set_new_key: log.log("ARS password set correctly")
    else: log.log("ARS password verified correctly")
    return 1

def process_tx():
    # This just processes Start EMV transaction and executes Verify PIN afterwards!
    # Check if card is inserted
    conn.send([0xD0, 0x60, 0x00, 0x00])
    status, buf, uns = conn.receive()
    if status != 0x9000:
        log.logerr("Error checking for card presence!")
        return -1
    tlv = TLVParser(buf)
    if tlv.tagCount(0x48):
        ins_tag_val = tlv.getTag(0x48, TLVParser.CONVERT_INT)[0]
        ins_tag_val &= 0xFF00
        ins_tag_val >>= 8
        if ins_tag_val != 3:
            log.logerr("EMV card is NOT inserted!")
            return -2
    # Carry on
    date = strftime( "%y%m%d" )
    time = strftime( "%H%M%S" )
    tags = tagStorage()
    tags.store( (0x9F, 0x02), b'\x00\x00\x00\x00\x50\x00' )
    tags.store( (0x9A), bytearray.fromhex(date) )
    tags.store( (0x9F, 0x21), bytearray.fromhex(time) )
    tags.store( (0x9A), b'\x00' )
    tags.store( (0x9C), b'\x00' )
    tags.store( (0x9F,0x41), b'\x00\x01' )
    tags.store( (0x5F,0x2A), b'\x08\x26' )
    tags.store( (0xDF,0xA2,0x18), b'\x01' )
    tags.store( (0xDF,0xA2,0x14), b'\x01' )
    tags.store( (0xDF,0xA2,0x04), b'\x01' )

    #Start transaction
    conn.send([0xDE, 0xD1, 0x00, 0x00], tags.getTemplate(0xE0))
    while True:
        #sleep(1)
        #conn.send([0xD0, 0xFF, 0x00, 0x00])
        status, buf, uns = conn.receive()
        if status != 0x9000:
            if status == 0x9F28:
                log.logerr("Unsupported card!")
            else:
                log.logerr("Transaction terminated with status ", hex(status))
            return -3
        else:
            break
    # Ok, start tx processed. Get PIN, encrypt it, verify it
    while True:
        c_pin = input("Enter PIN: ")
        if len(c_pin) < 4 or len(c_pin) > 12:
            log.logerr("Invalid PIN length ", len(c_pin))
            return -4
        global session_key
        if get_session_key(0) <= 0:
            log.logerr("Cannot generate session key for PIN!")
            return -5
        enc_pin = gvrsim.encrypt_pin( bytes(session_key), c_pin )
        if len(enc_pin) == 0:
            log.logerr("Cannot encrypt PIN!")
        # Provide this to VIPA
        tags.clear()
        tags.store( (0xDF, 0xED, 0x6C), enc_pin );
        conn.send([0xDE, 0xD8, 0x01, 0x00], tags.getTemplate(0xE0))
        while True:
            status, buf, uns = conn.receive_raw()
            if uns:
                log.log("Unsolicited stuff, ignoring")
            else:
                break
        if status != 0x9000:
            log.logerr("This should NEVER happen!")
            return -6
        if len(buf) == 3:
            from struct import unpack
            pres = buf[0]
            card_status = unpack("!H",buf[1:3])[0]
            log.log("Result ", hex(pres), ", card SW1SW2 ", hex(card_status))
            if pres == 0x00:
                log.logerr("Unknown error, should never happen!")
                return -100
            elif pres == 0x01:
                log.logerr("PIN failed, card might be blocked!")
                return -101
            elif pres == 0x02:
                log.log("PIN okay!")
                break
            elif pres == 0x03:
                log.logerr("Error during Get Challenge!")
                # Retry here?
            elif pres == 0x05:
                log.logerr("Invalid card!")
                return -102
            elif pres == 0x06:
                log.logerr("Incorrect PIN entered")
                # Retry for sure
        else:
            log.logerr("Invalid response length ", len(buf))
            return -7
    return 1

def test_ns():
    ''' First create connection '''
    req_unsolicited = conn.connect()
    ''' If unsolicited read it'''
    if req_unsolicited:
        status, buf, uns = conn.receive()
        check_status_error( status )

    res = key_exchange()
    # res = 1
    if res <= 0:
        return res
    res = init_ns()
    if res <= 0:
        return res
    log.log("Initialization completed successfully")

    os.system('reset')
    while True:
        print(" 1 = Inject PIN" )
        print(" 2 = Verify ARS Password 1" )
        print(" 3 = Verify ARS Password 2" )
        print(" 4 = Store new ARS Password 1" )
        print(" 5 = Store new ARS Password 2" )
        print(" 0 = Exit" )

        selection = input("Select: ") 
        if selection == '1':
            log.log("Perform PIN transaction")
            res = process_tx()
        elif selection == '2':
            log.log("Verify ARS Password 1")
            res = get_session_key(1)
            if res > 0:
                res = transmit_password(0, 1)
        elif selection == '3':
            log.log("Verify ARS Password 2")
            res = get_session_key(1)
            if res > 0:
                res = transmit_password(0, 2)
        elif selection == '4':
            log.log("Store New ARS Password 1")
            res = get_session_key(1)
            if res > 0:
                res = transmit_password(1, 1)
        elif selection == '5':
            log.log("Store New ARS Password 2")
            res = get_session_key(1)
            if res > 0:
                res = transmit_password(1, 2)
        #insert other selections here
        elif selection == '0':
            break
        else:
            log.log("Unknown Option Selected!")
    # While ends
    return 0


if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script( test_ns )
    utility.do_testharness()
