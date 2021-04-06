from testharness import *
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from testharness.tlvparser import TLVParser, tagStorage
from binascii import hexlify, unhexlify

def LoadHMACKeys():
    req_unsolicited = conn.connect()
    if req_unsolicited:
        status, buf, uns = conn.receive()
        check_status_error(status)

    # Generate Current HMAC
    #                 d1f8827dd9276f9f-80f8890d3e607ac0-3ca022ba91b80243-56dcdf54ad434f83
    hmackey_4111  = b'\x0D\x01\x0F\x08\x08\x02\x07\x0D\x0D\x09\x02\x07\x06\x0F\x09\x0F'
    hmackey_4111 += b'\x08\x00\x0F\x08\x08\x09\x00\x0D\x03\x0E\x06\x00\x07\x0A\x0C\x00'
    hmackey_4111 += b'\x03\x0C\x0A\x00\x02\x02\x0B\x0A\x09\x01\x0B\x08\x00\x02\x04\x03'
    hmackey_4111 += b'\x05\x06\x0D\x0C\x0D\x0F\x05\x04\x0A\x0D\x04\x03\x04\x0F\x08\x03'
    log.log("HMAC 4111 key:", hexlify(hmackey_4111).decode('utf-8'))
    
    log.log("Loading the HMAC keys: host_id 6 and 7")

    hmackey06  = b'\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10'
    hmackey06 += b'\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10'
    hmackey06 += b'\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10'
    hmackey06 += b'\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10'
    log.log("HMAC key 06__:", hexlify(hmackey06).decode('utf-8'))

    # Signature = HMAC_old(old XOR new)
    hmac_new_key06 = bytes(a ^ b for a, b in zip(hmackey_4111, hmackey06))
    log.log("HMAC NEW6 key:", hexlify(hmac_new_key06).decode('utf-8'))

    hmackey07  = b'\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF'
    hmackey07 += b'\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF'
    hmackey07 += b'\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF'
    hmackey07 += b'\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF'
    log.log("HMAC key 07__:", hexlify(hmackey07).decode('utf-8'))

    # Signature = HMAC_old(old XOR new)
    hmac_new_key07 = bytes(a ^ b for a, b in zip(hmackey_4111, hmackey07))
    log.log("HMAC NEW7 key:", hexlify(hmac_new_key07).decode('utf-8'))

    c_tag = tagStorage()
    # key type (mandatory)
    # • 1 — PIN key
    # • 2 — MAC/HMAC key
    # • 3 — Data key
    c_tag.store( (0xDF, 0xEC, 0x46), 0x03 )
    c_tag.store( (0xDF, 0xEC, 0x2E), hmackey06 )
    c_tag.store( (0xDF, 0xED, 0x15), hmac_new_key06 )
    # host_id = 0x06
    conn.send([0xC4, 0x0A, 0x06, 0x01] , c_tag.getTemplate(0xE0))
    status, buf, uns = conn.receive()
    log.log("Received key 06 update status")
    check_status_error( status )

    c_tag = tagStorage()
    c_tag.store( (0xDF, 0xEC, 0x46), 0x03 )
    c_tag.store( (0xDF, 0xEC, 0x2E), hmackey07 )
    c_tag.store( (0xDF, 0xED, 0x15), hmac_new_key07 )
    # host_id = 0x07
    conn.send([0xC4, 0x0A, 0x07, 0x01] , c_tag.getTemplate(0xE0))
    status, buf, uns = conn.receive()
    log.log("Received key 07 update status")
    check_status_error(status)

if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script(LoadHMACKeys)
    utility.do_testharness()
