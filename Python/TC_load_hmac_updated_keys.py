from testharness import *
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from testharness.tlvparser import TLVParser, tagStorage
from binascii import hexlify, unhexlify

### OLD METHOD OF ENABLING/DISABLING KEY UPDATES
''' UNLOCK KEY UPDATES: putfile.py --serial COM9 --file upload/keys/dl.bundle.TokenKCV_EnableUpdateKeyCmd.tar   '''
''' RELOCK KEY UPDATES: putfile.py --serial COM9 --file upload/keys/dl.bundle.TokenKCV_DisableUpdateKeyCmd2.tar '''

### NEW METHOD OF ENABLING/DISABLING KEY UPDATES
''' UNLOCK KEY UPDATES: putfile.py --serial COM9 --file upload/SphereConfig/hmac/dl.bundle.Sphere_config20191210a.tar '''
''' RELOCK KEY UPDATES: putfile.py --serial COM9 --file upload/SphereConfig/hmac/dl.bundle.Sphere_config20191210b.tar '''

# Generate HMAC
#
# EDA100E8F35DCE4BD9FDA2EF7456A1E4-03E09FEB2A95FB3D97F88784B548BF4D
# C464084095AE8D1F16B5760272495565-1D45B4B6083E4A5E41C4837081F460A6
#
def LoadHMACKeys():
    req_unsolicited = conn.connect()
    if req_unsolicited:
        status, buf, uns = conn.receive()
        check_status_error(status)

    # Retrieve Current KSN HMAC - SIGNATURE FOR DFED15 tag
    c_tag = tagStorage()
    c_tag.store((0xDF, 0xEC, 0x0E), 0x00)  # message for MAC
    c_tag.store((0xDF, 0xEC, 0x23), 0x06)  # host ID
    c_tag.store((0xDF, 0xEC, 0x23), 0x07)  # host ID

    # On success, tag HMAC (DFEC7B) is returned, otherwise error tag Return Code
    conn.send([0xC4, 0x22, 0x00, 0x00] , c_tag.getTemplate(0xE0))
    log.log("--- Retrieve current KSN HMAC ---")

    status, buf, uns = conn.receive()
    log.log("Generate HMAC response received")
    check_status_error(status)
    
    tlv = TLVParser(buf)
    tag_output_data = (0xDF, 0xEC, 0x7B)
    
    if (tlv.tagCount(tag_output_data) == 1):
        current_hmac = tlv.getTag(tag_output_data)[0]
        log.log("Current KSN HMAC:", hexlify(current_hmac).decode('utf-8'))

        # ''' WITH A CURRENT KSN-HMAC, UPDATE KEYS '''
        log.log("Loading the HMAC keys: host_id 6 and 7")

        # HMAC KEY 06
        # 19ABCDEFFEDCBA987654321001234567-29ABCDEFFEDCBA987654321001234567-39ABCDEFFEDCBA987654321001234567-49ABCDEFFEDCBA987654321001234567
        hmackey06  = b'\x19\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67'
        hmackey06 += b'\x29\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67'
        hmackey06 += b'\x39\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67'
        hmackey06 += b'\x49\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67'
        log.log("HMAC key 06:", hexlify(hmackey06).decode('utf-8'))

        # Signature = HMAC_old(old XOR new)
        hmac_new_key06 = bytes(a ^ b for a, b in zip(current_hmac, hmackey06))
        log.log("HMAC NEW6 key:", hexlify(hmac_new_key06).decode('utf-8'))
        
        c_tag = tagStorage()
        # key type (mandatory)
        # ??? 1 ??? PIN key
        # ??? 2 ??? MAC/HMAC key
        # ??? 3 ??? Data key
        c_tag.store( (0xDF, 0xEC, 0x46), 0x03 )
        c_tag.store( (0xDF, 0xEC, 0x2E), hmackey06 )
        c_tag.store( (0xDF, 0xED, 0x15), hmac_new_key06 )
        # host_id = 0x06
        conn.send([0xC4, 0x0A, 0x06, 0x01], c_tag.getTemplate(0xE0))
        status, buf, uns = conn.receive()
        log.log("Received key 06 update status")
        check_status_error( status )
        
        # HMAC KEY 07 
        # 156789ABCDEFFEDCBA98765432100123-256789ABCDEFFEDCBA98765432100123-356789ABCDEFFEDCBA98765432100123- 456789ABCDEFFEDCBA98765432100123
        hmackey07  = b'\x15\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23'
        hmackey07 += b'\x25\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23'
        hmackey07 += b'\x35\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23'
        hmackey07 += b'\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23'
        log.log("HMAC key 07:", hexlify(hmackey07).decode('utf-8'))

        # Signature = HMAC_old(old XOR new)
        hmac_new_key07 = bytes(a ^ b for a, b in zip(current_hmac, hmackey07))
        log.log("HMAC NEW7 key:", hexlify(hmac_new_key07).decode('utf-8'))

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
