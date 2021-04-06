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

    log.log("Loading the HMAC keys: host_id 6 and 7")

    hmackey06=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10'
    hmackey06+=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10'
    hmackey06+=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10'
    hmackey06+=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10'
    log.log("HMAC key 06:", hexlify(hmackey06).decode('utf-8'))

    hmackey07=b'\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF'
    hmackey07+=b'\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF'
    hmackey07+=b'\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF'
    hmackey07+=b'\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF'
    log.log("HMAC key 07:", hexlify(hmackey07).decode('utf-8'))

    c_tag = tagStorage()
    c_tag.store( (0xDF, 0xEC, 0x46), 0x03 )
    c_tag.store( (0xDF, 0xEC, 0x2E), hmackey06 )
    conn.send([0xC4, 0x0A, 0x06, 0x01] , c_tag.getTemplate(0xE0))
    status, buf, uns = conn.receive()
    log.log("Received key 06 update status")
    check_status_error( status )

    c_tag = tagStorage()
    c_tag.store( (0xDF, 0xEC, 0x46), 0x03 )
    c_tag.store( (0xDF, 0xEC, 0x2E), hmackey07 )
    conn.send([0xC4, 0x0A, 0x07, 0x01] , c_tag.getTemplate(0xE0))
    status, buf, uns = conn.receive()
    log.log("Received key 07 update status")
    check_status_error(status)

if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script(LoadHMACKeys)
    utility.do_testharness()
