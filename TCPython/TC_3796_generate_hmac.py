from testharness import *
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from testharness.tlvparser import TLVParser, tagStorage
from binascii import hexlify, unhexlify

def GenerateHMAC():
    req_unsolicited = conn.connect()
    if req_unsolicited:
        status, buf, uns = conn.receive()
        check_status_error(status)

    pan = b'\x37\x96\x05\x17\x71\x11\x11\x8F'
    # pan = b'\x34\x30\x30\x35\x35\x36\x32\x32\x33\x31\x32\x31\x32\x31\x34\x39'
    c_tag = tagStorage()
    c_tag.store((0xDF, 0xEC, 0x0E), pan)  # message for MAC
    c_tag.store((0xDF, 0xEC, 0x23), 0x06)  # host ID
    #c_tag.store((0xDF, 0xEC, 0x23), 0x07)  # host ID
    conn.send([0xC4, 0x22, 0x00, 0x00] , c_tag.getTemplate(0xE0))
    log.log("Generate HMAC sent")

    status, buf, uns = conn.receive()
    log.log("Generate HMAC response received")
    check_status_error(status)
    
    tlv = TLVParser(buf)
    tag_output_data = (0xDF, 0xEC, 0x7B)
    if (tlv.tagCount(tag_output_data) == 1):
        hmac = tlv.getTag(tag_output_data)[0]
        log.log("Generated HMAC:", hexlify(hmac).decode('utf-8'))

        c_tag = tagStorage()
        c_tag.store((0xDF, 0xEC, 0x0E), hmac)  # message for MAC
        #c_tag.store((0xDF, 0xEC, 0x23), 0x06)  # host ID
        c_tag.store((0xDF, 0xEC, 0x23), 0x07)  # host ID
        conn.send([0xC4, 0x22, 0x00, 0x00] , c_tag.getTemplate(0xE0))
        log.log("Generate HMAC sent")

        status, buf, uns = conn.receive()
        log.log("Generate HMAC response received")
        check_status_error(status)

        tlv = TLVParser(buf)
        tag_output_data = (0xDF, 0xEC, 0x7B)
        if (tlv.tagCount(tag_output_data) == 1):
            hmac = tlv.getTag(tag_output_data)[0]
            log.log("Generated HMAC:", hexlify(hmac).decode('utf-8'))

if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script(GenerateHMAC)
    utility.do_testharness()
