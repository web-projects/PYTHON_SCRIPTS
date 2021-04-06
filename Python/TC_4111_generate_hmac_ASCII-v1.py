from testharness import *
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from testharness.tlvparser import TLVParser, tagStorage
from binascii import hexlify, unhexlify

# GENERATED HMAC
#
# VERSION 1 -----------------------------------------------------------------
# HOSTID-6: 98A8AAED5A2BA9E228B138274FDF546D-6688D2AB8D9A36E0A50A5BF3B142AFB0
# HOSTID-7: D1F8827DD9276F9F80F8890D3E607AC0-3CA022BA91B8024356DCDF54AD434F83
#
# VERSION 2 -----------------------------------------------------------------
# HOSTID-6: C464084095AE8D1F16B5760272495565-1D45B4B6083E4A5E41C4837081F460A6
# HOSTID-7: EDA100E8F35DCE4BD9FDA2EF7456A1E4-03E09FEB2A95FB3D97F88784B548BF4D
#
def GenerateHMAC():
    req_unsolicited = conn.connect()
    if req_unsolicited:
        status, buf, uns = conn.receive()
        check_status_error(status)

    #pan = b'\x41\x11\x11\x11\x11\x11\x11\x11'
    pan = '4111111111111111'
    
    # expected VSS6 HMAC for TC test secrets: 98A8AAED5A2BA9E228B138274FDF546D6688D2AB8D9A36E0A50A5BF3B142AFB0
    # 98A8AAED5A2BA9E228B138274FDF546D-6688D2AB8D9A36E0A50A5BF3B142AFB0
    c_tag = tagStorage()
    c_tag.store((0xDF, 0xEC, 0x0E), pan)    # message for MAC
    c_tag.store((0xDF, 0xEC, 0x23), 0x06)   # host ID
    conn.send([0xC4, 0x22, 0x00, 0x00] , c_tag.getTemplate(0xE0))
    log.log("Generate HMAC sent")

    status, buf, uns = conn.receive()
    log.log("Generate HMAC response received")
    check_status_error(status)
    
    tlv = TLVParser(buf)
    tag_output_data = (0xDF, 0xEC, 0x7B)
    if (tlv.tagCount(tag_output_data) == 1):
        hmac = tlv.getTag(tag_output_data)[0]
        log.log("Generated HMAC HOSTID-06:", hexlify(hmac).decode('utf-8'))

        c_tag = tagStorage()
        c_tag.store((0xDF, 0xEC, 0x0E), hmac)  # message for MAC
        c_tag.store((0xDF, 0xEC, 0x23), 0x07)  # host ID
        
        # expected VSS7 HMAC for TC test secrets: D1F8827DD9276F9F80F8890D3E607AC03CA022BA91B8024356DCDF54AD434F83
        # D1F8827DD9276F9F80F8890D3E607AC0-3CA022BA91B8024356DCDF54AD434F83
        conn.send([0xC4, 0x22, 0x00, 0x00] , c_tag.getTemplate(0xE0))
        log.log("Generate HMAC sent")

        status, buf, uns = conn.receive()
        log.log("Generate HMAC response received")
        check_status_error(status)

        tlv = TLVParser(buf)
        tag_output_data = (0xDF, 0xEC, 0x7B)
        if (tlv.tagCount(tag_output_data) == 1):
            hmac = tlv.getTag(tag_output_data)[0]
            log.log("Generated HMAC HOSTID-07:", hexlify(hmac).decode('utf-8'))

if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script(GenerateHMAC)
    utility.do_testharness()
