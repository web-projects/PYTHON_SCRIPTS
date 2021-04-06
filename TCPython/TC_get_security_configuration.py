from testharness import *
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from testharness.tlvparser import TLVParser, tagStorage
from binascii import hexlify, unhexlify

def GetSecurityConfiguration():
    req_unsolicited = conn.connect()
    if req_unsolicited:
        status, buf, uns = conn.receive()
        check_status_error(status)

    log.log("Get Security Configuration: host_id 6")

    #conn.send([0xC4, 0x11, 0x00, 0x06])
    conn.send([0xC4, 0x11, 0x01, 0x00])
    status, buf, uns = conn.receive()
    log.log("Received Get Security Configuration status")
    check_status_error( status )

    #tlv = TLVParser(buf)
    #tag_output_data = (0xDF, 0xEC, 0x7B)
    #if (tlv.tagCount(tag_output_data) == 1):
    #    hmac = tlv.getTag(tag_output_data)[0]
    #    log.log("Generated KCV for 06:", hexlify(hmac).decode('utf-8'))


if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script(GetSecurityConfiguration)
    utility.do_testharness()
