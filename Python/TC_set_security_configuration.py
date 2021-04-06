from testharness import *
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from testharness.tlvparser import TLVParser, tagStorage
from binascii import hexlify, unhexlify

def SetSecurityConfiguration():
    req_unsolicited = conn.connect()
    if req_unsolicited:
        status, buf, uns = conn.receive()
        check_status_error(status)

    ''' host_id and VSS slot number. Host_id = VSS_slot+1 '''
    # ADE SLOT 0 - host_config_id=0x01, vss_slot=0x00
    # ADE SLOT 8 - host_config_id=0x01, vss_slot=0x08

    # Configuration ID
    #host_config_id = 0x01;

    # VSS SLOT (ADE-0 - PROD, ADE-8 - DEV)    
    vss_slot = 0x01;
    #vss_slot = 0x02;
    log.log("Set Security Configuration: for VSS SLOT=", vss_slot)

    c_tag = tagStorage()
    c_tag.store( (0xDF, 0xED, 0x0B), 0x03 )

    conn.send([0xC4, 0x10, vss_slot, 0x00], c_tag.getTemplate(0xE0))
    status, buf, uns = conn.receive()
    log.log("Received Set Security Configuration status")
    check_status_error( status )

    tlv = TLVParser(buf)
    tag_rsp_data = (0xDF, 0xDF, 0x30)
    if (tlv.tagCount(tag_rsp_data) == 1):
        rsp_val = tlv.getTag(tag_rsp_data)[0]
        log.log("RSP:", hexlify(rsp_val).decode('utf-8').upper())
        
if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script(SetSecurityConfiguration)
    utility.do_testharness()
