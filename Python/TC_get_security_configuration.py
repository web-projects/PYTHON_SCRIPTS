from testharness import *
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from testharness.tlvparser import TLVParser, tagStorage
from binascii import hexlify, unhexlify

# ---------------------------------------------------------------------------- #
# ONLINE PIN VSS DUPKT

ADE_KEY_SLOT = 0x00 # (0 - PROD, 8 - DEV)

pin_host_id_vss = 0x02;
# Key Set Id - VSS SLOT 
pin_keyset_id_vss = 0x00
    
# ---------------------------------------------------------------------------- #
# ONLINE PIN IPP DUPKT

pin_host_id_ipp = 0x05
# IPP KEY SLOT
pin_keyset_id_ipp = 0x01
    
ISIPPKEY = True    
PIN_HOST_ID = pin_host_id_ipp if ISIPPKEY else pin_host_id_vss
PIN_KEYSET_ID = pin_keyset_id_ipp if ISIPPKEY else pin_keyset_id_vss


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


def GetKeyConfiguration(hostId, keysetId):
    # [0xC4, 0x11]
    conn.send([0xC4, 0x11, hostId, keysetId])
    status, buf, uns = conn.receive()
    log.log("Received Get Security Configuration status")
    check_status_error( status )

    tlv = TLVParser(buf)
    tag_output_data = (0xDF, 0xEC, 0x7B)
    if (tlv.tagCount(tag_output_data) == 1):
        hmac = tlv.getTag(tag_output_data)[0]
        log.log("Generated KCV for 06:", hexlify(hmac).decode('utf-8'))
  
    return tlv

    
def GetSecurityConfiguration():

    global PIN_HOST_ID, PIN_KEYSET_ID
    
    req_unsolicited = conn.connect()
    if req_unsolicited:
        status, buf, uns = conn.receive()
        check_status_error(status)

    #Send reset device
    conn.send([0xD0, 0x00, 0x00, 0x01])
    status, buf, uns = getAnswer()
    tlv = TLVParser(buf)
    tid = tlv.getTag((0x9F, 0x1E))
        
    ''' host_id and VSS slot number. Host_id = VSS_slot+1 '''
    # ADE SLOT 0 - host_id=0x01, vss_slot=0x00
    # ADE SLOT 8 - host_id=0x08, vss_slot=0x00

    # ADE KEY
    ade_host_id = PIN_HOST_ID
    # Key Set Id - VSS SLOT (0 - PROD, 8 - DEV)
    ade_keyset_id = ADE_KEY_SLOT

    # ADE SRED KEY
    tlv = GetKeyConfiguration(ade_host_id, ade_keyset_id)

    # ADE SRED KSN
    ksn_ade_slot = ''
    tag_ksn_data = (0xDF, 0xDF, 0x11)
    if (tlv.tagCount(tag_ksn_data) == 1):
        ksn_val = tlv.getTag(tag_ksn_data)[0]
        ksn_ade_slot = hexlify(ksn_val).decode('utf-8').upper()

    # ONLINE PIN DEBIT KEY
    tlv = GetKeyConfiguration(PIN_HOST_ID, PIN_KEYSET_ID)

    # REPORT TID
    if len(tid): 
        tid = str(tid[0], 'iso8859-1')
        log.log('Terminal TID:', tid)
    else: 
        tid = ''
        log.logerr('Invalid TID (or cannot determine TID)!')

    log.logwarning("ADE HOST ID_:", str(ade_host_id))
    log.logwarning("KEYSET ID __:", str(ade_keyset_id))
    log.logerr    ("ADE SRED KSN:", ksn_ade_slot)
    log.logwarning("PIN HOST ID :", str(PIN_HOST_ID))
    log.logwarning("KEYSET ID __:", str(PIN_KEYSET_ID))

    # SRED KSN
    tag_ksn_data = (0xDF, 0xDF, 0x11)
    if (tlv.tagCount(tag_ksn_data) == 1):
        ksn_val = tlv.getTag(tag_ksn_data)[0]
        log.logerr("ADE SRED KSN:", hexlify(ksn_val).decode('utf-8').upper())
    elif PIN_HOST_ID == 0x02:
        log.logerr("ADE SRED KSN: NOT FOUND!")
    
    # ONLINE PIN
    tag_onlinepin_data = (0xDF, 0xED, 0x03)
    if (tlv.tagCount(tag_onlinepin_data) == 1):
        onlinepin_val = tlv.getTag(tag_onlinepin_data)[0]
        hexStrKSN = hexlify(onlinepin_val).decode('utf-8').upper()
        if PIN_HOST_ID == 0x05:
          ksnStr = bytes.fromhex(hexStrKSN).decode('utf-8')
          ksn = "{:F>20}".format(ksnStr)
          log.logerr("PINBLOCK KSN:", ksn)
        else:
          log.logerr("PINBLOCK KSN:", hexStrKSN)
    else:
        log.logerr("NO ONLINE PIN REPORTED")
    
    
if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script(GetSecurityConfiguration)
    utility.do_testharness()
