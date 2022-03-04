from testharness import *
from testharness.tlvparser import TLVParser, tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import getch, kbhit, check_status_error
from binascii import hexlify, unhexlify
from time import sleep

import TC_TransactionHelper

CONVERT_INT = 1
CONVERT_STRING = 2

EMV_KERNEL_CHECKSUM = ''
EMV_L2_KERNEL_VERSION = ''
EMV_CLESS_KERNEL_VERSION = ''


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

def ResetDevice():
    # Send reset device
    # P1 - 0x00
    # perform soft-reset, clears all internal EMV collection data and returns Terminal ID,
    #  Serial Number and Application information
    # P2
    # Bit 1 – 0
    # PTID in serial response
    # Bit 1 – 1
    # PTID plus serial number (tag 9F1E) in serial response
    # The following flags are only taken into account when P1 = 0x00:
    # Bit 2
    # 0 — Leave screen display unchanged, 1 — Clear screen display to idle display state
    # Bit 3
    # 0 — Slide show starts with normal timing, 1 — Start Slide-Show as soon as possible
    # Bit 4
    # 0 — No beep, 1 — Beep during reset as audio indicator
    # Bit 5
    # 0 — ‘Immediate’ reset, 1 — Card Removal delayed reset
    # Bit 6
    # 1 — Do not add any information in the response, except serial number if Bit 1 is set.
    # Bit 7
    # 0 — Do not return PinPad configuration, 1 — return PinPad configuration (warning: it can take a few seconds)
    # Bit 8
    # 1 — Add V/OS components information (Vault, OpenProtocol, OS_SRED, AppManager) to response (V/OS only).
    conn.send([0xD0, 0x00, 0x00, 0x81])
    status, buf, uns = getAnswer()
    log.log('Device reset')
    
    tlv = TLVParser(buf)
    
    # L2 EMV Contact Kernel: after terminal reset
    EMV_L2_KERNEL_VERSION = TC_TransactionHelper.GetEMVL2KernelVersion(tlv)

    return tlv


#
# Main function
#
# The first 4 bytes are the checksum of the crypto library. 
# The next 4 bytes are the checksum of the kernel’s core.
# Third four bytes are the combined checksum of first and second parts.
# The final 4 bytes are the checksum of the application specific configuration.
#
# ex: 2FD4B4F16F1BBC4E00C067C096369E1F
#     2FD4B4F1 6F1BBC4E 00C067C0 96369E1F
#     
#     2FD4B4F16F1BBC4E00C067C06D68B769
#     2FD4B4F1 6F1BBC4E 00C067C0 6D68B769
#
def processGetKernelVersion():
    req_unsolicited = conn.connect()
    if req_unsolicited:
        #Receive unsolicited
        log.log('Waiting for unsolicited')
        #status, buf, uns = getAnswer(False)
        #log.log('Unsolicited', TLVParser(buf) )

    # reset device: command response contains versions and device SN
    tlv = ResetDevice()
    tid = tlv.getTag((0x9F, 0x1E))
    if len(tid): 
        tid = str(tid[0], 'iso8859-1')
        log.log('TID (S/N):', tid)
    else: 
        tid = ''
        log.logerr('Invalid TID (or cannot determine TID)!')
    
    print('')

    # KERNEL LAST 4 BYTES
    #log.log('BUF LEN =', len(buf[0]))
    EMV_KERNEL_CHECKSUM = TC_TransactionHelper.GetEMVKernelChecksum(conn)
  
    # AMEX
    #aidValue = 'A00000002501'
    # Discover
    aidValue = 'A0000001523010'
    # MasterCard
    #aidValue = 'A0000000041010'
    # Visa
    #aidValue = 'A0000000031010'
    
    #log.warning('KERNEL LABEL: ' + clessKernelLabel)
    EMV_CLESS_KERNEL_VERSION = TC_TransactionHelper.GetEMVClessKernelVersion(conn, aidValue)
    #EMV_CLESS_KERNEL_VERSION = TC_TransactionHelper.GetEMVContactlessKernelVersion(conn, tlv, entryMode_value)
    
    # SUMMARY REPORT
    print('')
    print('--------------------------------------------------')
    log.warning('KERNEL CHECKSUM: ' + EMV_KERNEL_CHECKSUM)
    log.log    ('KERNEL EMV C-L2: ' + EMV_L2_KERNEL_VERSION)
    log.log    ('TARGET CLES-AID: ' + aidValue)
    log.logerr ('KERNEL EMV CVER: ' + EMV_CLESS_KERNEL_VERSION)


if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection()

    utility.register_testharness_script(processGetKernelVersion)
    utility.do_testharness()


