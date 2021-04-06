#!/usr/bin/python3
'''
Created on 23-07-2020

@authors: Jon_Bianco
'''

from testharness import *
from testharness.tlvparser import TLVParser, tagStorage
from sys import exit
from testharness.syslog import getSyslog

# BYTE 1
PTID_IN_SERIAL_RESPONSE        = 1 << 0
DISPLAY_SCREEN_UNCHANGED       = 1 << 1
START_SLIDESHOW_ASAP           = 1 << 2
BEEP_DURING_RESET              = 1 << 3

# BYTE 2
CONTACT_EMV_CONFIG_RELOAD      = 1 << 0
CONTACTLESS_EMV_CONFIG_RELOAD  = 1 << 1
CONTACTLESS_CAPK_CONFIG_RELOAD = 1 << 2
OS_COMPONENTS_VERSION          = 1 << 3
COMMUNICATIONS_MODE            = 1 << 4
CONNECT_PINPAD_MODE_ON         = 1 << 5
DISCONNECT_PINPAD_MODE_OFF     = 1 << 6

# Finalise the script, clear the screen
def performCleanup():
    # Clear screen
    conn.send([0xD2, 0x01, 0x01, 0x01])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer(True, False)
    # Disconnect

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
#
# Main function
def processExtendedReset():
    req_unsolicited = conn.connect()
    if req_unsolicited:
        #Receive unsolicited
        log.log('Waiting for unsolicited')
        #status, buf, uns = getAnswer(False)
        #log.log('Unsolicited', TLVParser(buf) )

    c_tag = tagStorage()
    # Bit  1 – 0 PTID in serial response
    #        – 1 PTID plus serial number (tag 9F1E) in serial response
    #        - The following flags are only taken into account when P1 = 0x00:
    # Bit  2 - 0 — Leave screen display unchanged, 1 — Clear screen display to idle display state
    # Bit  3 - 0 — Slide show starts with normal timing, 1 — Start Slide-Show as soon as possible
    # Bit  4 - 0 — No beep, 1 — Beep during reset as audio indicator
    # Bit  5 - 0 — ‘Immediate’ reset, 1 — Card Removal delayed reset
    # Bit  6 - 1 — Do not add any information in the response, except serial number if Bit 1 is set.
    # Bit  7 - 0 — Do not return PinPad configuration, 1 — return PinPad configuration (warning: it can
    #              take a few seconds)
    # Bit  8 - 1 — Add V/OS components information (Vault, OpenProtocol, OS_SRED, AppManager) to
    #              response (V/OS only).
    # Bit  9 – 1 - Force contact EMV configuration reload
    # Bit 10 – 1 – Force contactless EMV configuration reload
    # Bit 11 – 1 – Force contactless CAPK reload
    # Bit 12 – 1 – Returns OS components version (requires OS supporting this feature)
    # Bit 13 - 1 - Return communication mode (tag DFA21F) (0 - SERIAL, 1 - TCPIP, 3 - USB, 4 - BT, 5
    #            - PIPE_INTERNAL, 6 - WIFI, 7 - GPRS)
    # Bit 14 - 1 - Connect to external pinpad (PP1000SEV3) and set EXTERNAL_PINPAD to ON
    # Bit 15 - 1 - Disconnect external pinpad (PP1000SEV3) and set EXTERNAL_PINPAD to OFF
    # Bit 16 - 1 - Return VSR sponsor name (tag DFA241) and serial number (tag DFA240)
    # Bit 17 - 1 - Switch ON memory card support (overwrites configuration settings, valid until reboot)
    # Bit 18 - 1 - Switch OFF memory card support (overwrites configuration settings, valid until reboot)
    #
    BYTE1 = PTID_IN_SERIAL_RESPONSE | DISPLAY_SCREEN_UNCHANGED | START_SLIDESHOW_ASAP | BEEP_DURING_RESET
    BYTE2 = CONTACT_EMV_CONFIG_RELOAD | CONTACTLESS_EMV_CONFIG_RELOAD | CONTACTLESS_CAPK_CONFIG_RELOAD | OS_COMPONENTS_VERSION
    #BYTE2 = DISCONNECT_PINPAD_MODE_OFF
    #BYTE2 = CONNECT_PINPAD_MODE_ON
    c_tag.store( (0xDF, 0xED, 0x0D), [BYTE2, BYTE1] )
    
    #Send extended software reset device
    conn.send([0xD0, 0x0A, 0x00, 0x00], c_tag.getTemplate(0xE0))
    status, buf, uns = getAnswer()
    tlv = TLVParser(buf)
    tid = tlv.getTag((0x9F, 0x1e))
    if len(tid): 
        tid = str(tid[0], 'iso8859-1')
        log.log('Terminal TID: ', tid)
    else: 
        tid = ''
        log.logerr('Invalid TID (or cannot determine TID)!')

    # VIPA restart
    P1 = 0x02
    P2 = 0x08
    conn.send([0xD0, 0x00, P1, P2])

    #Reset display - IDLE SCREEN, BACKLIGHT OFF
    conn.send([0xD2, 0x01, 0x01, 0x00])
    status, buf, uns = getAnswer()  
   
if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection()

    utility.register_testharness_script(processExtendedReset)
    utility.do_testharness()
