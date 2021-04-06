
######  WARNING -  Be carerful about character encoding ######
###### First line instructs Python to us UTF-8 encoding ######
###### Default will be ASCII if the coding: line removed #####
# coding: utf-8

from testharness import *
from testharness.tlvparser import TLVParser, tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import getch, kbhit
from binascii import hexlify
from time import sleep



CONVERT_INT = 1
CONVERT_STRING = 2

BACKLIGHT_OFF = 0x00
BACKLIGHT_ON = 0x01

EMV_CARD_REMOVED = 0
EMV_CARD_INSERTED = 1
MAGSTRIPE_TRACKS_AVAILABLE = 2
ERROR_UNKNOWN_CARD = 3


TRANSACTION_APPROVED = 3
ONLINE_REQUESTED = 4
TRANSACTION_DECLINED = 5
MAGSWIPE_FALLBACK = 6
CONTACTLESS_MAGSTRIPE_TAP = 7

PIN_UNKNOWN = 0
PIN_FAILED = 1
PIN_SUCCESS = 2
PIN_CHALLENGE_ERROR = 3
PIN_BYPASS = 4
PIN_CARD_INVALID = 5
PIN_INCORRECT = 6
PIN_CANCELLED = 7
PIN_AMOUNT_REJECT = 8

#EMV Tag Example
START_TRANS_TAG = [
    [(0x9F, 0x02), b'\x00\x00\x00\x00\x10\x70' ],        #Total Transaction value
    [(0x9A), b'\x04\x01\x01'],                           #Transaction date
    [(0x9C), b'\x00'],                                   #Transaction type
    [(0x9F,0x21), b'\x01\x01\x01'],                      #Transaction time
    [(0x9F,0x41), b'\x00\x01' ],                         #Transaction sequence number
    [(0x5F,0x2A), b'\x08\x26' ],                         #Transaction currency code
    [(0xDF,0xA2,0x18), b'\x00'],                         #VeriFone PIN Entry style
    [(0xDF,0xA2,0x14), b'\x01'],                         #VeriFone Suppress Display
    [(0xDF,0xA2,0x04), b'\x01']                          #VeriFone Application selection using PINPad
]


CONTINUE_TRANS_TAG =[
    [ (0x9F,0x02), [0x00, 0x00, 0x00,0x00, 0x54, 0x00 ] ],  #Total Transaction value
    [ (0x5F,0x2A), [0x09, 0x78] ],                          #Transaction currency code
    [ (0xC2), [0x30, 0x30] ],
    [ (0xDF,0xA2,0x18), [0x00] ],                           #VeriFone PIN Entry style
    [ (0xDF,0xA3,0x07), [0x03,0xE8] ],
    [ (0xC0), [0x01] ],
    [ (0x8A), [0x59, 0x32 ] ],
    [ (0x91), [0x37,0xDD,0x29,0x75,0xC2,0xB6,0x68,0x2D,0x00,0x12] ]
]

CONTINUE2_TRANS_TAG =[
    [ (0x9F,0x02), [0x00, 0x00, 0x00,0x00, 0x54, 0x00 ] ],  #Total Transaction value
    [ (0x5F,0x2A), [0x09, 0x78] ],                          #Transaction currency code
    [ (0xC2), [0x30, 0x30] ],
    [ (0xDF,0xA2,0x18), [0x00] ],                           #VeriFone PIN Entry style
    [ (0xDF,0xA3,0x07), [0x03,0xE8] ],
    [ (0xC0), [0x01] ],
    [ (0x8A), [0x59, 0x32 ] ],
    [ (0x91), [0x37,0xDD,0x29,0x75,0xC2,0xB6,0x68,0x2D,0x00,0x12] ]
]



#Contactless Tag Example
START_CTLS_TAG = [
    [(0x9F, 0x02), b'\x00\x00\x00\x00\x10\x70' ],    #Amount
    #[(0x9F, 0x03), b'\x00\x00\x00\x00\x00\x00' ],   #Amount Other
    [(0x5F,0x2A), b'\x08\x26' ],                     #Currency code
    [(0x9A), b'\x12\x01\x01'],                       #Transaction Date
    [(0x9C), b'\x00'],                               #Transaction Type
    [(0x9F,0x21), b'\x01\x01\x01'],                  #Transaction Time
    #[(0x9F,0x41), b'\x00\x01' ],                    #
    [(0x9F,0x1A), b'\x08\x26' ]                      #Terminal Country Code
]   


CONTINUE_CTLS_TAG = [
    [ (0xC2), [0x30, 0x30] ],                        #
    [ (0xC0), [0x01] ],                              #Host Decision
    [ (0x89), b'\x37\xDD\x29\x75\xC2\xB6' ]          #Authorisation Code, Warning: DUMMY VALUE!
]


######################################################
######################################################
###############   Guidance and Help Notes ############
######################################################
######################################################

# Note 1 - connection
# Class Connection
#        enable_chained_messages(state)
#        connect_serial(...)
#        connect()
#        connect_tcp_server(...)
#        connect_tcp_client(...)
#        send_raw(*arg)  #no LCR or any other content parsing
#        send_rawhex(arg)#no LCR or any other content parsing
#        log_message(...)
#        send (value, tags)
#        receive(timeout)
#        setnad(nad_value)
#        close()


# Note 1b - conn.send
# The first argument is a command P1,P2,CLA, INS the second argument  is either a 
# special tag structure/template structure  OR a STRING.
# The second argument when you want to pass the tag structure is: LIST of dual elements
# where first element is a TUPLE which means tag, and the second element can be:
# LIST of INTS, bytearray or STRING. 
# In the template case the second parameter should be a two elements TUPLE where first
# element is an INT  value (Template, e.g. E0) and second element is a LIST of TAGS. For
# simplify the process of tag creation the special class tagStorage should be used for
# second argument preparation.


# Note - 2 - tlvparser
#  Class TLVParser
#        .getTag(tagval, conversion)
#        .tagCount(tagval)
#        .getUnparsed()  #return unparsed data
# Class TLVPrepare
#        .parse_received_data(data_frame)
#        .prepare_packet_from_tags(tags)
# Class tagStorage
#        .store(tag, value)
#        .get()
#        .getTemplate(template)





######################################################
######################################################
######## Helper Functions - Basic Functions ##########
######################################################
######################################################

# Converts data field to integer
def getDataField(buf, conversion = CONVERT_STRING):
    from struct import unpack
    for idx0 in buf:
        if len(idx0)==2 and type(idx0[0]) == str and idx0[0] == 'unparsed':
            if conversion == CONVERT_INT:
                if len(idx0[1]) == 1: return unpack("!B", idx0[1])[0]
                if len(idx0[2]) == 2: return unpack("!H", idx0[1])[0]
                else: return unpack("!L", idx0[1])[0]
            else:
                return str(idx0[1],'iso8859-1')
    return '0'

# Check whether transaction is identified as encrypted
def vspIsEncrypted(tlv):
    vsp_tag_val = tlv.getTag((0xDF,0xDF,0x6F))
    if len(vsp_tag_val):
        vsp_tag_val = tlv.getTag((0xDF,0xDF,0x6F), TLVParser.CONVERT_INT)[0]
        if vsp_tag_val != 0:
            log.log('VSP Encryption detected, flag ', hex(vsp_tag_val), '!')
            return True
        else:
            log.log('VSP present, but transaction unencrypted')
    return False

# Decrypts VSP - encrypted data
def vspDecrypt(tlv, tid):
    if not vspIsEncrypted(tlv):
        return False
    if len(tid) == 0:
        log.logerr('Cannot decrypt, no TID detected')
        return False
    try:
        enc = semtec.encryptor()
        enc.set_TID(tid)
    except exceptions.logicalException as exc:
        log.logerr('Cannot create decryptor object! Error ', exc)
        return False

    eparms = tlv.getTag((0xDF, 0xDF, 0x70), TLVParser.CONVERT_HEX_STR)
    if len(eparms): eparms = eparms[0]
    else: eparms = ''
    pan = tlv.getTag(0x5A, TLVParser.CONVERT_HEX_STR)
    if len(pan): pan = pan[0]
    else: pan = ''
    expiry = tlv.getTag((0x5F, 0x24), TLVParser.CONVERT_HEX_STR)
    if len(expiry): expiry = expiry[0]
    else: expiry = ''
    if len(pan) > 0:
        # EMV transaction - get appropriate tags
        log.log('EMV')
        t2eq = tlv.getTag(0x57, TLVParser.CONVERT_HEX_STR)
        if len(t2eq): t2eq = t2eq[0]
        else: t2eq = ''
        t1dd = tlv.getTag((0x9F, 0x1F), TLVParser.CONVERT_HEX_STR)
        if len(t1dd): t1dd = t1dd[0]
        else: t1dd = ''
        t2dd = tlv.getTag((0x9F, 0x20), TLVParser.CONVERT_HEX_STR)
        if len(t2dd): t2dd = t2dd[0]
        else: t2dd = ''
        if len(pan): log.log('PAN: ', pan)
        if len(expiry): log.log('Expiry: ', expiry)
        if len(t2eq): log.log('T2EQ: ', t2eq)
        if len(t2dd): log.log('T2DD: ', t2dd)
        if len(t1dd): log.log('T1DD: ', t1dd)
        try:
            pan_d, expiry_d, t2eq_d, t2dd_d, t1dd_d = enc.decrypt_emv(pan, expiry, t2eq, t2dd, t1dd, eparms)
            if len(pan_d): log.log('Decrypted PAN: ', pan_d)
            if len(expiry_d): log.log('Decrypted Expiry: ', expiry_d)
            if len(t2eq_d): log.log('Decrypted T2EQ: ', t2eq_d)
            if len(t2dd_d): log.log('Decrypted T2DD: ', t2dd_d)
            if len(t1dd_d): log.log('Decrypted T1DD: ', t1dd_d)
            return True
        except exceptions.logicalException as exc:
            log.logerr('Cannot decrypt! Error ', exc)
            # log.logerr('Cannot decrypt!')
            return False
    else:
        log.log('Magstripe')
        t1 = tlv.getTag((0x5F, 0x21), TLVParser.CONVERT_STR)
        if len(t1): t1 = t1[0]
        else: t1 = ''
        t2 = tlv.getTag((0x5F, 0x22), TLVParser.CONVERT_STR)
        if len(t2): t2 = t2[0]
        else: t2 = ''
        if len(pan): log.log('PAN: ', pan)
        if len(expiry): log.log('Expiry: ', expiry)
        if len(t1): log.log('T1: ', t1)
        if len(t2): log.log('T2: ', t2)

        try:
            pan_d, expiry_d, t1_d, t2_d = enc.decrypt(pan, expiry, t1, t2, eparms)
            if len(pan_d): log.log('Decrypted PAN: ', pan_d)
            if len(expiry_d): log.log('Decrypted Expiry: ', expiry_d)
            if len(t1_d): log.log('Decrypted T1: ', t1_d)
            if len(t2_d): log.log('Decrypted T2: ', t2_d)
            return True
        except exceptions.logicalException as exc:
            log.logerr('Cannot decrypt! Error ', exc)
            # log.logerr('Cannot decrypt!')
            return False


# Finalise the script, clear the screen
def performCleanup():
    # Clear screen
    conn.send([0xD2, 0x01, 0x01, 0x01])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer(True, False)
    # Disconnect

# Gets answer from the device, optionally ignoring unsolicited and stopping on errors
#  Note: A few commands return codes other than 0x9000 which are not really errors, such as file not found
#        setting noError = True suppresses any confusing logerr entries 
def getAnswer(ignoreUnsolicited = True, stopOnErrors = True, noErrors = False):
    while True:
        status, buf, uns = conn.receive()
        if uns and ignoreUnsolicited:
            log.log('Unsolicited packet detected: ', TLVParser(buf))
            continue
        if status != 0x9000 and (not noErrors):
            log.logerr('Pinpad reported error ', hex(status))
            if stopOnErrors:
                performCleanup()
                log.logerr('*** TEST BEING HALTED ABNORMALLY ***')
                exit(-1)
        break
    return status, buf, uns


def calculateLRC(*args ):
    lrc = 0
    for by in args:
        if type(by)!=int:
            for b in bytearray( by ):
                lrc ^= b
        else: lrc = (lrc ^ by) & 0xFF
    return lrc


######################################################
######################################################
############ Standard API - API Functions ############
######################################################
######################################################

#Select File    00 A4    Select file for operations (optional truncate), create new if file does not exist.
NO_TRUNCATE_FILE = 0x04
TRUNCATE_FILE = 0x05
def selectFile(filename, P1=NO_TRUNCATE_FILE):
    #filename format is 'FILENAME.OLD'
    log.log ('selectFile')
    conn.send([0x00, 0xA4, P1, 0x00], filename)
    status, buf, uns = getAnswer()
    return 0, status, buf, uns 


#Read Binary    00 B0    Read file contents from the offset location
def readBinary(readControl, P1=0x00, P2=0x00, IgnoreNoFile=False):
    log.log ('readBinary')
    #special message format send
    c_nad=0x01
    c_pcb=0x00
    message_header= [0x00, 0xB0, P1, P2]
    w_len=len(readControl)+4
    lrc = calculateLRC(c_nad, c_pcb, w_len, message_header, readControl )
    log_out_frame_buf = [] #record what was actually sent
    log_out_frame_buf += conn.send_raw(c_nad, c_pcb, w_len, message_header, readControl, lrc )
    conn.log_message('send', message_header+readControl, log_out_frame_buf, None, message_header)
    if IgnoreNoFile==True:
        status, buf, uns = getAnswer(True, False, True)
    else:
        status, buf, uns = getAnswer()
    if status!=0x9000:
        if status==0x9F13:
            log.log('No file found probably due to missing previous selectFile, not necessarily an error')
        else:
            log.logerr('Pinpad reported error ', hex(status))
            performCleanup()
            log.logerr('*** TEST BEING HALTED ABNORMALLY ***')
            exit(-1)
    return 0, status, buf, uns 



#Update Binary    00 D6    Update file from the offset location
def updateBinary(dataUpdate, P1=0x00, P2=0x00, IgnoreNoFile=False):
    log.log ('updateBinary')
    conn.send([0x00, 0xD6, P1, P2], dataUpdate)
    if IgnoreNoFile==True:
        status, buf, uns = getAnswer(True, False, True)
    else:
        status, buf, uns = getAnswer() #Stop & ErrLog
    if len(buf) != 0:
        log.logerr('message had unexpected Data content', buf)
    if status!=0x9000:
        if status==0x9F16:
            log.log('No file found probably due to missing previous selectFile, not necessarily an error')
        else:
            log.logerr('Pinpad reported error ', hex(status))
            performCleanup()
            log.logerr('*** TEST BEING HALTED ABNORMALLY ***')
            exit(-1)
    return 0, status, buf, uns 

#Rename Binary    00 AA    Rename file
RENAME_SELECTED_FILE = 0x01 #oldname not used
RENAME_SUPPLIED_FILE = 0x00
def renameBinary(newname, oldname='', P1=RENAME_SUPPLIED_FILE):
    log.log ('renameBinary')
    if P1==RENAME_SELECTED_FILE:
        conn.send([0x00, 0xAA, P1, 0x00], newname)
    elif P1==RENAME_SUPPLIED_FILE:
        conn.send([0x00, 0xAA, P1, 0x00], newname+':'+oldname)
    else:
        log.logerr('test script error, P1 value not valid for this command', P1)
    status, buf, uns = getAnswer()
    if len(buf) != 0:
        log.logerr('message had unexpected Data content', buf)
    return 0, status, buf, uns 


#Delete Binary    00 AB    Delete file
def deleteBinary(filename, IgnoreNoFile=False):
    #filename format is 'FILENAME.OLD'
    log.log ('deleteBinary')
    conn.send([0x00, 0xAB, 0x00, 0x00], filename)
    if IgnoreNoFile==True:
        status, buf, uns = getAnswer(True, False, True)
    else:
        status, buf, uns = getAnswer() #Stop & ErrLog
    if len(buf) != 0:
        log.logerr('message had unexpected Data content', buf)
    if status!=0x9000:
        if status==0x9F13:
            log.log('No file found probably due to missing previous selectFile, not necessarily an error')
        else:
            log.logerr('Pinpad reported error ', hex(status))
            performCleanup()
            log.logerr('*** TEST BEING HALTED ABNORMALLY ***')
            exit(-1)
    return 0, status, buf, uns



#Get Binary Status    00 C0    Retrieve file information (e.g. file size)
def getBinaryStatus(filename):
    #filename format is 'FILENAME.OLD'
    log.log ('getBinaryStatus')
    conn.send([0x00, 0xC0, 0x00, 0x00], filename)
    status, buf, uns = getAnswer()
    tlv = TLVParser(buf)
    if status==0x9000 and not (tlv.tagCount(0x80) and tlv.tagCount(0x81) and tlv.tagCount(0x82) and tlv.tagCount(0x83) and tlv.tagCount(0x87) and tlv.tagCount(0x88) and tlv.tagCount(0x89)):
        log.logerr('message had a missing expected tag or tags (80, 81, 82, 83, 87, 88 and 89)', buf)
        return -1, status, buf, uns
    return 0, status, buf, uns 


#Find First File    00 C3    Find file using search string, first (search order not defined) matched file-name returned and file selected
def findFirstFile(filemask, IgnoreNoFile=False):
    #filename format is '*.INI'
    log.log ('findFirstFile')
    conn.send([0x00, 0xC3, 0x00, 0x00], filemask)
    if IgnoreNoFile==True:
        status, buf, uns = getAnswer(True, False, True)
    else:
        status, buf, uns = getAnswer() #Stop & ErrLog
    if status==0x9000:
        tlv = TLVParser(buf)
        if not (tlv.tagCount(0x84)):
            log.logerr('message had a missing expected tag (84)', buf)
            return -1, status, buf, uns
    elif status==0x9F13:
        log.log('No file match found to supplied mask, not necessarily an error')
    else:
        log.logerr('Pinpad reported error ', hex(status))
        performCleanup()
        log.logerr('*** TEST BEING HALTED ABNORMALLY ***')
        exit(-1)
    return 0, status, buf, uns 


#Find Next File    00 C4    Step through search results, return name and select file
def findNextFile(filemask, IgnoreNoFile=False):
    #filename format is '*.INI'
    log.log ('findNextFile')
    conn.send([0x00, 0xC4, 0x00, 0x00], filemask)
    if IgnoreNoFile==True:
        status, buf, uns = getAnswer(True, False, True)
    else:
        status, buf, uns = getAnswer() #Stop & ErrLog
    if status==0x9000:
        tlv = TLVParser(buf)
        if not (tlv.tagCount(0x84)):
            log.logerr('message had a missing expected tag (84)', buf)
            return -1, status, buf, uns
    elif status==0x9F13:
        log.log('No next file match found to supplied mask, not necessarily an error')
    else:
        log.logerr('Pinpad reported error ', hex(status))
        performCleanup()
        log.logerr('*** TEST BEING HALTED ABNORMALLY ***')
        exit(-1)
    return 0, status, buf, uns 


#Free Space    00 D0    Return free space (RAM and Flash availability returned)
def freeSpace():
    log.log ('freeSpace')
    conn.send([0x00, 0xD0, 0x00, 0x00])
    status, buf, uns = getAnswer()
    tlv = TLVParser(buf)
    if status==0x9000 and not (tlv.tagCount((0xDF, 0xDE, 0x7E))==2 and tlv.tagCount((0xDF, 0xDE, 0x7F))==2 ):
        log.logerr('message had a missing expected tag or tags (DFDE7E and DFDE7F)', buf)
        return -1, status, buf, uns
    return 0, status, buf, uns 


#Update Key    CA 0A    Insert replacement MSK encryption key
#Set Security Configuration    C4 10    Update host security configuration
#Get Security Configuration    C4 11    Return the security configuration
#Generate MAC    C4 20    Calculate and return MAC for the data �blob� supplied in the message 
#Verify MAC    C4 21    Calculate MAC for data �blob� supplied in the message and compared with externally received MAC also passed in with the message
#Encrypt Data    C4 25    Return encrypted version of the data �blob� supplied in the message
#Decrypt Data    C4 26    Return in-the-clear decrypted version of the data �blob� supplied in the message


#Power On Notification    E6    Unsolicited notification of device power cycle or transaction IP connection/re-connection
def powerOnNotification():
    log.log ('powerOnNotification')
    displayCommandString('\x0D\x09Perform power or wifi\x0D\x0D\x09off and on\x07')
    #await unsolicited power on message
    status, buf, uns = getAnswer(ignoreUnsolicited=False)
    if not uns:
        log.logerr('unsolicited response expected only')
    tlv = TLVParser(buf)
    if status==0x9000 and not (tlv.tagCount((0xC3))==1 and tlv.tagCount((0xC4))==1 and tlv.tagCount((0x9F, 0x1C))==1):
        log.logerr('message had a missing expected tags (C3, C4 and 9F1C)', buf)
        return -1, status, buf, uns    
    return 0, status, buf, uns 

#Abort    D0 FF    Abort current processing and return to idle status
def abortDevice():
    log.log ('abortDevice')
    conn.send([0xD0, 0xFF, 0x00, 0x00])
    status, buf, uns = getAnswer()
    if len(buf) != 0:
        log.logerr('message had unexpected Data content', buf)
    return 0, status, buf, uns 

#Reset Device    D0 00    Reset all local data, removing all TLV held objects and clearing all transaction status flags.  Chip interface reset at hardware level
def resetDevice(P1=0x00, P2=0x00):
    log.log ('resetDevice')
    conn.send([0xD0, P1, P2, 0x01])
    status, buf, uns = getAnswer()
    tlv = TLVParser(buf)
    tid = tlv.getTag((0x9F, 0x1e))
    if len(tid): 
        tid = str(tid[0], 'iso8859-1')
        log.log('Terminal TID: ', tid)
    else: 
        tid = ''
        log.logerr('Invalid TID (or cannot determine TID)!')
    return tid, status, buf, uns 


#Start Upgrade    D0 04    Reset device and then enter software upgrade mode.  In upgrade mode only file read/write operations function
def startUpgrade():
    log.log ('startUpgrade')
    conn.send([0xD0, 0x04, 0x00, 0x00])
    status, buf, uns = getAnswer(ignoreUnsolicited=False)
    if not uns:
        log.logerr('unsolicited response expected only')
    tlv = TLVParser(buf)
    tid = tlv.getTag((0x9F, 0x1e))
    if len(tid): 
        tid = str(tid[0], 'iso8859-1')
        log.log('Terminal TID: ', tid)
    else: 
        tid = ''
        log.logerr('Invalid TID (or cannot determine TID)!')
    return tid, status, buf, uns 


#Disconnect    D0 03    Drop IP connection, return to idle state Configure File Versions    D0 01    Return information on all configuration files held on the device.
def disconnect():
    log.log ('disconnect')
    conn.send([0xD0, 0x03, 0x00, 0x00])
    pass # no response will be received.
    return 0, 0x9000, [], False


#Configure File Versions D0 01 Return information on all configuration files held on the device
def configureFileVersions():
    log.log ('configureFileVersions')
    conn.send([0xD0, 0x01, 0x00, 0x00])
    status, buf, uns = getAnswer()
    tlv = TLVParser(buf)
    if status==0x9000 and not (tlv.tagCount((0xDF, 0xDE, 0x7E)) and tlv.tagCount((0xDF, 0xDE, 0x7F))):
        log.logerr('message had a missing expected tag or tags (DFDE7E and DFDE7F)', buf)
        return -1, status, buf, uns
    return 0, status, buf, uns 


#Serial Port Configuration        Update the serial port configuration, returned response will be under new configuration
    #Dione only - not coded
    
    
#Display Configuration    D2 05    Update display configuration (e.g. backlight on/off)
def displayConfiguration(display_config_tag, P1=0x01):
    log.log ('displayConfiguration')
    if len(display_config_tag) !=0:
        conn.send([0xD2, 0x05, 0x00, 0x00, display_config_tag])
    else:
        conn.send([0xD2, 0x05, 0x00, 0x00])
    status, buf, uns = getAnswer()
    if len(buf) != 0:
        log.logerr('message had unexpected Data content', buf)
    return 0, status, buf, uns 


#Battery Status    D0 62    Return battery status information
    #P1
BATTERY_POWERED = 0x00
FORCE_CHARGE=0x01
BATTERY_CAPACITY=0x02
POWER_SOURCE=0x03
CHARGE_THRESHOLD=0x04
UPGRADE_FIRMWARE=0x05
BATTERY_STATUS=0x06
LOAD_FIRMWARE=0x07
SERIAL_NUMBER=0x08
REPORT_FIRMWARE=0x09
STANDBY=0xFF
def batteryStatusFirmware(fileName='', P1=REPORT_FIRMWARE, P2=0x00):
    log.log ('batteryStatus')
    if P1==UPGRADE_FIRMWARE or P1==LOAD_FIRMWARE or P1==REPORT_FIRMWARE:
        conn.send([0xD0, 0x62,  P1, 0x00], fileName)
    else:
        conn.send([0xD0, 0x62,  P1, P2])
    status, buf, uns = getAnswer()
    return 0, status, buf, uns 

def batteryStatus(P1=POWER_SOURCE, P2=0x00):
    batteryStatusFirmware('', P1, P2)

#Card Status    D0 60    Enables, and configures, reporting of card movement events, plus option enter/cancel/clear/function key events.  Responses occur unsolicited when the card movement(s) or appropriate key press(es) occur.
def cardStatus(P1=0x1F, P2=0x03):
    log.log ('cardStatus')
    conn.send([0xD0, 0x60, P1, P2])
    status, buf, uns = getAnswer(False) #Don't ignore unsolicited
    if (P1 & 0x01): #Test bit 0 is set
        log.log ('Card ICC/MagSwipe armed for unsolicited event')
    return 0, status, buf, uns 


#Verify PIN    DE D5    Enable, and configure, device for EMV PIN verification. Two unsolicited responses (a) validation of the command and confirmation of PIN entry wait state and (b) PIN verification status when the PIN entry is completed.
def verifyPIN(verify_pin_tag, P1=0x01):
    log.log ('verifyPIN')
    if len(verify_pin_tag) !=0:
        verify_templ = ( 0xE0, verify_pin_tag )
        conn.send([0xDE, 0xD5, P1, 0x01, verify_templ])
    else:
        conn.send([0xDE, 0xD5, P1, 0x01])
    while True:
        status, buf, uns = getAnswer(False)
        #solicited, PIN entry completed
        if not uns:
            log.log('PIN verification concluded ', buf)
            return 0, status, buf, uns
        #unsolicited, PIN attempted 
        tlv = TLVParser(buf)
        log.log('PIN try attempted ', tlv)


#Atomic Verify PIN    DE D7    Enable, and configure, device for EMV PIN verification. Two unsolicited responses (a) validation of the command and confirmation of PIN entry wait state and (b) PIN verification status when the PIN entry is completed.
#Online PIN    DE D6    Prompt user (with supplied prompt details) for PIN. One unsolicited response returned containing the encrypted PIN information.
#Get EMV Hash Value    DE 01    Return the EMV Hash value


#Start Transaction    DE D1    Pass transaction details (e.g. price) and start payment card transaction.  Returned values will pertain to a decision required by POS/EFT device
def startTransaction(start_trans_tag=START_TRANS_TAG):
    log.log ('startTransaction')
    start_templ = ( 0xE0, start_trans_tag )
    conn.send([0xDE, 0xD1, 0x00, 0x00], start_templ)
    while True:
        status, buf, uns = getAnswer(False) #Don't ignore unsolicited
        #unexpected unsolicited received
        if uns:
            log.log('Unsolicited packet detected: ignoring')
            if status == 0x9000:
                tlv = TLVParser(buf)
                if tlv.tagCount(0xE6) != 0:
                    log.log('Multi application card!')
                continue
            else:
                log.log('unexpected unsolicited message received ', buf)
                continue
        #expected solicited received
        if status != 0x9000:
            if status == 0x9F28:
                return MAGSWIPE_FALLBACK, status, buf, uns
            else:
                log.logerr('Transaction terminated with status ', hex(status))
                return -1, status, buf, uns
        return 0, status, buf, uns


#Continue Transaction    DE D2    Pass in further data objects and decision or host responses.  Unsolicited response details the current status of the transaction once the wait state has been reached, further <Continue Transaction> may be required.
def continueTransaction(continue_trans_tag=CONTINUE_TRANS_TAG):
    log.log ('continueTransaction')
    continue_tpl = (0xE0, continue_trans_tag )
    conn.send([0xDE, 0xD2, 0x00, 0x00], continue_tpl)
    while True:
        status, buf, uns = getAnswer(False) #Don't ignore unsolicited
        if status != 0x9000:
            log.logerr('Transaction terminated with status ', hex(status))
            return -1, status, buf, uns
        tlv = TLVParser(buf)        
        #optional E6 (Status) template, reporting why Terminal is in wait state 
        if tlv.tagCount(0xE6) != 0:
            log.log ('transaction in wait state ', TLVParser(buf))
            log.log('PIN Entry is being performed, waiting for user input')
            #handling to allow user to break from PIN entry to continue test
            print('PIN entry modification, press PC key \'A\' to abort, \'B\' to bypass or \'C\' to cancel')
            while True:
                if kbhit():
                    key = getch()
                    log.log('key press ', key)
                    if key == 'a' or key == 'A':
                        log.logerr('PIN entry aborting')
                        abortDevice()
                        break
                    if key == 'b' or key == 'B':
                        log.logerr('PIN entry bypassing')
                        verifyPIN(P1=0xFF)
                        break
                    if key == 'c' or key == 'C':
                        log.logerr('PIN entry cancelling')
                        verifyPIN(P1=0x00)
                        break
                if conn.is_data_avail():
                    break  # Has user attempted PIN entry, proceed to evaluation of results
                continue
        else:
        #Status result 
            if tlv.tagCount(0xE3):
                log.log ('transaction approved')
                return TRANSACTION_APPROVED, status, buf, uns
            if tlv.tagCount(0xE4):
                log.log ('online request, transaction must be verified online')
                return ONLINE_REQUESTED, status, buf, uns
            if tlv.tagCount(0xE5):
                log.log ('transaction declined')
                return TRANSACTION_DECLINED, status, buf, uns


#Put Data    00 DA    Load a value to the call identified tag
def putData(tag_value, P1, P2):
    log.log ('putData')
    conn.send([0x00, 0xDA, P1, P2] , tag_value)
    status, buf, uns = conn.receive()
    if len(buf) != 0:
        log.logerr('message had unexpected Data content', buf)
    return 0, status, buf, uns


#Get Data    00 CA    Return the contents of the call identified Tag
def getData(P1, P2):
    log.log ('getData')
    conn.send([0x00, 0xCA, P1, P2])
    status, buf, uns = getAnswer()
    return 0, status, buf, uns


#Display Command    D2 01    Display text on screen, either free format or pre-configured.
def displayCommandString(display_string='', P1=0x00, P2=BACKLIGHT_ON):
    log.log ('displayCommand')
    if P1==0x00:
        conn.send([0xD2, 0x01, P1, P2], display_string)
    else:
        conn.send([0xD2, 0x01, P1, P2])
    #solicited response
    status, buf, uns = getAnswer()
    if len(buf) != 0:
        log.logerr('message had unexpected Data content', buf)
    return 0, status, buf, uns

def displayCommand(P1=0x01, P2=BACKLIGHT_ON):
    return displayCommandString('', P1, P2)


#Display Bitmap    D2 10    Display bitmap (.BMP) file at identified location on the screen
    #P1 values
CLEAR_DISPLAY = 0x00
OVERLAY_DISPLAY = 0x01
def displayBitmap(bitmap_template, P1=CLEAR_DISPLAY, P2=BACKLIGHT_ON):
    #filename format is 'FILENAME.BMP'
    log.log ('displayBitmap')
    conn.send([0xD2, 0x10, P1, P2], bitmap_template)
    status, buf, uns = getAnswer()
    if len(buf) != 0:
        log.logerr('message had unexpected Data content', buf)
    return 0, status, buf, uns 


#Select Language    D2 D0    Language selection control (Automatic[customer selected], Manual[API selected]) or return current language selected. 
    #P1 values
AUTOMATIC_LANGUAGE = 0x00
MANUAL_LANGUAGE = 0x01
GET_LANGUAGE = 0x02
    #P2 values
GET_LANGUAGE_LIST=0x00
USE_LANGUAGE_SUPPLIED=0x01
def selectLanguage(languageCode='', P1=AUTOMATIC_LANGUAGE, P2=GET_LANGUAGE_LIST):
    log.log ('selectLanguage')
    if len(languageCode)==3 and (P1==MANUAL_LANGUAGE and P2==USE_LANGUAGE_SUPPLIED):
        languageTag = []
        languageTag.append([(0xDF, 0xA2, 0x22), languageCode])
        conn.send([0xD2, 0xD0, P1, P2], languageTag)
    else:
        conn.send([0xD2, 0xD0, P1, P2] )
    status, buf, uns = getAnswer()
    if (P1==MANUAL_LANGUAGE and P2==GET_LANGUAGE_LIST) or P1==AUTOMATIC_LANGUAGE or P1==GET_LANGUAGE :
        tlv = TLVParser(buf)
        if not tlv.tagCount((0xDF, 0xA2, 0x20)):
            log.logerr('message had a missing expected tag or tags (DFA222)', buf)
            return -1, status, buf, uns
    elif len(buf) != 0:
            log.logerr('message had unexpected Data content', buf)   
    return 0, status, buf, uns


#Request Choice    D2 03    Display choice menu with up to 8 choices and await selection.  Chosen option is returned in an unsolicited return message.
def requestChoice(prompt1, prompt2, prompt3, prompt4, prompt5, prompt6, prompt7, prompt8, title='Choice Title', P1=0x00, P2=BACKLIGHT_ON):
    log.log ('requestChoice')
    if len(prompt1) ==0:
        prompt1='prompt1'
    displayTag = []
    displayTag.append( [(0xDF,0xA2,0x02),'1'] )
    displayTag.append( [(0xDF,0xA2,0x03),prompt1] ) 
    if len(prompt2):
        displayTag.append( [(0xDF,0xA2,0x02),'2'] )
        displayTag.append( [(0xDF,0xA2,0x03),prompt2] ) 
    if len(prompt3):
        displayTag.append( [(0xDF,0xA2,0x02),'3'] )
        displayTag.append( [(0xDF,0xA2,0x03),prompt3] )
    if len(prompt4):
        displayTag.append( [(0xDF,0xA2,0x02),'4'] )
        displayTag.append( [(0xDF,0xA2,0x03),prompt4] )
    if len(prompt5):
        displayTag.append( [(0xDF,0xA2,0x02),'5'] )
        displayTag.append( [(0xDF,0xA2,0x03),prompt5] )
    if len(prompt6):
        displayTag.append( [(0xDF,0xA2,0x02),'6'] )
        displayTag.append( [(0xDF,0xA2,0x03),prompt6] )
    if len(prompt7):
        displayTag.append( [(0xDF,0xA2,0x02),'7'] )
        displayTag.append( [(0xDF,0xA2,0x03),prompt7] )
    if len(prompt8):
        displayTag.append( [(0xDF,0xA2,0x02),'8'] )
        displayTag.append( [(0xDF,0xA2,0x03),prompt8] )
    if len(title):
        displayTag.append( [(0xDF,0xA2,0x11),title] )
    conn.send([0xD2, 0x03, P1, P2], displayTag)
    #solicited response
    status, buf, uns = getAnswer()
    return buf, status, buf, uns  # buf loaded with choice value, between 1 and 8


#Manage Display Contract    D0 70    Retrieve or set display contrast. Setting lost on reboot.
    #P1 values
READ_CONTRAST = 0x00
def manageDisplayContract(P1=READ_CONTRAST):
    log.log ('manageDisplayContract')
    conn.send([0xD0, 0x70, P1, 0x00])
    status, buf, uns = getAnswer()
    if P1==READ_CONTRAST:
        tlv = TLVParser(buf)
        if status==0x9000 and not tlv.tagCount((0xDF, 0xA2, 0x0B))==1:
            log.logerr('message had a missing expected tag (DFA20B)', buf)
        return -1, status, buf, uns
    return 0, status, buf, uns 

#Key Board Status    D0 61    Enable reporting of key entry event.  Response occurs unsolicited when keyboard key press occurs.  Each press will result in a new message, this will continue until stopped.
#Get Numeric Data    D2 04    Present selected prompt screen for an numeric field (e.g. price) for entry (or editing) and return resulting customer entry.
#Get Alphanumeric Data    D2 F1    Present selected prompt screen for an alphanumeric field (e.g. car registration number) for entry (or editing) and return resulting customer entry.
#Print Data    D2 A1    Print text on printer and position printer head appropriately on ejecting paper. Response can be set to be solicited or unsolicited.
#Print Bitmap    D2 A2    Print bitmap (.BMP) file on printer at Right or Centre location. Start with CR/line-feed. Response can be set to be solicited or unsolicited.
#Print Barcode    D2 A3    Print barcode on printer. Response can be set to be solicited or unsolicited.
#I2C Read    D1 20    Read data from address location on I2C card
#I2C Write    D1 21    Write data to address location on I2C card
#Memory Card  Read    D1 11    Read data from address location on memory card.  On first read the card data is read and cached on the Terminal, subsequent reads are from the cache.
#Memory Card  Write    D1 12    Write data to address location on memory card. Update to memory data is within Terminal cache only, changes will be lost without <Memory Card Update>
#Memory Card Update    D1 13    Write terminal cache to physical memory card.
#VSP Status    DD 00    Return the VSP encryption service status retrieved from the VTP terminal driver
#VSP Last Encrypted Status    DD 01    Return the status of encryption of the last (current) transaction
#Manual PAN Entry    D2 14    Prompt customer for manual PAN and card Expiration Date, entered data will be return VSP encrypted.
#Get Set Date Time    DD 10    Set, or return, the current date and time on the Terminal.
#Start TGK Process    DD D0    Start process for the updating of VTP encrypt key. If key update is not available a solicited error response will occur.
#Continue TGK Process    DD D2    If the Key transfer to the decryption server has been completed (the POS is responsible for this operation) the Terminal can be instructed to complete, or fail-back, the introduction of the newly generated Keys.
#TGK Status    DD DD    Return the status of the last Key management process.
#Get Contactless Status    C0 00    Return the status of the contactless device
def contactlessStatus(P1=0x00):
    log.log ('contactlessStatus')
    ctlsDeviceFound = False
    conn.send([0xC0, 0x00, P1, 0x00])
    status, buf, uns = getAnswer(True, False) # Continue on error, status not 0x9090
    if status == 0x9000:
        cnt = getDataField(buf, CONVERT_INT)
        if cnt >= 1:
            log.log("Detected ", cnt, " contactless devices")
            ctlsDeviceFound = True
        else:
            log.log('No contactless devices found')
    else:
        log.log('No contactless driver found')
    return ctlsDeviceFound, status, buf, uns

#Open and Initialise Contactless Reader    C0 01    Opens and initialises a closed contactless reader.
def openAndInitialiseContactless():
    log.log ('openAndInitialiseContactless')
    conn.send([0xC0, 0x01, 0x00, 0x00])
    #solicited response
    status, buf, uns = getAnswer()
    if len(buf) != 0:
        log.logerr('message had unexpected Data content', buf)
    return 0, status, buf, uns        

#Close Contactless reader    C0 02    NOT implemented.
def closeContactlessReader():
    log.log ('closeContactlessReader')
    conn.send([0xC0, 0x02, 0x00, 0x00])
    #solicited response
    status, buf, uns = getAnswer()
    if len(buf) != 0:
        log.logerr('message had unexpected Data content', buf)
    return 0, status, buf, uns   

#Update Firmware    C0 FF    Starts firmware update process, the firmware being fetched from a VeriFone defined file/location
#Start Contactless Transaction    C0 A0    Activates polling for contactless card, solicited response indicates success of request. Unsolicited response will return the transaction results for the contactless tap or a timeout.
def startContactlessTransaction(start_ctls_tag=START_CTLS_TAG, timeout=0x00):
    log.log ('startContactlessTransaction')
    start_templ = ( 0xE0, start_ctls_tag )
    conn.send([0xC0, 0xA0, 0x01, timeout], start_templ)
    #solicited response
    status, buf, uns = getAnswer()
    if len(buf) != 0:
        log.logerr('message had unexpected Data content', buf)
    log.log ('Contactless armed for unsolicited event')
    return 0, status, buf, uns

    
#Continue Contactless Transaction    C0 A1    Update balance of the card after transaction was authorised online.
def continueContactlessTransaction(continue_ctls_tag=CONTINUE_CTLS_TAG):
    log.log ('continueContactlessTransaction')
    continue_ctls_templ = ( 0xE0, continue_ctls_tag )
    conn.send([0xC0, 0xA1, 0x00, 0x00], continue_ctls_templ)
    #solicited response
    status, buf, uns = getAnswer()
    if len(buf) != 0:
        log.logerr('message had unexpected Data content', buf)
    #unsolicited response
    status, buf, uns = getAnswer(False) #Don't ignore unsolicited
    if len(buf) != 0:
        log.logerr('message had unexpected Data content', buf)
    if not uns:
        log.logerr ('unexpected solicited message received ', buf)
        return -1, status, buf, uns
    return 0, status, buf, uns
    
    
#Cancel Contactless Transaction    C0 C0    Cancel previous 'Start Contactless Transaction' . Unsolicited response will return with the transaction status, usually 'cancelled'.
def cancelContactlessTransaction():
    log.log ('cancelContactlessTransaction')
    conn.send([0xC0, 0xC0, 0x00, 0x00])
    #solicited response
    status, buf, uns = getAnswer()
    if len(buf) != 0:
        log.logerr('message had unexpected Data content', buf)
    #unsolicited response
    status, buf, uns = getAnswer(False) #Don't ignore unsolicited
    if not uns:
        log.logerr ('unexpected solicited message received ', buf)
        return -1, status, buf, uns
    log.log ('cancelContactlessTransaction, result code ', buf)
    return 0, status, buf, uns



######################################################
######################################################
##   Transaction (High LEvel) Flow Helper Functions ##
######################################################
######################################################

#Check on Insertion status of ICC card
def emvCardState(tlv):
    result = -1
    # Check for card status
    if tlv.tagCount(0x48):
        ins_tag_val = tlv.getTag(0x48, TLVParser.CONVERT_INT)[0]
        ins_tag_val &= 0xFF00
        ins_tag_val >>= 8
        if ins_tag_val == 3:
            log.log('ICC Card inserted')
            result = EMV_CARD_INSERTED
        else:
            if ins_tag_val == 0:
                log.log('ICC Card removed')
                result = EMV_CARD_REMOVED
            else:
                log.log('ICC Card unknown state')
                result = ERROR_UNKNOWN_CARD
    return result

#Check on status of Magstripe card
def magstripeCardState(tlv):
    result = -1
    # Check for card status
    if tlv.tagCount(0x48):
        ins_tag_val = tlv.getTag(0x48, TLVParser.CONVERT_INT)[0]
        ins_tag_val &= 0x00FF
        if ins_tag_val == 1:
            log.logerr('Magstripe, but no tracks!')
            result = ERROR_UNKNOWN_CARD
        else:
            if ins_tag_val == 0:
                log.log('ICC Card removed!')
                result = EMV_CARD_REMOVED
            else:
                log.logerr('Magstripe track data available')
                result = MAGSTRIPE_TRACKS_AVAILABLE
    return result

#handler to wait for card removal
def awaitCardRemoval():
    displayCommand(P1=0x0E)
    #unsolicited response
    while True:
        status, buf, uns = getAnswer(False) #Don't ignore unsolicited
        if not uns:
            log.logerr ('unexpected solicited message received ', buf)
            return -1, status, buf, uns
        tlv = TLVParser(buf)
        if emvCardState(tlv) == EMV_CARD_REMOVED:
            break
    return 0, status, buf, uns

#handler to await card event
def awaitCardEvent():
    #unsolicited response
    while True:
        status, buf, uns = getAnswer(False) #Don't ignore unsolicited
        if not uns:
            log.logerr ('unexpected solicited message received ', buf)
            return -1, status, buf, uns
        tlv = TLVParser(buf)
        result = emvCardState(tlv)
        if result != ERROR_UNKNOWN_CARD:
            return result, status, buf, uns
        else:
            result = magstripeCardState(tlv)
            return result, status, buf, uns
    return -1, status, buf, uns 



def transactionExample():
    tid, status, buf, uns = resetDevice()                           #reset device and retrieve Terminal ID for VSP usage
    result, status, buf, uns = openAndInitialiseContactless()       #initialise contactless reader
    result, status, buf, uns = cardStatus()                         #start monitoring for card movements
    ctlsDeviceFound, status, buf, uns = contactlessStatus(P1=0x00)  #Check Contactless reader ready
    if not ctlsDeviceFound:
        displayCommand(P1=0x0D)                                     #No contactless reader available, prompt for card
    else:
        result, status, buf, uns = startContactlessTransaction()    #Else, enable for contactless transaction
     
    log.log ('waiting for card movement Tap/Insert/Swipe')
    #At this point we are either getting a Contactless or an Insert/Swipe
    while True:
        status, buf, uns = getAnswer(False) #Don't ignore unsolicited
        if not uns:
            log.logerr ('unexpected solicited message received ', buf)
            return -1, status, buf, uns
        tlv = TLVParser(buf)
        if tlv.tagCount(0x48):   #Card Insertion Detected, proceed with ICC or Magswipe handling
            emvStatus = emvCardState(tlv)
            magStatus = magstripeCardState(tlv)
            #First stop contactless if it was started
            if ctlsDeviceFound and (emvStatus==EMV_CARD_INSERTED  or magStatus==MAGSTRIPE_TRACKS_AVAILABLE):
                result, status, buf, uns = cancelContactlessTransaction()
            #ICC Card Handling
            if emvStatus == EMV_CARD_INSERTED:
                log.log("Card inserted, process EMV transaction")
                result, status, buf, uns = startTransaction()
                #putData
                result, status, buf, uns = putData('\x00\x00\x00\x00\x10\x70', 0x9f, 0x02)
                #getData
                result, status, buf, uns = getData(0x9F, 0x02)
                #VSP handling
                tlvEMV=TLVParser(buf)
                if vspIsEncrypted(tlvEMV):
                    vspDecrypt(tlvEMV, tid)
                #continue transaction
                if result == MAGSWIPE_FALLBACK:
                    result, status, buf, uns = awaitCardRemoval()
                    displayCommandString('Please Try MagStipe')               
                    continue  #Card movement should generate another unsolicited message
                result, status, buf, uns = continueTransaction()
                if result == ONLINE_REQUESTED:
                    displayCommand(0x05)
                    result, status, buf, uns = continueTransaction(CONTINUE2_TRANS_TAG)
                log.log('Prompt for ICC card removal')
                awaitCardRemoval()
                return result, status, buf, uns
            elif emvStatus == EMV_CARD_REMOVED  and magStatus!=MAGSTRIPE_TRACKS_AVAILABLE:
                log.log('Unexpected ICC card removal')
                return -1, status, buf, uns
            else:
                pass # fall through
            #MagSwipe card handling, if ICC not found
            if magStatus == MAGSTRIPE_TRACKS_AVAILABLE:
                log.log("Card swiped, process MagStripe transaction")
                #VSP handling
                if vspIsEncrypted(tlv):
                    vspDecrypt(tlv, tid)
                #continue transaction
                return 0, status, buf, uns
            elif emvStatus == ERROR_UNKNOWN_CARD or magStatus == ERROR_UNKNOWN_CARD:
                log.log('Unknown card type')
                return -1, status, buf, uns
            else:
                log.logerr('card state undefined')
                return -1, status, buf, uns
        else:  
            # Contactless transaction  
            if tlv.tagCount(0xE3):
                log.log ('transaction approved')
                return TRANSACTION_APPROVED, status, buf, uns 
            if tlv.tagCount(0xE4):
                log.log ('online request, transaction must be verified online')
                result, status, buf, uns = continueContactlessTransaction()
                tlv = TLVParser(buf)
                if tlv.tagCount(0xE3):
                    log.log ('transaction approved')
                    return TRANSACTION_APPROVED, status, buf, uns 
                if tlv.tagCount(0xE5):
                    log.log ('transaction declined')
                    return TRANSACTION_DECLINED, status, buf, uns
                log.log ('Online requested, unexpected result not clear')  
                return result, status, buf, uns 
            if tlv.tagCount(0xE5):
                log.log ('transaction declined')
                return TRANSACTION_DECLINED, status, buf, uns  
            if tlv.tagCount(0xE7):
                log.log ('Contactless MagStripe card was tapped')    
                return CONTACTLESS_MAGSTRIPE_TAP, status, buf, uns 
            log.logerr('no appropriate template received in response Data')
            return -1, status, buf, uns    



######################################################
######################################################
################## Main Test Script ##################
########## This is where the tests are run ###########
######################################################
######################################################
# Main function
def processTestCase():
    req_unsolicited = conn.connect()
    if req_unsolicited:
        #Receive unsolicited
        log.log('Waiting for unsolicited')
        status, buf, uns = getAnswer(False)
        log.log('Unsolicited', TLVParser(buf))
    
    
    abortDevice()
    resetDevice()

#    freeSpace()
#    batteryStatus()

### File handling script test cases    
#    filemask='*.*'
#    findFirstFile(filemask, True)
#    findNextFile(filemask, True)
#    fileread="VCSCORE.INS"
#    selectFile(fileread)
#    readBinary([0x05], P1=0x00, P2=0x0F)
#    readBinary([0x01, 0x0F, 0x05], P1=0x80, P2=0x00)

#    testFile='MARKTEST.TXT'
#    renameFile='MARKTEST.OLD'
#    testMessage='Marks Test Message to Test File'
#    selectFile(testFile, TRUNCATE_FILE)  #TRUNCATE_FILE=0x05
#    getBinaryStatus(testFile)
#    updateBinary('Marks Test Message to Test File', 0x00, 0x00, True)
#    readBinary([0x1F])
#    deleteBinary(testFile)
#    renameBinary('MARKTEST.OLD', testFile, P1=RENAME_SUPPLIED_FILE)
#    getBinaryStatus(renameFile)
#    deleteBinary(renameFile, True)
    

###Display script test cases
#    requestChoice('prompt1', 'prompt2', 'prompt3', 'prompt4', 'prompt5', 'prompt6', 'prompt7', 'prompt8', title='Title')
#    requestChoice('promptA', 'promptB', 'promptC', 'promptD', 'promptE', 'promptF', 'promptG', 'promptH', title='Title')
#    displayCommand() #Back to idle
#    selectLanguage()
#    selectLanguage('', GET_LANGUAGE)
#    selectLanguage('', MANUAL_LANGUAGE, GET_LANGUAGE_LIST)
#    selectLanguage('SPA', MANUAL_LANGUAGE, USE_LANGUAGE_SUPPLIED)   
#    selectLanguage('', GET_LANGUAGE)
#    selectLanguage('ENG', MANUAL_LANGUAGE, USE_LANGUAGE_SUPPLIED)   
#    selectLanguage('', GET_LANGUAGE)
#    displayCommandString('Left first line\x07\x0D\x09Centered second line\x0DLeft third line\x0D\x09Centered forth line\x0D\x07(Line 5 beep)\x0D\x09\x07(Last Line beep)')
#    manageDisplayContract()

### Transaction Test Example      
#    result, status, buf, uns = transactionExample()
#    displayCommand(0x0C)
#    if result == TRANSACTION_APPROVED:
#        displayCommandString('Transaction Approved')
#        sleep (2)
#    if result == TRANSACTION_DECLINED:
#        displayCommandString('Transaction Declined')
#        sleep (2)
#    displayCommand() #Back to idle


###########  Script entry point,  calls main test process ##########################
if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection()

    utility.register_testharness_script(processTestCase)
    utility.do_testharness()
