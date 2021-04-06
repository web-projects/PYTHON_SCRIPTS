from testharness import *
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from testharness.tlvparser import TLVParser, tagStorage
from binascii import hexlify, unhexlify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import os.path

# 20201207: args support
import TC_testharness.utility as util
from functools import partial

''' Online PIN Decriptor, deciphers received data '''
def OnlinePINDecriptor(args):

    # If SRED is enabled and pan_cache_timeout is specified in the [vipa] section
    # of MAPP_VSD_SRED.CFG, the last cached PAN will be used for PIN Block
    # Formats that require PAN in case the PAN tag is not supplied.
    #PANDATA = b'\x54\x13\x33\x00\x89\x00\x00\x39'
    PANDATA = bytes.fromhex('67 99 99 89 00 00 00 70 19 09')
    
    #encryptedPIN = args.data
    #ksn = args.ksn
    
    # THESE ARE DEFAULT
    #ksn          = 'F8765432100002C00228'
    #encryptedPIN = 'c1e7944deff4af07' 
    
    # *-- LIVE CHECKS HERE --*
    
    # FAILS
    #encryptedPIN = '4D01EAE255AE3058'
    #ksn          = 'F8765432100006C0023F'
    #encryptedPIN = 'EC26C41B691E5D98'
    #ksn          = 'F8765432100002C000D7'
    
    # PASSES
    #encryptedPIN = 'ADDE494E7BD8E798'
    #ksn          = 'F8765432100006E0023E'
    
    # FISERV
    #encryptedPIN = '81629D3E02DBB9C6'
    #ksn          = 'F8765432100006C00276'
    
    encryptedPIN = 'A57552123B5FC72A'
    ksn          = 'F876543210040B800004'
    
    #        0123456789012345678:
    log.log("KSN                :", ksn)
    log.log("Encrypted PIN      :", encryptedPIN)
        
    # We have KSN, let's find key
    # 2) DERIVE PIN KEY FROM KSN USING Idtech Decrypt/Encrypt Tool
    keyTable = { 
                 # *--- DON'T DELETE TEST KSN-KEY --*
                 'F8765432100002C00228' : 'CDA4448CD1A4C697B52E2276B3E7D29B',
                 # *--- ADD KSN-KEYS HERE: ---*
                 'F8765432100006C00246' : '971A751C9B464FD0BAFFD4DAEF58306B',
                 'F8765432100006C0023F' : '967B56D11EF7CFB28E22C4C29344A4EF',
                 'F8765432100006E0023E' : '536A043DA5D2C73353061F86373339E6',
                 'F8765432100002C000D7' : '523917AE5A75E2AB179985C735947D52',
                 'F8765432100006C00276' : '507C16CE5C34A83F8B23539A1B2FCC6C',
                 'F876543210040B800004' : 'EFAF6BEFB369350A808255E5C1F6F8AF',
               }
               
    if not ksn in keyTable:
        raise exceptions.logicalException("Cannot find key in static table - please inject Security keys again!!!")
        
    key = keyTable[ksn]
    #        0123456789012345678:
    log.log("DECRYPTING Key     :", key + "\r\n")
    encryptedPIN = unhexlify(encryptedPIN)
    open("pin.dat", "wb").write(encryptedPIN)
    if os.path.isfile("pindec.dat"):
        os.remove("pindec.dat")

    vscmd = "openssl"
    #args = ' ' + "des-ede -nosalt -nopad -d -in pin.dat -out pindec.dat -k " + key
    args = ' ' + "des-ede -p -nosalt -nopad -d -in pin.dat -out pindec.dat -K " + key + " -iv 0000000000000000"
    log.log("calling openssl ", vscmd, ", params: ", args + "\r\n")
    if os.system(vscmd + args):
        raise exceptions.logicalException("Openssl call failed.")
    
    dec = open("pindec.dat", "rb").read()
    #        0123456789012345678:
    log.log("Decrypted PIN block:", hexlify(dec))
    pinLen = dec[0] & 0x0F
    log.log("PIN length detected:", pinLen)
    if (pinLen < 4 or pinLen > 12):
        raise exceptions.logicalException("Invalid PIN Block length!")
    if (pinLen % 2): 
      pinLen += 1
    pinLen = (int)(pinLen / 2)
    log.log("PIN ENTERED _______:", hexlify(dec[1:pinLen + 1]))

    log.log("PAN _______________:", hexlify(PANDATA).decode('ascii'))
    PANDATA = bytearray(unhexlify((hexlify(bytearray(PANDATA))[-13:])[:12]))
    PANDATA.reverse()
    encodedPIN = bytearray(dec)
    encodedPIN.reverse()
    appendCnt = len(encodedPIN)-len(PANDATA)
    #print('encoded pin: ', hexlify(encodedPIN))
    #print('pan: ', hexlify(PANDATA))
    clearPIN = bytearray()
    for idx in range(len(PANDATA)):
        #print('encpin val ', encodedPIN[idx], '; pan val ', PANDATA[idx])
        val = encodedPIN[idx]
        val ^= PANDATA[idx]
        clearPIN.append(val)

    encodedPIN.reverse()
    while (appendCnt > 0):
        appendCnt -= 1
        clearPIN.append(encodedPIN[appendCnt])
    clearPIN.reverse()
    log.log("PIN block _________:", hexlify(clearPIN))
    clearPIN = clearPIN[1:pinLen+1]
    PIN = str(hexlify(clearPIN)).replace("f", "")
    log.loginfo('PIN entered _______:', PIN)
    os.remove("pin.dat")
    os.remove("pindec.dat")


if __name__ == '__main__':
   
   log = getSyslog()
   
   arg = util.get_argparser();
   arg.add_argument( '--ksn', dest='ksn', default='F8765432100002C00228',
                      help='ONLINE PIN KSN' )
   arg.add_argument( '--data', dest='data', default='c1e7944deff4af07',
                      help='Encrypted PIN Data' )
   args = util.parse_args()
                            
   utility.register_testharness_script(
        partial( OnlinePINDecriptor, args ))
   utility.do_testharness()
