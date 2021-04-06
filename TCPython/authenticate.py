from testharness import *
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from testharness.tlvparser import TLVParser, tagStorage
from binascii import hexlify, unhexlify
import os
import ast

CERT_DIR = ".certs"

def Authenticate():

    POSCert = os.path.join(CERT_DIR, "pos.pem")
    POSKey = os.path.join(CERT_DIR, "pos.key")
    termDevCert = os.path.join(CERT_DIR, "terminal_device_cert.enc")
    termDevCertDecoded = os.path.join(CERT_DIR, "terminal_device_cert.dec")
    terminalPub = os.path.join(CERT_DIR, "ped.pub")
    posRandomFile = os.path.join(CERT_DIR, "pos.rnd")
    posDIDFile = os.path.join(CERT_DIR, "pos.did")
    termRandomFile = os.path.join(CERT_DIR, "term.rnd")
    termDIDFile = os.path.join(CERT_DIR, "term.did")
    termSEKFile = os.path.join(CERT_DIR, "term_sek.enc")
    termSEKFormattedDecodedFile = os.path.join(CERT_DIR, "term_sek_formatted.dec")
    termSEKDecodedFile = os.path.join(CERT_DIR, "term_sek.dec")
    
    posRandom = [0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78]
    posDID = [0x98, 0x76, 0x54, 0x32, 0x10, 0x98, 0x76, 0x54, 0x32, 0x10]
    
    posCertContent = ""
    if os.path.isfile(POSCert) :
        with open('.certs/pos.pem', 'r') as f:
            posCertContent = f.read()
 
    ''' First create connection '''
    req_unsolicited = conn.connect()
    ''' If unsolicited read it'''
    if req_unsolicited:
            status, buf, uns = conn.receive()

    ''' Send data '''
    c_tag = tagStorage()
    c_tag.store( (0xDF, 0x83, 0x13), posRandom )
    c_tag.store( (0xDF, 0x83, 0x1A), posDID )
    if posCertContent:
        c_tag.store( (0xDF, 0x83, 0x11), posCertContent )
    c_tag.store( (0xDF, 0x83, 0x12), "pos.pem" )

    conn.send([0xDD, 0x21, 0x00, 0x00] , c_tag.getTemplate(0xE0))
    status, buf, uns = conn.receive()
    check_status_error( status )
    tlv = TLVParser(buf)
    if (tlv.tagCount( (0xDF, 0x83, 0x14) ) == 1 and tlv.tagCount( (0xDF, 0x83, 0x1D) ) == 1):
        encryptedDevCert = tlv.getTag((0xDF, 0x83, 0x14))[0]
        log.log("Signed Device certificate: ", hexlify(encryptedDevCert))

        clearRND = tlv.getTag((0xDF, 0x83, 0x1D))[0]
        log.log("Clear random number: ", hexlify(clearRND))
        
        log.log("Saving terminal device certificate: " + termDevCert)
        fTermDC = open(termDevCert, 'wb')
        fTermDC.write(encryptedDevCert)
        fTermDC.close()
        
        log.log("Saving POS random")
        fposRND = open(posRandomFile, 'wb')
        fposRND.write(bytearray(i for i in posRandom))
        fposRND.close()
        
        log.log("Saving POS DID")
        fposDID = open(posDIDFile, 'wb')
        fposDID.write(bytearray(i for i in posDID))
        fposDID.close()
        
        log.log("Decoding terminal device certificate")
        opensslcmd = "openssl rsautl -verify -raw -inkey " + terminalPub + " -pubin -in " + termDevCert + " -out " + termDevCertDecoded
        os.system(opensslcmd)
        if os.path.isfile(termDevCertDecoded) :
            with open(termDevCertDecoded, "rb") as f:
                byte = f.read(2)
                log.log("byte start: ", hexlify(byte))
                byte = f.read(1)
                log.log("byte 3: ", byte)
                while byte == b'\xff' :
                    byte = f.read(1)
                log.log("byte last: ", hexlify(byte))
                clearRNDRemote = f.read(8)
                RNDOwn = f.read(8)
                DIDOwn = f.read(10)
                DIDRemote = f.read(10)
            
            log.log("Clear random number REMOTE: ", hexlify(clearRNDRemote))
            if clearRND == clearRNDRemote :
                log.log("Random is validated")
                log.log("Saving term random")
                ftermRND = open(termRandomFile, 'wb')
                ftermRND.write(clearRNDRemote)
                ftermRND.close()
                log.log("Saving term DID")
                ftermDID = open(termDIDFile, 'wb')
                ftermDID.write(DIDRemote)
                ftermDID.close()                
            else:
                log.log("Random is NOT validated")

    if (tlv.tagCount( (0xDF, 0x83, 0x15) ) == 1 ):
        encStreamEncKey = tlv.getTag((0xDF, 0x83, 0x15))[0]
        
        log.log("Saving terminal stream encryption key")
        fTermSEK = open(termSEKFile, 'wb')
        fTermSEK.write(encStreamEncKey)
        fTermSEK.close()
        
        log.log("Decoding terminal stream encryption key")
        opensslcmd = "openssl rsautl -sign -raw -inkey " + POSKey + " -in " + termSEKFile + " -out " + termSEKFormattedDecodedFile
        os.system(opensslcmd)
        if os.path.isfile(termSEKFormattedDecodedFile) :
            log.log("Terminal SEK is decoded")
            with open(termSEKFormattedDecodedFile, "rb") as f:
                byte = f.read(2)
                log.log("byte start: ", hexlify(byte))
                byte = f.read(1)
                log.log("byte 3: ", byte)
                while byte == b'\xff' :
                    byte = f.read(1)
                log.log("byte last: ", hexlify(byte))
                decStreamEncKey = f.read(16)
            
            log.log("Clear terminal SEK: ", hexlify(decStreamEncKey))
            log.log("Saving clear terminal stream encryption key")
            fTermSEK = open(termSEKDecodedFile, 'wb')
            fTermSEK.write(decStreamEncKey)
            fTermSEK.close()


if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script( Authenticate )
    utility.do_testharness()
