from testharness import *
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from testharness.tlvparser import TLVParser, tagStorage
import binascii
import random
import os


CERT_DIR = ".certs"

def AuthVerify():

    posDevCertDecodedFile = os.path.join(CERT_DIR, "pos_device_cert.dec")
    posDevCertFile = os.path.join(CERT_DIR, "pos_device_cert.enc")
    posSEKFormattedDecodedFile = os.path.join(CERT_DIR, "pos_sek_formatted.dec")
    posSEKDecodedFile = os.path.join(CERT_DIR, "pos_sek.dec")
    termSEKDecodedFile = os.path.join(CERT_DIR, "term_sek.dec")
    posSEKFile = os.path.join(CERT_DIR, "pos_sek.enc")
    posRandomFile = os.path.join(CERT_DIR, "pos.rnd")
    termRandomFile = os.path.join(CERT_DIR, "term.rnd")
    posDIDFile = os.path.join(CERT_DIR, "pos.did")
    termDIDFile = os.path.join(CERT_DIR, "term.did")
    POSKey = os.path.join(CERT_DIR, "pos.key")
    terminalPub = os.path.join(CERT_DIR, "ped.pub")
    mutualSEKFile = os.path.join(CERT_DIR, "mutual_sek.dec")


    fposRND = open(posRandomFile, 'rb')
    posRandom = fposRND.read()
    fposRND.close()
    
    ftermRND = open(termRandomFile, 'rb')
    termRandom = ftermRND.read()
    ftermRND.close()
    
    fposDID = open(posDIDFile, 'rb')
    posDID = fposDID.read()
    fposDID.close()

    ftermDID = open(termDIDFile, 'rb')
    termDID = ftermDID.read()
    ftermDID.close()                

    posDevCert = bytearray(b'\x00\x01')
    for x in range(256-39):
        posDevCert.append(255)
    posDevCert.append(0)
    posDevCert = b"".join([posDevCert, posRandom])
    posDevCert = b"".join([posDevCert, termRandom])
    posDevCert = b"".join([posDevCert, termDID])
    posDevCert = b"".join([posDevCert, posDID])

    with open(posDevCertDecodedFile, "wb") as f:
        f.write(posDevCert)
        f.close()

    formattedPosSEK = bytearray(b'\x00\x01')
    for x in range(256-19):
        formattedPosSEK.append(255)
    formattedPosSEK.append(0)
    posSEK = ''.join([random.choice('0123456789ABCDEF') for x in range(32)])
    bposSEK = binascii.unhexlify(posSEK)
    formattedPosSEK = b"".join([formattedPosSEK, bposSEK])
    
    with open(posSEKDecodedFile, "wb") as f:
        f.write(bposSEK)
        f.close()

    with open(posSEKFormattedDecodedFile, "wb") as f:
        f.write(formattedPosSEK)
        f.close()
        
    log.log("Signing POS device certificate")
    opensslcmd = "openssl rsautl -sign -raw -inkey " + POSKey + " -in " + posDevCertDecodedFile + " -out " + posDevCertFile
    os.system(opensslcmd)
    if os.path.isfile(posDevCertFile) :
        log.log("POS device certificate is signed")
        f = open(posDevCertFile, 'rb')
        posDevCertEnc = f.read()
        f.close()


    log.log("Encrypting POS stream encrytion key")
    opensslcmd = "openssl rsautl -verify -raw -inkey " + terminalPub + " -pubin -in " + posSEKFormattedDecodedFile + " -out " + posSEKFile
    os.system(opensslcmd)
    if os.path.isfile(posSEKFile) :
        log.log("POS stream encrytion key is encrypted")
        f = open(posSEKFile, 'rb')
        formattedPosSEKEnc = f.read()
        f.close()
    
    
    f = open(posSEKDecodedFile, 'rb')
    poskey = bytearray(f.read())
    f.close()
    
    f = open(termSEKDecodedFile, 'rb')
    termkey = bytearray(f.read())
    f.close()    

    for i in range(len(poskey)):
        termkey[i] ^= poskey[i]

    f = open(mutualSEKFile, 'wb')
    f.write(termkey)
    f.close()
    
    log.log("Mutual stream encryption key is saved: ", mutualSEKFile)
        
            
    ''' First create connection '''
    req_unsolicited = conn.connect()
    ''' If unsolicited read it'''
    if req_unsolicited:
            status, buf, uns = conn.receive()

    ''' Send data '''
    c_tag = tagStorage()
    c_tag.store( (0xDF, 0x83, 0x14), posDevCertEnc )
    c_tag.store( (0xDF, 0x83, 0x15), formattedPosSEKEnc )

    conn.send([0xDD, 0x22, 0x01, 0x00] , c_tag.getTemplate(0xE0))
    status, buf, uns = conn.receive()
    check_status_error( status )

if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script( AuthVerify )
    utility.do_testharness()
