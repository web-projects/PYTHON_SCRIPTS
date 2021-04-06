from testharness import *
from sys import exit
from sys import stdout
from testharness.syslog import getSyslog
from testharness.tlvparser import TLVParser, tagStorage
from functools import partial
from shutil import copyfile
from binascii import hexlify, unhexlify
import testharness.utility as util
import testharness.fileops as fops
import testharness.exceptions as exc
import os
import os.path
import random

class Except(Exception):
    def __init__(self, message):
        self.msg = message

    def __str__(self):
        return repr(self.msg)

CERT_DIR = ".certs"
CAKey = os.path.join(CERT_DIR, "ca.key")
CACert = os.path.join(CERT_DIR, "ca.pem")
CACertSign = os.path.join(CERT_DIR, "ca.pem.P7S")
POSKey = os.path.join(CERT_DIR, "pos.key")
POSCSR = os.path.join(CERT_DIR, "pos.csr")
POSCert = os.path.join(CERT_DIR, "pos.pem")
TermPub = os.path.join(CERT_DIR, "ped.pub")

def query_yes_no(question, default="no"):
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        choice = input("\n" + question + prompt)
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")

def toascii( inp ):
    if inp==None: return ''
    inp = bytearray(inp if type(inp)!=int else [inp])
    return str(inp, 'iso8859-1')

def Connect(conn, log):
    req_unsolicited = conn.connect()
    if req_unsolicited:
        status, buf, uns = conn.receive()
        if status != 0x9000:
            log.logerr('Unsolicited fail')
            exit(-1)
        log.log('Unsolicited', TLVParser(buf) )

def PutFile( conn, log, filename , remotefilename ):
    progress = partial( util.display_console_progress_bar, util.get_terminal_width() )
    try:
        fops.updatefile( conn, log, filename, remotefilename, False, progress=progress )
    except exc.invResponseException as e:
        log.logerr( "Unable to use updatefile fallback to putfile" )
        fops.putfile( conn, log, filename, remotefilename, progress=progress )

def CreateCACertificate(conn, log):
    log.loginfo("Upload: CACertificate")
    if not ( os.path.isfile(CAKey) or os.path.isfile(CACert) or os.path.isfile(CACertSign) ):
        log.loginfo("CreateCACertificate")
        os.system("openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout " + CAKey + " -out " + CACert + " -config " + os.path.join(CERT_DIR,"openssl.conf") )
        os.system("filesignature --file " + CACert + " I --config verix")
    try:
        log.loginfo("CA put --> POS")
        PutFile(conn, log, CACert, os.path.basename(CACert))
        PutFile(conn, log, CACertSign, os.path.basename(CACertSign)) 
    except exc.invResponseException as e:
        log.logerr("Can't PutCertificates! please check exclusion.dat, connection etc")
        log.logerr(str(e))
        exit(1)
    log.log("File "+ CACert + " and " + CACertSign + " loaded")

def CreatePOSCertificate(log):
    if not (os.path.isfile(POSKey) and os.path.isfile(POSCSR) and os.path.isfile(POSCert)):
        log.log("Creating POS certificate")
        os.system("openssl genrsa -out " + POSKey )
        log.log("Creating POS key: " + POSKey)
        os.system("openssl req -new -key " + POSKey + " -out " + POSCSR + " -config " + os.path.join(CERT_DIR,"openssl2.conf") )
        log.log("Creating POS sign request" + POSCSR)        
        os.system("openssl x509  -req -days 360 -in " + POSCSR + " -CA " + CACert + " -CAkey " + CAKey + " -CAcreateserial -out " + POSCert)
        if not os.path.isfile(POSCert):
            raise(Except("ERROR: POSCert is not created!"))
    else:
        log.log("POS certificate already ready")


def GenerateRSAKey():
    if not os.path.exists(CERT_DIR):
        os.makedirs(CERT_DIR)

    if query_yes_no("Gen new certs?", default="no"):
        CreateCACertificate(conn, log)
        CreatePOSCertificate(log)

    log.loginfo("Mutual auth cert handshake, DD 23 can take a while ( ~10sec) ")
    ''' 0x08 1024 in ~ 10 sec '''
    ''' 0x08 2048 in ~ 1 min  '''
    ''' 0x10 4096 in~ 10 min  '''
    
    conn.send([0xDD, 0x23, 0x00, 0x00], ( 0xE0, [ [(0xDF,0x83,0x1C), b'\x08\x00'] ] ))
    status, buf, uns = conn.receive()
    util.check_status_error( status )

    tlv = TLVParser(buf)
    if (tlv.tagCount( (0xDF, 0x83, 0x1B) ) == 1):
        certSignReq = tlv.getTag((0xDF, 0x83, 0x1B))[0]
        strCSR = toascii( certSignReq )

        csrFile = os.path.join(CERT_DIR, "ped.csr")
        terminalCert = os.path.join(CERT_DIR, "ped.pem")
        
        log.log("Saving CSR")
        file = open(csrFile, 'w')
        file.write(strCSR) 
        file.close()
        
        log.log("Signing terminal CSR + save in: ", terminalCert)
        os.system("openssl x509 -req -days 360 -in " + csrFile + " -CA " + CACert + " -CAkey " + CAKey + " -CAcreateserial -out " + terminalCert)
        ''' Retrieve public key from ped'''
        log.log("Extracting terminal public key from terminal certificate")
        os.system("openssl x509 -pubkey -noout -in " + terminalCert + "  > " + TermPub)
        log.log("Terminal public key is extracted: " + TermPub + " sending signed terminal certificate to terminal")
        PutFile(conn, log, terminalCert, "ped.pem")
    else:
        log.logerror("Terminal response fialure")
        exit(1)
    log.loginfo("Key generation and upload success!")

def Authenticate():
    termDevCert = os.path.join(CERT_DIR, "terminal_device_cert.enc")
    termDevCertDecoded = os.path.join(CERT_DIR, "terminal_device_cert.dec")
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
    if os.path.isfile(POSCert):
        log.loginfo("Using POSCert")
        with open(POSCert, 'r') as f:
            posCertContent = f.read()
 
    ''' Send data '''
    c_tag = tagStorage()
    c_tag.store( (0xDF, 0x83, 0x13), posRandom )
    c_tag.store( (0xDF, 0x83, 0x1A), posDID )
    if posCertContent:
        c_tag.store( (0xDF, 0x83, 0x11), posCertContent )
    c_tag.store( (0xDF, 0x83, 0x12), os.path.basename(POSCert) )

    conn.send([0xDD, 0x21, 0x00, 0x00] , c_tag.getTemplate(0xE0))
    status, buf, uns = conn.receive()
    util.check_status_error( status )
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
        os.system("openssl rsautl -verify -raw -inkey " + TermPub + " -pubin -in " + termDevCert + " -out " + termDevCertDecoded)
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
    bposSEK = unhexlify(posSEK)
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
    log.loginfo("openssl rsautl -verify -raw -inkey " + TermPub + " -pubin -in " + posSEKFormattedDecodedFile + " -out " + posSEKFile )
    os.system("openssl rsautl -verify -raw -inkey " + TermPub + " -pubin -in " + posSEKFormattedDecodedFile + " -out " + posSEKFile )
    if os.path.isfile(posSEKFile) :
        log.log("POS stream encrytion key is encrypted")
        f = open(posSEKFile, 'rb')
        formattedPosSEKEnc = f.read()
        if not len(formattedPosSEKEnc) > 0:
            raise(Except("Restored random value messed up - there is nothing, check ssl command in log above for hand verification"))
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
        
    ''' Send data '''
    c_tag = tagStorage()
    c_tag.store( (0xDF, 0x83, 0x14), posDevCertEnc )
    c_tag.store( (0xDF, 0x83, 0x15), formattedPosSEKEnc )

    log.log(str(c_tag.getTemplate(0xE0)))

    conn.send([0xDD, 0x22, 0x01, 0x00] , c_tag.getTemplate(0xE0))
    status, buf, uns = conn.receive()
    util.check_status_error( status )
    log.loginfo("Success stream encryption keys auth done")

if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    Connect(conn, log)
    if query_yes_no("Generate keys?", default="yes"):
        utility.register_testharness_script( GenerateRSAKey )
    utility.register_testharness_script( Authenticate )
    utility.register_testharness_script( AuthVerify )
    utility.do_testharness()
