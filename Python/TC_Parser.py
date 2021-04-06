from testharness import *
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from testharness.tlvparser import TLVParser, tagStorage, TLVPrepare
from binascii import hexlify, unhexlify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import os.path

# 20201207: args support
import TC_testharness.utility as util
from functools import partial

def AidList(tags):

    aidList = []
    lblList = []

    for item in tags:
        value = hexlify(item[1]).decode('ascii')
        log.log(value)
        # 4f: AID
        aidIndex = value.find('4f')
        if aidIndex != -1:
            dataLen = int(value[aidIndex+2:aidIndex+4], 16) * 2
            aid = value[aidIndex+4:aidIndex+4+dataLen]
            #log.log("AID:" + aid)
            aidList.append(aid)
            # 50: LABEL
            labelIndex = value.find('50')
            if labelIndex != -1:
                dataLen = int(value[labelIndex+2:labelIndex+4], 16) * 2
                label = value[labelIndex+4:labelIndex+4+dataLen]
                label = bytes.fromhex(label)
                label = label.decode('ascii')
                #log.log("LABEL:" + label)
                lblList.append(label)

    for i in range(len(aidList)):
            log.log('App', i+1, ': AID ' + aidList[i] + ', label ' + lblList[i])

def TCParser(args):

    val = 'bf0c56611f4f07a0000000041010500a4d6173746572436172648701019f0a0400010102611c4f07a000000004306050074d61657374726f8701029f0a040001010161154f07a000000004220350074d61657374726f870103'
    val += '9000'
    buf = unhexlify(val)
    tlvp = TLVPrepare()
    tlv_tags = tlvp.parse_received_data( buf )

    tags = TLVParser(tlv_tags)
    AidList(tags)


if __name__ == '__main__':
   
   log = getSyslog()
   
   arg = util.get_argparser();
   arg.add_argument( '--ksn', dest='ksn', default='F8765432100002C00228',
                      help='ONLINE PIN KSN' )
   arg.add_argument( '--data', dest='data', default='c1e7944deff4af07',
                      help='Encrypted PIN Data' )
   args = util.parse_args()
                            
   utility.register_testharness_script(
        partial( TCParser, args ))
   utility.do_testharness()
