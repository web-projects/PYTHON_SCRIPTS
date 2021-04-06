from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog

def semtec_function():
    log = getSyslog()
    log.log(' Hello semtec')
    enc = semtec.encryptor()
    enc.set_TID('325010967')
    log.log('SemtecResult=',enc.decrypt(pan='5413335519260012',expiry='5812'))


if __name__ == '__main__':
    utility.register_testharness_script(semtec_function)
    utility.do_testharness()