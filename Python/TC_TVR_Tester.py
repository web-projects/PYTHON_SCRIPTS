from testharness import *
from testharness.syslog import getSyslog
from binascii import hexlify, unhexlify, b2a_hex

import testharness.utility as util
import TC_TransactionHelper


def testAllMessages():
  # Byte 1
  for x in range(8, 0, -1):
    TC_TransactionHelper.showTVRByte1Failures(log, x)
  # Byte 2
  print('')
  for x in range(8, 0, -1):
    TC_TransactionHelper.showTVRByte2Failures(log, x)
  # Byte 3
  print('')
  for x in range(8, 0, -1):
    TC_TransactionHelper.showTVRByte3Failures(log, x)
  # Byte 4
  print('')
  for x in range(8, 0, -1):
    TC_TransactionHelper.showTVRByte4Failures(log, x)


def processRequest():
  #tvr =  b'\xff\xff\xff\xff\xff'
  #tvr =  b'\x5a\x5a\x5a\x5a\x5a'
  tvr =  b'\x04\x00\x00\x80\x00'
  log.attention('TVR:', hexlify(tvr))
  index = 1
  for x in tvr:
    # change x to X for upper: "0x%0*X"
    log.log('BYTE[' + str(index) + ']: ' + "0x%0*x" % (2, x))
    #log.log('BYTE[' + str(index) + ']: ' + "{0:#0{1}x}".format(x, 4))
    #log.log('BINARY :', bin(x).replace("0b", ""))
    for n in range(8, -1, -1):
      bit = (x & (1 << n)) >> n
      if bit == 1:
        #log.log('   BIT :', n + 1)
        TC_TransactionHelper.showTVRFailures(log, index, n + 1)
    index = index + 1

# ---------------------------------------------------------------------------- #
# Main
# ---------------------------------------------------------------------------- #
if __name__ == '__main__':

    log = getSyslog()
    #utility.register_testharness_script(testAllMessages)
    utility.register_testharness_script(processRequest)
    utility.do_testharness()
