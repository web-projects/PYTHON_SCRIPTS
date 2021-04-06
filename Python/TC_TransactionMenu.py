from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from time import sleep
from binascii import hexlify, unhexlify

LIST_STYLE_SCROLL = 0x00
LIST_STYLE_NUMERIC = 0x01
LIST_STYLE_SCROLL_CIRCULAR = 0x02

# Transaction Type Dictionary
TransactionType = {
    1: [ b'\x00', "SALE" ],
    2: [ b'\x01', "CASH ADVANCE" ],
    3: [ b'\x09', "SALE WITH CASHBACK" ],
    4: [ b'\x20', "RETURN REFUND" ],
    5: [ b'\x30', "BALANCE INQUIRY" ],
    6: [ b'\x31', "RESERVATION" ]
}
TransactionTitle = 'SELECT TYPE:'


def select_transaction():
  ''' Set data for request '''
  c_tag = tagStorage()
  c_tag.store( (0xDF, 0xA2, 0x12), LIST_STYLE_SCROLL )
  #BUG: Unable to push the direct string not bytearray
  c_tag.store( (0xDF,0xA2,0x11), TransactionTitle )
  
  i = 1
  for key in TransactionType:
      c_tag.store( (0xDF, 0xA2, 0x02), i )
      c_tag.store( (0xDF, 0xA2, 0x03), TransactionType[key][1] )
      i = i + 1
      
  ''' Send request '''
  conn.send([0xD2, 0x03, 0x00, 0x01] , c_tag.get())
  
  is_unsolicited = True
  while is_unsolicited:  # unsolicited responses come when echo mode is on
      status, buf, is_unsolicited = conn.receive()
      check_status_error( status )

  # if user cancels, default to 'SALE' Transaction
  if status == 0x9f43:
      log.log("TRANSACTION TYPE: '" + TransactionType[1][1] + "' AT INDEX =", 1)
  else:
    tlv = TLVParser(buf)
    if tlv.tagCount((0xDF, 0xA2, 0x02)) == 1:
      selection = tlv.getTag((0xDF, 0xA2, 0x02))[0]
      index = selection[0]
      log.log("TRANSACTION TYPE: '" + TransactionType[index][1] + "' AT INDEX =", index)

  #Reset display
  conn.send([0xD2, 0x01, 0x01, 0x01])
  log.log('*** RESET DISPLAY ***')
  status, buf, is_unsolicited = conn.receive()
  check_status_error( status )

    
if __name__ == '__main__':
    log = getSyslog()
    
    conn = connection.Connection();
    ''' First create connection '''
    req_unsolicited = conn.connect()

    utility.register_testharness_script( select_transaction )
    utility.do_testharness()
