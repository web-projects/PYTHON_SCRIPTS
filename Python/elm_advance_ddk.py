from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error


''' How to create example scripts '''
def elm_init_function():
   ''' First create connection '''
   req_unsolicited = conn.connect()
   ''' If unsolicited read it'''
   if req_unsolicited:
         status, buf, uns = conn.receive()
         check_status_error( status )
   ''' Reset display '''
   conn.send([0xD2, 0x01, 0x01, 0x00])
   status, buf, uns = conn.receive()
   check_status_error( status )
   ''' Check VSP Status '''
   conn.send([0xDD, 0x00, 0x03, 0x00])
   status, buf, uns = conn.receive()
   check_status_error( status )
   tlv = TLVParser(buf)
   vsp_stat = tlv.getTag((0xDF, 0xA2, 0x30), TLVParser.CONVERT_INT)[0]
   log.log('VSP status ', vsp_stat)
   if vsp_stat != 0:
       log.log('VSP Detected')
       if vsp_stat == 1:
          log.log('VSP Not active')
       else:
          if vsp_stat == 2:
              log.log('VSP Active')
          else:
              log.logerr('Unknown status!')
              return False
       ''' Get VSP version '''
       vsp_version = tlv.getTag((0xDF, 0xA2, 0x32), TLVParser.CONVERT_STR)[0]
       log.log('VSP Version ', vsp_version)
       if (vsp_version[:2] == '4.'):
          log.log('ELM Detected!')
          ''' First of all, we need TID '''
          conn.send([0xD0, 0x00, 0x00, 0x01])
          status, buf, uns = conn.receive()
          tlv = TLVParser(buf)
          tid = tlv.getTag((0x9F, 0x1e))
          if len(tid): 
              tid = str(tid[0], 'iso8859-1')
              log.log('Terminal TID: ', tid)
          else: 
              tid = ''
              log.logerr('Invalid TID (or cannot determine TID)!')
              return False
          ''' Trying to enable it '''
          conn.send([0xDD, 0xC1, 0x00, 0x00])
          status, buf, uns = conn.receive()
          check_status_error( status )
          status, buf, uns = conn.receive()
          check_status_error( status )
          tlv = TLVParser(buf)
          t1 = tlv.getTag((0x5F, 0x21), TLVParser.CONVERT_STR)
          if len(t1): t1 = t1[0]
          else: t1 = ''
          t2 = tlv.getTag((0x5F, 0x22), TLVParser.CONVERT_STR)
          if len(t2): t2 = t2[0]
          else: t2 = ''
          if len(t1): log.log('T1: ', t1)
          if len(t2): log.log('T2: ', t2)

          try:
              enc = semtec.encryptor()
              enc.set_TID(tid)
          except exceptions.logicalException as exc:
              log.logerr('Cannot create decryptor object! Error ', exc)
              return False
          pan = ''
          expiry = ''
          try:
              pan_d, expiry_d, t1_d, t2_d = enc.decrypt(pan, expiry, t1, t2)
              log.log('Done ok')
          except exceptions.logicalException as exc:
              if not '909' in str(exc):
                  log.logerr('Advance DDK error ', exc)
              else:
                  log.log('VSP keys advanced on Host')
          return True
       else:
          log.logerr('Not ELM (Dogwood)')
          return False
   else:
        log.log('No VSP detected!')
        return False

if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script( elm_init_function )
    utility.do_testharness()