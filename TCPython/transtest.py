'''
Created on 28-03-2012

@author: Lucjan_B1
'''

from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog


def transtest_function():
    log = getSyslog()
    conn = connection.Connection();
    #Create ssl server
    #conn.connect_tcp_server(timeout=30)
    #conn.connect_tcp_client('localhost',16107)
    #conn.connect_serial('COM1', 57600, timeout=2 );
    req_unsolicited = conn.connect()
    if req_unsolicited:
        #Receive unsolicited
        status, buf, uns = conn.receive()
        if status != 0x9000:
            log.logerr('Unsolicited fail')
            exit(-1)
        log.log('Unsolicited', TLVParser(buf) )
    #Send reset device
    conn.send([0xD2, 0x01, 0x01, 0x00])
    status, buf, uns = conn.receive()
    if status != 0x9000:
        log.logerr('reset fail')
        exit(-1)
    #Monitor card status
    conn.send([0xD0, 0x60, 0x01, 0x00])
    status, buf, uns = conn.receive()
    if status != 0x9000:
        log.logerr('Cardstatus fail')
        exit(-1)
    #print('CardStatus',TLVParser(buf))
    #Prompt for card
    conn.send([0xD2, 0x01, 0x0D, 0x00])
    status, buf, uns = conn.receive()
    if status != 0x9000:
        log.logerr('prompt card fail')
        exit(-1)
    #Short insert card notification
    log.log('**** WAIT FOR CARD INSERTION ****')
    status, buf, uns = conn.receive()
    if status != 0x9000 and not uns:
        log.logerr('Pinpad fail!!', hex(status),uns)
        exit(-1)
    tlv = TLVParser(buf)
    ins_tag_val = tlv.getTag(0x48, tlv.CONVERT_INT)
    if ins_tag_val[0]!=0x300:
        log.logerr('PINPAD FAILED tag 0x48 is', ins_tag_val)
        exit(-1)
    #Create localtag for transaction
    start_trans_tag = [
         [(0x9F, 0x02), b'\x00\x00\x00\x10\x04\x00' ],
         [(0x9A), b'\x04\x01\x01'],
         [(0x9C), b'\x00'],
         [(0x9F,0x21), b'\x01\x01\x01'],
         [(0x9F,0x41), b'\x00\x01' ],
         [(0x5F,0x2A), b'\x08\x26' ],
         [(0xDF,0xA2,0x18), b'\x00'],
         [(0xDF,0xA2,0x14), b'\x01'],
         [(0xDF,0xA2,0x04), b'\x01']
    ]
    start_templ = ( 0xE0, start_trans_tag )
    print(start_templ)
    #Start transaction
    conn.send([0xDE, 0xD1, 0x00, 0x00], start_templ)
    status, buf, uns = conn.receive()
    if status != 0x9000:
        log.logerr('Start transaction fail', hex(status), buf)
        exit(-1)
    #print(TLVParser(buf))
    #Continue transaction
    c_tag = tagStorage()
    c_tag.store( (0x9F,0x02), [0x00, 0x00, 0x00,0x00, 0x54, 0x00 ] )
    c_tag.store( (0x5F,0x2A), [0x09, 0x78] )
    c_tag.store(  0xC2, [0x30, 0x30] )
    c_tag.store( (0xDF,0xA2,0x18), 0x00 )
    c_tag.store( (0xDF,0xA3,0x07), [0x03,0xE8] )
    c_tag.store( 0xC0, 0x01 )
    c_tag.store( 0x8A, [0x59, 0x32 ] )
    c_tag.store( 0x91, [0x37,0xDD,0x29,0x75,0xC2,0xB6,0x68,0x2D,0x00,0x12] ) 

    #continue_tran_tag = [
    #    [ (0x9F,0x02), [0x00, 0x00, 0x00,0x00, 0x54, 0x00 ] ],
    #    [ (0x5F,0x2A), [0x09, 0x78] ],
    #    [ (0xC2), [0x30, 0x30] ],
    #    [ (0xDF,0xA2,0x18), [0x00] ],
    #    [ (0xDF,0xA3,0x07), [0x03,0xE8] ],
    #    [ (0xC0), [0x01] ],
    #    [ (0x8A), [0x59, 0x32 ] ],
    #    [ (0x91), [0x37,0xDD,0x29,0x75,0xC2,0xB6,0x68,0x2D,0x00,0x12] ]
    #]
    #continue_tpl = (0xE0, continue_tran_tag )
    #conn.send([0xDE, 0xD2, 0x00, 0x00], continue_tpl)
    conn.send( [0xDE, 0xD2, 0x00, 0x00], c_tag.getTemplate(0xE0) )

    status, buf, uns = conn.receive()
    if status != 0x9000:
        log.logerr('Continue transaction fail', hex(status), buf)
        exit(-1)
    #print(TLVParser(buf))
    log.log('*** PIN ENTRY WAIT ***')
    status, buf, uns = conn.receive()
    utility.check_status_error((status, buf, uns))
    tlv = TLVParser(buf)
    #print(tlv)
    if tlv.tagCount(0xE6) != 0:
        log.logerr('Not complete response wait again')
        status, buf, uns = conn.receive()
        if status != 0x9000:
            log.logerr('Pin entry wait #2', hex(status), buf)
            exit(-1)
    # Continue with positive response
    conn.send([0xDE, 0xD2, 0x00, 0x00])
    log.log('*** ONLINE REQUEST WAIT ***')
    status, buf, uns = conn.receive()
    if status != 0x9000:
        log.logerr('Online Request wait', hex(status), buf)
        exit(-1)
    #print(TLVParser(buf))
    #Remove card
    conn.send([0xD2, 0x01, 0x0E, 0x00])
    log.log('*** REMOVE CARD PROMPT***')
    status, buf, uns = conn.receive()
    if status != 0x9000:
        log.logerr('Remove card', hex(status), buf)
        exit(-1)
    log.log('*** REMOVE CARD WAIT ***')
    status, buf, uns = conn.receive()
    if status != 0x9000:
        log.logerr('Remove card wait', hex(status), buf)
        exit(-1)
    #Reset display
    conn.send([0xD2, 0x01, 0x01, 0x00])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = conn.receive()
    if status != 0x9000:
        log.logerr('Reset display wait', hex(status), buf)
        exit(-1)
    #Disconnect
    conn.send([0xD2, 0x01, 0x01, 0x00])
    log.log('*** DISCONNECT ***')
    status, buf, uns = conn.receive()
    if status != 0x9000:
        log.logerr('Disconnect wait', hex(status), buf)
        exit(-1)
    

if __name__ == '__main__':
    utility.register_testharness_script(transtest_function)
    utility.do_testharness()
