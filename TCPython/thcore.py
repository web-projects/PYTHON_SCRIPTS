import ssl
from binascii import  unhexlify;
from binascii import  hexlify;
from testharness import *
from testharness import syslog
tags = [
         [(0xDF,0xA2,0x22) , 'CHI'],
         [(0xDF,0xA2,0x23) ,  [ 0x10 , 0x20, 0x30 ] ],
         [(0xDF,0xA2,0x24) ,  b'\x05\x10\x15']
       ] 

data1 = [ 0xD1, 0xD2, 0xD3, 0xD4, 0xD5 ]
data2 = "dupajas1"


template1 = ( (0xE0), tags )
template2 = ( (0xE1),  tags )

long_tag =  [
    [(0xDF, 0xC0, 0x01) ,  b'0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789'] 
]



slog = syslog.getSyslog()
slog.logerr('Error log',1,2,3)
slog.log('Normal log')
exit(0)

conn = connection.Connection();
#conn.connect_serial('COM5', 57600, timeout=2 );
#conn.connect_tcp_server(timeout=15)
#conn.connect_tcp_client('192.168.16.120', ssl_protocol=True, 
#                       ca_cert='c:/pc/testharness/certs/ca.pem',
#                        timeout = 10)
#conn.send_raw( unhexlify(b'010004D2D0000007') );    
#conn.send_rawhex('010004D2D0000007');
#conn.send_raw( [0x01, 0x00, 0x04, 0xD2, 0xD0, 0x00, 0x00, 0x07] );
#status0, buf0 = conn.receive()
#print( buf0 )



conn.connect_tcp_server(timeout=10, ssl_protocol=True, 
                        ca_cert='c:/pc/testharness/certs/ca.pem', 
                        certfile='c:/pc/testharness/certs/server.pem', 
                        keyfile='c:/pc/testharness/certs/key.pem')
status0, buf0 = conn.receive()
print( buf0 )

conn.send( [0xD0, 0x00, 0x00, 0x00], template1 );
status, buf = conn.receive()
print("STATUS=", hex(status) )

#if type(buf)==bytearray:
#    print('RAWDATA RECEIVED=', len(buf) ,hexlify(buf)) 
#else:
#    for b in buf:
#        print('PARSE OK=', b )

parser = tlvparser.TLVParser(buf)
#for tag,val in parser:
#    print('tag',tag,'val',val)
parser2 = tlvparser.TLVParser(parser.getTag(239))
print(parser.getTag(239))
#print(parser2)
print(parser2.getTag((0xDF,0x81,0x06), parser2.CONVERT_DEF))
print(parser.getTag(239, parser2.CONVERT_DEF))
#print(buf)
#print(parser)
#print(parser.getUnparsed())
#for tag,value in parser.getTag(239):
#    print(tag,value)