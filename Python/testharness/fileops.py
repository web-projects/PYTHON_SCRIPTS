

''' Base file operations for VIPA
    Authors Kamil_P1, Lucjan_B1
'''

__author__ = "Kamil Pawlowski, Lucjan Bryndza"
__copyright__ = "(c) 2014 Lucjan Bryndza"
__license__ = "GPL"


from testharness import connection
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from time import strftime
import testharness.exceptions as exc
import os.path
import struct

# Constants
CHAIN_DISABLED = 0
CHAIN_AUTODETECT = 1
CHAIN_FORCED = 2

__CHAIN_FORCED_DATA_SIZE = 1800 # Number of bytes
__DETECTED_CHAIN_SIZE = 0 # Global, so that we won't detect over and over during one script execution

'''----------------------------------------------------------------- '''
#Detect the chain size
def __detect_chain_size( conn, log, chain ):
    global __DETECTED_CHAIN_SIZE
    global __CHAIN_FORCED_DATA_SIZE
    packetSize = 248 # const
    if chain == CHAIN_FORCED:
        packetSize = __CHAIN_FORCED_DATA_SIZE
    elif chain == CHAIN_AUTODETECT:
        if __DETECTED_CHAIN_SIZE == 0:
            # Detect chain size
            conn.send([0xD0, 0x00, 0x00, 0x00])
            status, buf, uns = conn.receive()
            tlv = TLVParser(buf)
            if (tlv.tagCount((0xDF, 0xA2, 0x1D))):
                packetSize = tlv.getTag((0xDF, 0xA2, 0x1D), TLVParser.CONVERT_INT)[0]
                __DETECTED_CHAIN_SIZE = packetSize
            else:
                log.logerr("No packet size (DFA21D tag), assuming chained messages are not supported!")
                __DETECTED_CHAIN_SIZE = 248
        else:
            packetSize = __DETECTED_CHAIN_SIZE
    return packetSize

'''----------------------------------------------------------------- '''
''' Put File function - puts local file to the device, file name is passed as argument '''
def putfile( conn, log, fn, remote_fn=None, chain=CHAIN_DISABLED, signature=False, progress=None ):
    from struct import pack
    if remote_fn==None: remote_fn = os.path.basename(fn)
    log.log('Uploading file ', fn, ' as ', remote_fn)
    packetSize = __detect_chain_size( conn, log, chain )
    # Go!
    log.log("Packet size: ", packetSize)
    P1 = 0x80
    P2 = 0
    d1 = 0
    offset = 0

    conn.send([0x00, 0xA4, 0x05, 0x00], remote_fn.upper())
    status, buf, uns = conn.receive()
    if status != 0x9000:
        raise exc.invResponseException( 'Cannot select file ' + fn , status )
    if progress!=None:
        log.loginfo( 'INFO: Binary stream data not included in log' )
        enable_logging = False
    else:
        enable_logging = True
    fileSize = os.path.getsize(fn);
    prevPercent = -1
    with open(fn, 'rb') as f:
        while True:
            readData = f.read(packetSize)
            readSize = len(readData)
            if (readSize == 0): break
            sendData = pack("B", d1)
            sendData += bytearray(readData)
            conn.send([0x00, 0xD6, P1, P2], sendData, log_packet = enable_logging )
            status, buf, uns = conn.receive( log_packet = enable_logging )
            if status != 0x9000:
                raise exc.invResponseException( 'File write error' , status )
            offset += readSize
            d1 = (offset & 0xFF)
            P2 = ((offset & 0xFF00) >> 8) & 0xFF
            P1 = ((offset & 0xFF0000) >> 16) & 0xFF
            P1 |= 0x80
            if hasattr(progress,'__call__'):
                percent = round(offset/fileSize,2)
                if percent != prevPercent: progress( percent )
                prevPercent = percent
    log.log('Download done')
#File signature not supported
    if signature:
        pass

'''----------------------------------------------------------------- '''
''' Get File function - gets file from device                        '''
def getfile( conn, log, remote_fn, local_fn=None, progress=None ):
    from struct import pack
    conn.send( [0x00,0xA4,0x04,0x00], remote_fn.upper() )
    status, buf, uns = conn.receive()
    if status != 0x9000:
        raise exc.invResponseException( 'Cannot select file ' + remote_fn , status )
    if progress!=None:
        log.loginfo( 'INFO: Binary stream data not included in log' )
        enable_logging = False
    else:
        enable_logging = True
    tlv = TLVParser(buf)
    fileSize = tlv.getTag(0x80, tlv.CONVERT_INT)[0]
    if fileSize == 0:
        raise exc.logicalException( 'File with name ' + remote_fn + " doesn't exists")
    now = strftime( "%Y%m%d%H%M%S" )
    if local_fn == None:
        local_fn = remote_fn + '_' + now
    packetLen = 248
    log.log( 'Downloading File', remote_fn, 'Length', fileSize, 'as localfile', local_fn )
    prevPercent = -1
    with open( local_fn, 'wb' ) as f:
        offset = 0
        while offset < fileSize:
            d1 = (offset & 0xFF)
            P2 = ((offset & 0xFF00) >> 8) & 0xFF
            P1 = ((offset & 0xFF0000) >> 16) & 0xFF
            P1 |= 0x80
            sendData = pack("B", d1 )
            conn.send( [ 0x00, 0xB0, P1, P2 ],  sendData ,log_packet = enable_logging )
            status, buf, uns = conn.receive_raw( log_packet = enable_logging )
            if status != 0x9000:
                raise exc.invResponseException( 'Error during get file', status )
            offset += len( buf )
            f.write( buf )
            if hasattr(progress,'__call__'):
                percent = round(offset/fileSize,2)
                if percent != prevPercent: progress( percent )
                prevPercent = percent
    log.log('Download done')
    return local_fn

'''----------------------------------------------------------------- '''
''' UpdateFile function - puts local file to the device, file name is passed as argument '''
def updatefile( conn, log, fn, remote_fn=None, signature=False, progress=None ):
    if not os.path.isfile(fn):
        raise exc.logicalException( 'File '+ fn+ ' doesnt exist!' )
    from struct import pack
    if remote_fn==None: remote_fn = os.path.basename(fn)
    log.log('Uploading file ', fn, ' as ', remote_fn)
    fileSize = os.path.getsize(fn);
    size = hex(fileSize)[2:]
    while len(size) < 8: size = '0'+size
    log.log('size ', size)

    c_tag = tagStorage()
    c_tag.store( (0x84), remote_fn.lower() )
    c_tag.store( (0x80), bytearray.fromhex(size) )
    conn.send([0x00, 0xA5, 0x05, 0x81], c_tag.getTemplate(0x6F))
    status, buf, uns = conn.receive()
    if status != 0x9000:
        raise exc.invResponseException( 'Cannot upload file '+ fn, status )
    dataCnt = 0;
    prevPercent = -1
    with open(fn, 'rb') as f:
        while True:
            readData = f.read(1024)
            readSize = len(readData)
            if (readSize == 0): break
            dataCnt+= readSize
            sendData = bytearray(readData)
            conn.send_raw(sendData)
            if hasattr(progress,'__call__'):
                percent = round(dataCnt/fileSize,2)
                if percent != prevPercent: progress( percent )
                prevPercent = percent

    log.log('Done, waiting for confirmation')
    # We're done, wait for response
    status, buf, uns = conn.receive()

