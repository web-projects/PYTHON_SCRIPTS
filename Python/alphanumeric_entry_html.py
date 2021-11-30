from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
import sys
import linecache
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
from binascii import hexlify, unhexlify


def traceit(frame, event, arg):
    if event == "line":
        lineno = frame.f_lineno
        filename = frame.f_globals["__file__"]
        if (filename.endswith(".pyc") or
            filename.endswith(".pyo")):
            filename = filename[:-1]
        name = frame.f_globals["__name__"]
        line = linecache.getline(filename, lineno)
        print(name,":", lineno,": ", line.rstrip())
    return traceit


def setupKeyboardReader():
  log.log("Setup keyboard reader")
  # collect response from user
  # Bit 0 - Enter, Cancel, Clear keys
  # Bit 1 - function keys
  # Bit 2 - numeric keys
  conn.send([0xD0, 0x61, 0x07, 0x00])
  status, buf, uns = conn.receive()
  
  
def processRequest():
   ''' First create connection '''
   req_unsolicited = conn.connect()
   ''' If unsolicited read it'''
   if req_unsolicited:
         status, buf, uns = conn.receive()
         
         check_status_error( status )
   
   ''' Reset Device '''
   # P1
   # 0x00 - perform soft-reset
   # P2
   # Bit 1 – 0
   # PTID in serial response
   # Bit 1 – 1
   # PTID plus serial number (tag 9F1E) in serial response
   # Bit 2
   # 0 — Leave screen display unchanged, 1 — Clear screen display to idle display state
   conn.send( [0xD0, 0x00, 0x00, 0x17] )
   status, buf, uns = conn.receive()
   check_status_error( status )
   
   tlv = TLVParser(buf)
   tid = tlv.getTag((0x9F, 0x1e))
   if len(tid): 
      tid = str(tid[0], 'iso8859-1')
      log.log('Terminal TID:', tid)
   else:
      tid = ''
      log.logerr('Invalid TID (or cannot determine TID)!')
   
   # Chained Commands
   cc = tlv.getTag((0xDF, 0xA2, 0x1D))
   if len(cc): 
      cc = str(cc[0], 'iso8859-1')
      log.log('COMMAND SIZE:', cc)
   
   # keyboard reader
   setupKeyboardReader()
   
   ''' html resource data '''
   html_file = b'mapp/alphanumeric_entry.html'
   html_logo = b'signature.png'
   html_tags = [
      [ (0xDF, 0xAA, 0x01), html_file ],
      [ (0xDF, 0xAA, 0x02), b'logo_image' ],          [ (0xDF, 0xAA, 0x03), html_logo ],
      [ (0xDF, 0xAA, 0x02), b'TEMPLATE_INPUT_TYPE' ], [ (0xDF, 0xAA, 0x03), b'number' ],
      [ (0xDF, 0xAA, 0x02), b'title_text' ],          [ (0xDF, 0xAA, 0x03), b'ENTER NUMBER' ],
      [ (0xDF, 0xAA, 0x02), b'input_precision' ],     [ (0xDF, 0xAA, 0x03), b'0' ],
      [ (0xDF, 0xAA, 0x02), b'max_len' ],             [ (0xDF, 0xAA, 0x03), b'4' ],
   ]
   html_templ = ( 0xE0, html_tags )
   
   # display HTML
   conn.send( [0xD2, 0xE0, 0x00, 0x01], html_templ )
   #sys.settrace(traceit)
   status, buf, uns = conn.receive()
   check_status_error( status )

   ''' Check for HTML display result '''
   status, buf, uns = conn.receive()
   check_status_error( status )
    
   ''' save to json file '''
   tlv = TLVParser(buf)
   tag_output_data = (0xDF, 0xAA, 0x05)
   if (tlv.tagCount(tag_output_data) == 1):
       htmlResponse = tlv.getTag(tag_output_data)[0]
       log.log("RESULT:", hexlify(htmlResponse))
       tag_output_data = (0xDF, 0xAA, 0x03)
       if (tlv.tagCount(tag_output_data) >= 3):
           htmlResponse = tlv.getTag(tag_output_data)[2]
           log.log("RESULT:", htmlResponse)       
           open("upload/signature/signature.json", "wb").write(htmlResponse)
   else:
       log.logerr("NO SIGNATURE DATA!")
       
   ''' Reset display '''
   conn.send( [0xD2, 0x01, 0x01, 0x00] )
   status, buf, uns = conn.receive()
   check_status_error( status )
   

if __name__ == '__main__':

    log = getSyslog()

    conn = connection.Connection();
    utility.register_testharness_script( processRequest )
    utility.do_testharness()
