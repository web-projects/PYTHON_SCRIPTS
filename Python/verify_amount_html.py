from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog
from testharness.utility import check_status_error

#
# putfile.py --file upload/html/verify_amount.html --rfile www/mapp/verify_amount.html --serial COM11
#

def waitForKeyPress():
  # collect response from user
  # Bit 0 - Enter, Cancel, Clear keys
  # Bit 1 - function keys
  # Bit 2 - numeric keys
  conn.send([0xD0, 0x61, 0x07, 0x00])
  status, buf, uns = conn.receive()


  # wait for a key press
  exitKey = False
  keyPressed = 0x00
  while exitKey == False:
    status, buf, uns = conn.receive()
    check_status_error(status)
    tlv = TLVParser(buf)
    if tlv.tagCount((0xDF, 0xA2, 0x05)):
      user_input = tlv.getTag((0xDF, 0xA2, 0x05))[0]
      #log.log('KEY PRESSED:', user_input[0])
      # YES: <1>, <X>
      # NO : <2>, <O>      
      if (user_input[0] == 0x20 or user_input[0] == 0x1B) or (user_input[0] == 0x1F or user_input[0] == 0x0D):
        exitKey = True
        keyPressed = user_input[0]
  # user selection   
  switcher = {
        0x20: "NO",
        0x1B: "NO",
        0x1F: "YES",
        0x0D: "YES"
  }
  user_choice = switcher.get(keyPressed, "UNKNOWN CHOICE")
  log.logerr('USER SELECTED:', user_choice)

   
def htmlEntry():

    req_unsolicited = conn.connect()
    if req_unsolicited:
        status, buf, uns = conn.receive()
        check_status_error(status)

    conn.send([0xD2, 0x01, 0x01, 0x00])  # Reset display
    status, buf, uns = conn.receive()
    check_status_error(status)
    
    html_resource = b'mapp/verify_amount.html'
    title   = b'<tr><td>VERIFY AMOUNT</td></tr>'
    message = b'Total....$99999.99\n1. Yes\n2. No'
    logo = b'signature.png'
    html_tags = [
      [(0xDF, 0xAA, 0x01), html_resource],
      [(0xDF, 0xAA, 0x02), b'logo_image'],        [(0xDF, 0xAA, 0x03), logo],
      [(0xDF, 0xAA, 0x02), b'TEMPLATE_BKG_IMG0'], [(0xDF, 0xAA, 0x03), logo],
      
      #[(0xDF, 0xAA, 0x02), b'text_style'], [(0xDF, 0xAA, 0x03), title],
      [(0xDF, 0xAA, 0x02), b'TEMPLATE_TEXT0'], [(0xDF, 0xAA, 0x03), title],
      [(0xDF, 0xAA, 0x02), b'TEMPLATE_TEXT1'], [(0xDF, 0xAA, 0x03), message],
    ]
    html_templ = (0xE0, html_tags)
	
    # P1
    # Bit 0 - enable update events (echo mode, see Receiving echo mode data on POS)
    # P2
    # Backlight: 00 – off, 01 – on
    conn.send([0xD2, 0xE0, 0x00, 0x01], html_templ)
  
    ''' send command to device '''
    status, buf, uns = conn.receive()
    check_status_error(status)

    # collect response from user
    waitForKeyPress()
    
    #Reset display - regardless of tx type
    conn.send([0xD2, 0x01, 0x01, 0x00])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = conn.receive()
    
    
if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection()
    utility.register_testharness_script(htmlEntry)
    utility.do_testharness()
