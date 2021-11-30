'''
Created on 06-11-2021
@author(s): Jon_Bianco
'''

from testharness import *
from testharness.tlvparser import TLVParser, tagStorage
from sys import exit
from testharness.syslog import getSyslog


# Finalise the script, clear the screen
def performCleanup():
    # Clear screen
    conn.send([0xD2, 0x01, 0x01, 0x01])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer(True, False)
    # Disconnect

# Gets answer from the device, optionally ignoring unsolicited and stopping on errors
def getAnswer(ignoreUnsolicited = True, stopOnErrors = True):
    while True:
        status, buf, uns = conn.receive()
        if uns and ignoreUnsolicited:
            log.log('Unsolicited packet detected: ', TLVParser(buf))
            continue
        if status != 0x9000:
            log.logerr('Pinpad reported error ', hex(status))
            if stopOnErrors:
                performCleanup()
                exit(-1)
        break
    return status, buf, uns
#
# Main function
def processVipaRestart():
    req_unsolicited = conn.connect()
    if req_unsolicited:
        #Receive unsolicited
        log.log('Waiting for unsolicited')
        #status, buf, uns = getAnswer(False)
        #log.log('Unsolicited', TLVParser(buf) )

    # VIPA restart
    P1 = 0x02 # VIPA restart
    P2 = 0x08 # BEEP
    conn.send([0xD0, 0x00, P1, P2])

    #Reset display - IDLE SCREEN, BACKLIGHT OFF
    conn.send([0xD2, 0x01, 0x01, 0x00])
    status, buf, uns = getAnswer()  
   
if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection()

    utility.register_testharness_script(processVipaRestart)
    utility.do_testharness()
