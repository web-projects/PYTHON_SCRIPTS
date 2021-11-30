from testharness import *
from testharness.tlvparser import TLVParser
from sys import exit
import testharness.fileops as fops
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
import testharness.utility as util
from binascii import hexlify, unhexlify
from functools import partial

import os.path
from os import path

SPHERE_VERSION_FILE = 'sphere.ver'

def getFile(conn, log, filename , local_fn):
    try:
        log.log("GETFILE:", filename)
        progress = partial(util.display_console_progress_bar, util.get_terminal_width())
        fops.getfile(conn, log, filename, local_fn, progress)
        return True
    except Exception:
        log.logerr("FILE NOT FOUND:", filename)
        return False
        
def getSphereVersionFile(conn, log, filename):
    # is there a local copy already
    fileExists = path.exists(filename)
    # if not, get it from the device
    if fileExists == False:
        fileExists = getFile(conn, log, filename, filename)
    if fileExists == True:
        data = open(filename, "rb").read()
        if len(data):
            return data.decode('utf-8').split("|")
    return ""

    
def ProcessSphereVersion(args):
    # -----------------------------------------------------------------
    # GET SPHERE VERSION
    # -----------------------------------------------------------------
    #
    ''' First create connection '''
    req_unsolicited = conn.connect()
    ''' If unsolicited read it'''
    if req_unsolicited:
      status, buf, uns = conn.receive()
      check_status_error( status )
 
    SPHERE_VER = getSphereVersionFile(conn, log, args.filename)
    if len(SPHERE_VER):
      log.logwarning("SPHERE VERSION", SPHERE_VER)
      for x in SPHERE_VER:
        log.logerr(x)
      
    ''' Reset display '''
    conn.send( [0xD2, 0x01, 0x01, 0x00] )
    status, buf, uns = conn.receive()
    check_status_error( status )
   
    #if deviceReboot == True:
    #  rebootDevice()
      
   
# -----------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------
if __name__ == '__main__':
    # setup logger
    log = getSyslog()
  
    arg = util.get_argparser()
  
    # VERSION FILE
    arg.add_argument('--filename', dest='filename', default='',
                     help='version file to retrieve')
     
    args = util.parse_args()
      
    # validate version
    if len(args.filename) == 0:
      args.filename = SPHERE_VERSION_FILE
    log.log('SPHERE-VERSION FILE: ' + SPHERE_VERSION_FILE)
     
    conn = connection.Connection();
    utility.register_testharness_script( partial(ProcessSphereVersion, args) )
    utility.do_testharness()
