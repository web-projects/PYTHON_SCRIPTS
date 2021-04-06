#!/bin/env python
# -*- coding: utf-8 -*-

from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
import sys
import linecache
from testharness.syslog import getSyslog
from testharness.utility import check_status_error
NAD_PINPAD=2
NAD_TERMINAL=1

''' How to create example scripts '''
def demo_function():
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
   ''' Send data '''
   conn.send([0xD2, 0x01, 0x00, 0x01], 'Test tralala' )
   status, buf, uns = conn.receive()
   check_status_error( status )

def demo_test_pp1000():
   ''' First create connection '''
   req_unsolicited = conn.connect()
   ''' If unsolicited read it'''
   if req_unsolicited:
         status, buf, uns = conn.receive()
         check_status_error( status )
#   ''' Reset display '''
   prev_nad = conn.setnad(NAD_PINPAD)
#   conn.send([0xD2, 0x01, 0x01, 0x00])
#   status, buf, uns = conn.receive()
#   check_status_error( status )
   ''' Send data '''
   conn.send([0xD2, 0x01, 0x00, 0x01], 'FIRST LINE\x0ASECOND LINE' )
#   sys.settrace(traceit)
   status, buf, uns = conn.receive()
   check_status_error( status )
   conn.setnad(prev_nad)

def demo_test_font_pp1000():
   ''' First create connection '''
   req_unsolicited = conn.connect()
   ''' If unsolicited read it'''
   if req_unsolicited:
         status, buf, uns = conn.receive()
         check_status_error( status )
#   ''' Reset display '''
   prev_nad = conn.setnad(NAD_PINPAD)
#   conn.send([0xD2, 0x01, 0x01, 0x00])
#   status, buf, uns = conn.receive()
#   check_status_error( status )
   ''' Send data '''
   tags = [
    [(0xDF, 0xA2, 0x10), b'M2.FON' ],
    [(0xDF, 0x81, 0x04), b'Tralalalala']
    ]
   start_templ = ( 0xE0, tags )
   conn.send([0xD2, 0x02, 0x00, 0x01], start_templ )
#   sys.settrace(traceit)
   status, buf, uns = conn.receive()
   check_status_error( status )
   conn.setnad(prev_nad)

def demo_test_multiple_choice_pp1000():
   ''' First create connection '''
   req_unsolicited = conn.connect()
   ''' If unsolicited read it'''
   if req_unsolicited:
         status, buf, uns = conn.receive()
         check_status_error( status )
#   ''' Reset display '''
   prev_nad = conn.setnad(NAD_PINPAD)
#   conn.send([0xD2, 0x01, 0x01, 0x00])
#   status, buf, uns = conn.receive()
#   check_status_error( status )
   ''' Send data '''
   conn.send([0xD2, 0x03, 0x00, 0x01], '0123456\x0A11234567\x0A212345678\x0A3123456789\x0A4123456789A\x0A5123456789AB\x0A5123456789ABC\x0A5123456789ABCD\x0A5123456789ABCDE\x0A5123456789ABCDEF' )
#   sys.settrace(traceit)
   status, buf, uns = conn.receive()
   check_status_error( status )
   conn.setnad(prev_nad)

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

if __name__ == '__main__':
    log = getSyslog()
    
    conn = connection.Connection();
#    utility.register_testharness_script( demo_function )
#    utility.register_testharness_script( demo_test_pp1000 )
    utility.register_testharness_script( demo_test_font_pp1000 )
#    utility.register_testharness_script( demo_test_multiple_choice_pp1000 )
    utility.do_testharness()
