#!/bin/env python
# -*- coding: utf-8 -*-

from testharness import *
from testharness.syslog import getSyslog
from testharness.utility import check_status_error

''' How to create example scripts '''
def demo_function():
   ''' First create connection '''
   req_unsolicited = conn.connect()
   ''' If unsolicited read it'''
   if req_unsolicited:
         status, buf, uns = conn.receive()
         check_status_error( status )
   ''' Wait for anything from client'''
   status, buf, uns = conn.receive()
   check_status_error( status )

if __name__ == '__main__':
    log = getSyslog()
    conn = connection.Connection();
    utility.register_testharness_script( demo_function )
    utility.do_testharness()
