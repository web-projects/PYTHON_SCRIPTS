#!/usr/bin/python3
''' --------------------------------------------------------------- '''
import testharness.oldsyntax as oldsyntax
import testharness.utility as  utility
from functools import partial
''' --------------------------------------------------------------- '''
#Main do testharness
if __name__ == '__main__':
    arg = utility.get_argparser();
    arg.add_argument( '--script', dest='script', metavar='filename', required=True,
                            help='Old testharness script filename' )
    args = utility.parse_args();
    utility.register_testharness_script( partial( oldsyntax.execute_script, args.script ) )
    utility.do_testharness()

