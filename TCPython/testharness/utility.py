""" VIPA test framework TestHarness3
    Copyright (c) 2012-2014 Lucjan Bryndza Verifone
"""

from testharness.syslog import syslog
from testharness.syslog import getSyslog
import traceback
import sys
import os
import argparse
import platform

__testharness_tests = []
__arg_parser = None
__arg_parser_results = None
__arg_parser_results_initialized = False

''' Register testharness script '''
def register_testharness_script( script ):
    __testharness_tests.append(script)

# Get argument parser
def get_argparser( ):
    global __arg_parser
    if __arg_parser == None:
        __arg_parser = argparse.ArgumentParser( description = __doc__ ,
                fromfile_prefix_chars='@' )
    return __arg_parser


# Parse arguments
def parse_args():
    global __arg_parser_results
    global __arg_parser_results_initialized
    if not __arg_parser_results_initialized:
        if platform.system() == 'Linux':
            default_comm = '/dev/ttyS0'
            help_comm = 'Connect by the serial port number and optional rate /dev/ttyS0:115200 or /dev/ttyS0'
        else:
            default_comm = 'COM1'
            help_comm = 'Connect by the serial port number and optional rate COM1:115200 or COM1'
        parser = get_argparser()
        group = parser.add_mutually_exclusive_group()
        group.add_argument( '--serial', dest='serial_port', default=default_comm,
                            help=help_comm)
        parser.add_argument( '--flow-ctrl', dest='flow_ctrl', default="rts-cts",
                            choices=['none','rts-cts','xon-xoff'],
                            help='Serial flow control to use: '
                                + '"none" - no flow control, '
                                + '"rts-cts" - hardware flow control (default), '
                                + '"xon-xoff" - software flow control')
        group.add_argument( '--tcp-server', dest='tcp_server', metavar='port', 
                            help='Listen on the selected port')
        group.add_argument('--tcp-client', dest='tcp_client', metavar='HOST:PORT',
                            help='Connect to the remote host')
        parser.add_argument('--timeout', dest='timeout', metavar='timeout', type=int, default=None,
                            help='Connection timeout')
        parser.add_argument( '--se_cert', dest='se_cert', default=None, help='3DES certificate for Stream Encryption' )
        parser.add_argument( '--se_whitelist', dest='se_whitelist', default=None, help='Stream encryption - non encrypted funs for stream encryption config' )
        parser.add_argument( '--seq_num', dest='seq_num', default=None, help='stream encryption sequential number' )
        subparsers = parser.add_subparsers(help='sub-command help')
        parser_ssl = subparsers.add_parser('ssl',help='SSL help' )
        parser_ssl.add_argument( '--ca', dest='sslca', metavar='cacert', required=True,
                help='CA certificate file for ssl connection' )
        parser_ssl.add_argument( '--cert', dest='sslcert', metavar='cert', required=False,
                help='Certificate file' )
        parser_ssl.add_argument( '--key', dest='sslkey', metavar='key', required=False,
                help='Private key file' )
        parser_ssl.add_argument('--passwd', dest='sslpasswd', metavar='password',
                help='SSL certificate password' )
        parser_ssl.add_argument( '--verify', dest='sslverify', choices=['none','optional','required'],
                default='optional' , help='SSL certificate verify mode' )
        __arg_parser_results = parser.parse_args()
        __arg_parser_results_initialized = True
    return __arg_parser_results


'''Do testharness and log exception '''
def do_testharness():
    parse_args()
    slog = getSyslog()
    fd = None
    old_term = None
    if os.name=='posix':
        import termios
        fd = sys.stdin.fileno()
        try:
            new_term = termios.tcgetattr(fd)
            old_term = termios.tcgetattr(fd)
            new_term[3] = (new_term[3] & ~termios.ICANON & ~termios.ECHO)
            termios.tcsetattr(fd, termios.TCSAFLUSH, new_term)
        except termios.error:
            pass
    try:
        for t in __testharness_tests:
            t()
    except Exception:
        slog.save_xml_output()
        slog.logerr( traceback.format_exc() )
    finally:
        slog.save_xml_output()
        if os.name=='posix' and old_term!=None:
            termios.tcsetattr(fd, termios.TCSAFLUSH, old_term)

''' Windows like kbhit defs '''
def kbhit():
    if os.name!='posix':
        import msvcrt
        return msvcrt.kbhit()
    else:
        from select import select
        ret = select([sys.stdin], [], [], 0)
        return len(ret[0])>0

''' Windows getch emu '''
def getch():
    if os.name=='posix':
        import sys
        return sys.stdin.read(1)
    else:       
        import msvcrt
        return msvcrt.getch().decode()


''' Check status result '''
def check_status_error(receive_tpl):
    slog = getSyslog()
    if type(receive_tpl)==int:
        status = receive_tpl
        buf = None
    else:
        status, buf, uns = receive_tpl
    if status != 0x9000:
        slog.logerr('Check status failed', hex(status), buf)
        sys.exit(-1)

''' Calculate LRC '''
def lrccalc( *args ):
    lrc = 0
    for arg in args:
        if type(arg)!=int:
            for x in bytearray( arg ):
                lrc ^= x
        else:
            lrc = ( lrc ^ arg ) & 0xFF
    return lrc


# Console progressbar handler
def display_console_progress_bar( term_width , percent ):
    term_width -= 10
    from sys import stdout
    stdout.write('[')
    for p in range(term_width):
        if int(term_width * percent + 0.5) > p: stdout.write('=')
        else: stdout.write(' ')
    stdout.write('] ')
    stdout.write(str(int(percent*100)) + '%\r')
    stdout.flush()


#Get terminal console witdth
def get_terminal_width():
    import os
    import sys
    import struct
    if sys.platform.startswith('win'):
        try:
            from ctypes import windll, create_string_buffer
            h = windll.kernel32.GetStdHandle(-12)
            csbi = create_string_buffer(22)
            res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)
            if res:
                import struct
                (bufx, bufy, curx, cury, wattr,
                 left, top, right, bottom, maxx, maxy) = struct.unpack("hhhhHhhhhhh", csbi.raw)
                width = right - left + 1
        except:
            width = 80
    else:
        try:
            import fcntl, termios, struct
            hw = struct.unpack('hh', fcntl.ioctl(1, termios.TIOCGWINSZ, '1234'))
            width = hw[1]
        except:
            try:
                width = os.environ['COLUMNS']
            except:  
                width = 80
    return width
