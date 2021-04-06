
''' Old testharness script interpreter 
    Author Lucjan_B1
'''

__author__ = "Lucjan Bryndza"
__copyright__ = "(c) 2014 Lucjan Bryndza"
__license__ = "GPL"
__email__ = "Lucjan_B1@verifone.com"

from testharness.tlvparser import TLVParser,tagStorage
from testharness import connection
from testharness.syslog import getSyslog
from pyparsing import *
from binascii import unhexlify
from testharness.utility import lrccalc
from functools import partial
import testharness.utility as utils
import testharness.exceptions as exc
import testharness.fileops as fops
import time;
import os;
''' --------------------------------------------------------------- '''
__SCRIPT_ROOT = None;
''' --------------------------------------------------------------- '''
#Create AST th parser
def __create_ast_th_language_syntax( ):
#Old test testharness format script parser
    th_sfmt = Forward()
# Helper funcs
    prompt_chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"$%&\\()*+-./:;<=>?@[\\]^_`|~'
    hexbyte = Word( hexnums , max=2 ).setParseAction( lambda s,l,t: [ int(t[0],16) ] )
    integer = Word( nums ).setParseAction( lambda s,l,t: [ int(t[0]) ] )
# Hex string data
    hexstr = Regex( "([A-Fa-f0-9]{2})+" ).setParseAction( lambda s,l,t: [ list(unhexlify( t[0] )) ] )
    quoted_txt_array =  QuotedString("'").setParseAction( lambda s,l,t: [  list(bytearray( t[0],'iso8859-1')) ] )
    hexstr_txt =  Group( ZeroOrMore(hexstr) & ZeroOrMore( quoted_txt_array ) )
# Added hexs
    hexstr_plus  = Group( hexstr + ZeroOrMore( Suppress("+") + hexstr ) )
#Filename path
    filepath_txt = Word( alphanums +  "_/\-()!.^" )
    filename_txt = Word( alphanums +  "_-()!.^" )
#Comment and log
    comment_expr = Keyword("rem", caseless=True ) + restOfLine
    loginfo_expr = Keyword("#") + restOfLine

#True or false expr
    boolean_expr = ((Keyword("false", caseless=True ) | Keyword("true", caseless=True )). \
            setParseAction( lambda s,l,t: [ True if t[0].lower() == "true" else False ] ))

#Set NAD command
    setnad_keyword = Keyword("setnad",caseless=True)
    nad_expr = setnad_keyword - hexbyte

#Set device command
    setdevice_keyword = Keyword("setdevice", caseless=True )
    setdevice_enum = CaselessLiteral("xtreme") | CaselessLiteral("xtremeslot") | \
                    CaselessLiteral("icxpressslot") | CaselessLiteral("xplorer")
    setdevice_expr = setdevice_keyword - setdevice_enum
#Flush command
    flush_expr = Keyword( "flush", caseless=True )

#Send command
    send_keyword = Keyword( "send", caseless = True )
    send_args =  hexbyte + ( Suppress(",") + hexbyte ) * 3
    send_args_templ =  ( Suppress(",") + Suppress("{") + hexstr + Suppress("}") ).setResultsName("tag")
    send_args_notempl = ( Suppress(",") + hexstr_txt ).setResultsName("hex")
    send_args_data = ( send_args_templ | send_args_notempl ) * ( None, 1 )
    send_args_le = ( Suppress(",") + hexbyte ).setResultsName( "le" )
    send_args_leopt = send_args_le * ( None, 1 )
    send_expr =  send_keyword + send_args + send_args_data + send_args_leopt

#Wait command
    wait_keyword = Keyword( "wait", caseless = True )
    wait_expr = wait_keyword - integer.setResultsName("timeout")


#Pause command
    pause_keyword = Keyword( "pause", caseless = True )
    pause_expr = pause_keyword - integer

#Prompt expression
    prompt_keyword = Keyword( "prompt", caseless = True )
    prompt_expr = prompt_keyword - \
    Group( OneOrMore( Word(prompt_chars))).setResultsName("comment") - \
    Suppress(",") + integer.setResultsName("timeout")

#Clear local pool 
    clearlocalpool_expr = Keyword( "clearlocalpool", caseless = True );

#Store local keyword
    storelocal_keyword = Keyword( "storelocaltag", caseless = True )
    storelocal_expr = storelocal_keyword + hexstr + Suppress(",") + hexstr_txt

#Append local keyword
    appendlocal_keyword = Keyword("appendlocal", caseless = True )
    appendlocal_expr = appendlocal_keyword + hexstr + Suppress(",")  + hexstr_plus

#Abort sw1sw2
    abortsw1sw2_expr = Keyword( "abortsw1sw2", caseless = True ) + boolean_expr;

# Send direct
    senddirect_keyword = Keyword("senddirect", caseless = True )
    senddirect_expr = senddirect_keyword + hexstr

# Put file command
    putfile_keyword = Keyword( "putfile", caseless = True )
    putfile_cmd2 = boolean_expr.setResultsName("sign")  +  \
    Optional( Suppress(',')  +  filename_txt ).setResultsName( "rename" )
    putupdfile_cmd = filepath_txt + Optional( Suppress(',') + putfile_cmd2 )
    putfile_expr = putfile_keyword + putupdfile_cmd

#Update file
    updatefile_keyword = Keyword( "updatefile", caseless = True )
    updatefile_expr = updatefile_keyword + putupdfile_cmd

# Get file syntax
    getfile_keyword = Keyword( "getfile", caseless = True )
    getfile_args = filename_txt + Optional( Suppress(',') + filepath_txt )
    getfile_expr = getfile_keyword + getfile_args

#Continue parsing
    th_sfmt << Group( nad_expr | setdevice_expr | flush_expr | send_expr | wait_expr | \
            prompt_expr | clearlocalpool_expr | loginfo_expr | storelocal_expr | \
            appendlocal_expr | abortsw1sw2_expr | pause_expr | senddirect_expr | \
            putfile_expr | updatefile_expr | getfile_expr )


    oldth_syntax = ZeroOrMore(th_sfmt)
    oldth_syntax.ignore( comment_expr )
    return oldth_syntax

''' --------------------------------------------------------------- '''
#Send command and parse tags
def __send_command( toks, conn, pool, localtempl, log ):
    b4list = toks.asList()[1:5]
    print(toks)
    if len(toks) == 5:
        conn.send( b4list )
    elif len(toks) == 6 or len(toks)==7:
        tag = toks.get("tag")
        data = toks.get("hex")
        lebyte = toks.get("le")
        if lebyte != None: lebyte=lebyte[0]
        if data!=None and len(data[0])>0:
            print((data))
            data = bytearray(sum(data[0],[]))
            conn.send( b4list, data, le_byte = lebyte )
        elif tag != None:
            tagdata = pool.getTagData( tag[0] )
            if tag[0][0] in localtempl:
                conn.send( b4list, localtempl[tag[0][0]], le_byte = lebyte )
            elif tagdata != None:
                conn.send( b4list, [tag, data ], le_byte = lebyte )
            else:
                log.logerr( "Unable to find tag or template", tag )
                raise exc.logicalException( 'Unable to find tag or template' )
        else:
            conn.send( b4list, le_byte = lebyte )
    else:
        raise exc.invtypeException("Unknown parameters send command")


''' --------------------------------------------------------------- '''
#Send command and parse tags
def __wait_command( toks, conn, log , abort_sw1sw2 ):
    timeout = toks.get("timeout")
    comment = toks.get("comment")
    if comment != None:
        comment = str(" ").join( comment ).strip()
        log.loginfo( comment )
    if timeout == 0:
        timeout = None
    status, buf, uns = conn.receive( timeout )
    if status != 0x9000 and abort_sw1sw2 == True:
        raise exc.invResponseException( 'Invalid response', status )

''' --------------------------------------------------------------- '''
# Store tag command
def __storetag_command( toks, pool ):
    tag = tuple(toks[1])
    value = []
    for i in toks[2]:
        value += i
    pool.store( tag, value )
    return pool

''' --------------------------------------------------------------- '''
# Append local testharness command implementation
def __appendlocal_command( toks, pool ):
    newpool = tagStorage()
    newpool.clear();
    tplvalue =  toks[1][0]
    for t in toks[2]:
        fdata = pool.getTagData( tuple(t) )
        newpool.store( t, fdata )
    return tplvalue,newpool.getTemplate(tplvalue)

''' --------------------------------------------------------------- '''
#Send direct command
def __senddirect_command( toks, conn, log ):
    data = toks[1]
    lrc =  lrccalc( data )
    conn.send_raw( data, lrc )

''' --------------------------------------------------------------- '''
#Put file command
def __putfile_command( toks, conn, log ):
    filename  = toks[1]
    if not os.path.isfile( filename ):
        filename = os.path.join( __SCRIPT_ROOT, filename )
    do_sign = toks.get("sign")
    if do_sign==None: do_sign = False
    renfile = toks.get("rename")
    if renfile!=None: renfile = renfile[0]
    progress = partial( utils.display_console_progress_bar, utils.get_terminal_width() )
    fops.putfile( conn, log, filename, renfile , fops.CHAIN_AUTODETECT, do_sign, progress )

''' --------------------------------------------------------------- '''
#Update file command
def __updatefile_command( toks, conn, log ):
    filename  = toks[1]
    if not os.path.isfile( filename ):
        filename = os.path.join( __SCRIPT_ROOT, filename )
    do_sign = toks.get("sign")
    if do_sign==None: do_sign = False
    renfile = toks.get("rename")
    if renfile!=None: renfile = renfile[0]
    progress = partial( utils.display_console_progress_bar, utils.get_terminal_width() )
    fops.updatefile( conn, log, filename, renfile, do_sign, progress )

''' --------------------------------------------------------------- '''
# Get file command execution
def __getfile_command( toks, conn, log ):
    remote_file = toks[1]
    if len(toks) == 3:
        local_file = toks[2]
    else:
        local_file = None
    progress = partial( utils.display_console_progress_bar, utils.get_terminal_width() )
    fops.getfile( conn, log, remote_file, local_file, progress )
''' --------------------------------------------------------------- '''
#Transtest main function
def execute_script( filename ):
    global __SCRIPT_ROOT
    __SCRIPT_ROOT = os.path.dirname( os.path.abspath( filename ) )
    th_ast_parser = __create_ast_th_language_syntax();
    ast = th_ast_parser.parseFile( filename, True )
    log = getSyslog()
    conn = connection.Connection();
    req_unsolicited = conn.connect()
    abort_sw1sw2  = True
    pool = tagStorage()
    localtempl = {}
    if req_unsolicited:
        #Receive unsolicited
        status, buf, uns = conn.receive()
        if status != 0x9000:
            raise exc.invResponseException( 'Unsolicited message fail', status )
        log.log('Unsolicited', TLVParser(buf) )
    for toks in ast:
        if toks[0] == 'setnad':
            conn.setnad( toks[1] )
            log.loginfo( 'Set NAD to', toks[1] )
        elif toks[0] == '#':
            log.loginfo("Comment:", str(toks[1]).strip() )
        elif toks[0] == 'setdevice':
            log.loginfo('Set device to', toks[1] )
        elif toks[0] == 'flush':
            log.loginfo('Flush comms')
        elif toks[0] == 'clearlocalpool':
            pool.clear()
            localtempl.clear()
            log.loginfo('Clear local pool')
        elif toks[0] == 'pause':
            log.loginfo('Pause for', toks[1], 'sec' )
            time.sleep( toks[1] )
        elif toks[0] == 'send':
            __send_command( toks, conn, pool, localtempl, log )
        elif toks[0] == 'abortsw1sw2':
            abort_sw1sw2 = toks[1];
            log.loginfo('Abort SW1SW2 =', abort_sw1sw2 )
        elif toks[0] == 'wait':
            __wait_command( toks, conn, log, abort_sw1sw2 )
        elif toks[0] == 'prompt':
            log.loginfo( 'Prompt message:', str(" ").join(toks[1].asList()) )
            __wait_command( toks, conn, log, abort_sw1sw2 )
        elif toks[0] == 'storelocaltag':
            pool = __storetag_command( toks, pool )
        elif toks[0] == 'appendlocal':
            tpl,data = __appendlocal_command( toks, pool )
            localtempl[tpl] = data
        elif toks[0] == 'senddirect':
            __senddirect_command( toks, conn, log )
        elif toks[0] == 'putfile':
            __putfile_command( toks, conn, log )
        elif toks[0] == 'updatefile':
            __updatefile_command( toks, conn, log )
        elif toks[0] == 'getfile':
            __getfile_command( toks, conn, log )
        else:
            log.logerr( 'Unknown tokens', str(toks) )
            raise exc.logicalException('Unknown tokens in script')
