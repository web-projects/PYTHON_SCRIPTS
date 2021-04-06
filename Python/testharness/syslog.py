'''
Created on 29-03-2012

@author: Lucjan_B1
'''
import colorama
import datetime
import xml.etree.ElementTree as etree


''' Claass log '''
class syslog(object):
    
    ''' Log levels '''
    LOGLEVEL_ERROR      = 0x01    
    LOGLEVEL_USER       = 0x02
    LOGLEVEL_SYSTEM     = 0x04
    LOGLEVEL_PARSE      = 0x08
    LOGLEVEL_DATA       = 0x10
    LOGLEVEL_PACKET     = 0x20
    LOGLEVEL_INFO       = 0x40
    LOGLEVEL_WARNING    = 0x80
    __LOGLEVEL_DATA_LOG = LOGLEVEL_PARSE | LOGLEVEL_DATA | LOGLEVEL_PACKET
    
    ''' Output directory '''
    __OUTPUT_DIR = 'out'
    
    '''Console output handler '''
    def __console_output(self, level, msg ):
        from colorama import Fore, Back
        """ Tag to string convert """
        def tstr( tag ):
            ret = ''
            if type(tag)==int:
                ret += "%02X" % tag
            else: 
                for t in tag: ret += "%02X" % t
            return ret
        
        if msg[0] == 'message':
            if msg[2][1]=='error':
                print(Back.RED + msg[1][1][:-3] + '! ' + msg[3][1] )
            elif msg[2][1]=='info':
                print(Back.GREEN + msg[1][1][:-3]+ '> ' + msg[3][1] )
            elif msg[2][1]=='warning':
                print(Back.BLUE + msg[1][1][:-3]+ '> ' + msg[3][1] )  
            else:
                print(msg[1][1][:-3]+'>', msg[3][1])
        #Structural message parsing
        else:
            if msg[0]=='send' or msg[0]=='recv': 
                if msg[0]=='send' and msg[4][1][0]=='value':
                    val = msg[4][1][1][1]
                    desc = msg[4][1][2][1]
                    info = 'CLA|INS|P1|P2=%s [%s]' % (val, desc)
                elif msg[0]=='recv':
                    val = msg[4][1][1][1]
                    desc = msg[4][1][2][1]
                    info = "STATUS=%X [%s]" % (val, desc)
                print(msg[1][1][:-3]+'| ' + Fore.YELLOW + msg[0] + Fore.RESET + '> ' + info)
                if len(msg[2][1][1])>0:
                    msg_len = len(msg[2][1][1])
                    print(Back.WHITE + Fore.BLACK + msg[2][0]+": [%i]" % msg_len )
                    print(Fore.GREEN + msg[2][1][0]+'|'+ msg[2][1][1])
                    print(Fore.GREEN + msg[2][2][0]+'|'+ msg[2][2][1])
                else:
                    print(Back.WHITE + Fore.BLACK + msg[2][0]+': [None]')
                print(Back.WHITE + Fore.BLACK + msg[3][0]+ ": [%i]" % len(msg[3][1:]))
                for f in msg[3][1:]:
                    print(Fore.GREEN + f[0] + '|' + f[1])
                tlv_msg = msg[4][2]
                if len(tlv_msg)>1:
                    for tlvi in tlv_msg[1:]:
                        if type(tlvi)==list:
                            if tlvi[0]=='template':
                                print(Back.BLUE + tlvi[0] + ' ' + tstr(tlvi[1][1]) + ' [' + tlvi[2][1]+']')
                                for tlvy in tlvi[3:]:
                                    print(Back.MAGENTA+ tlvy[0] + ' '+ tlvy[1][1] + ' [' + tlvy[2][1] + ']')
                                    print(Fore.GREEN + tlvy[3][1][0] + '|' + tlvy[3][1][1]) 
                                    print(Fore.GREEN + tlvy[3][2][0] + '|' + tlvy[3][2][1])
                        else:
                            raise Exception('Dodac obluge samych tagow')
            else:
                raise Exception('Unknown frame')
    
    '''Console output handler '''
    def __xml_output(self, level, msg ):
        #Convert string
        def tstr( tag ):
            ret = ''
            if type(tag)==int:
                ret += "%02X" % tag
            elif type(tag)==str:
                ret = tag
            else: 
                for t in tag: ret += "%02X" % t
            return ret
        #import itertools as it
        def msg_iter(imsg, tree):
            for i in imsg:
                if type(i)==list:
                    if len(i)>=2 and type(i[0])!=list and type(i[1])!=list:
                        #print('YYY', i)
                        etree.SubElement(tree, str(i[0])).text = tstr(i[1])
                    else:
                        msg_iter(i, tree)
                else:
                    #print('XXX', i)
                    tree = etree.SubElement(tree, i)
                
                   
        msg_iter( msg, self.__root_xml)
                
    
    ''' Log level descriptor '''
    __LOGLEVEL_DESC = {
        LOGLEVEL_ERROR  : "error",
        LOGLEVEL_USER   : "user",
        LOGLEVEL_SYSTEM : "system",
        LOGLEVEL_PARSE  : "parse",
        LOGLEVEL_DATA   : "data",
        LOGLEVEL_PACKET : "packet",
        LOGLEVEL_INFO   : "info",
        LOGLEVEL_WARNING: "warning",
    }
    ''' Application loglevel mask '''
    __loglevel_mask =  LOGLEVEL_ERROR | LOGLEVEL_USER | LOGLEVEL_PARSE | LOGLEVEL_DATA | LOGLEVEL_SYSTEM | LOGLEVEL_INFO | LOGLEVEL_WARNING
    
    ''' Output handler '''
    __log_handler = [ __console_output, __xml_output ]
    
    ''' Constructor '''
    def __init__(self):
        import os
        import os.path as path
        colorama.init(autoreset=True)
        self.__root_xml = etree.Element("testharness")
        if not path.exists(self.__OUTPUT_DIR):
            os.mkdir(self.__OUTPUT_DIR)
        self.__xml_filename = path.join(self.__OUTPUT_DIR, 
                'results-' + str(datetime.datetime.now()).replace(' ','_').replace(':','-').replace('.','-') + ".xml")
    
    ''' Save xml output '''
    def save_xml_output(self):
        xtree = etree.ElementTree(self.__root_xml)
#        pi = etree.ProcessingInstruction('xml-stylesheet', 'type="text/xsl" href="testharness.xsl"')
#        pi.(1, self.__root_xml)
#        xtree = etree.ElementTree(pi)
#        xtree.write(self.__xml_filename, xml_declaration=True, encoding="utf-8")
        with open(self.__xml_filename, 'w') as f:
            f.write('<?xml version="1.0" encoding="UTF-8" ?>')
            f.write('<?xml-stylesheet type="text/xsl" href="testharness.xsl"?>')
            xtree.write(f, xml_declaration=False, encoding="unicode")
        #Copy XSLT file if not exists
        import os.path as path
        import shutil
        dest_xsl = path.join(self.__OUTPUT_DIR, 'testharness.xsl')
        src_xsl = path.join(path.dirname(path.realpath(__file__)),'./config/testharness.xsl')
        if not path.exists( dest_xsl ):
            shutil.copy(src_xsl, dest_xsl)
        

    ''' Log '''
    def log_level(self, level, *args):
        if self.__loglevel_mask & level:
            xstr = ''
            for ax in args:
                xstr += (str(ax) if type(ax)!=str else ax) + ' '
            #Format XML like message
            fmt = [ 'message',
                    ['timestamp',  str(datetime.datetime.now())],
                    ['level', self.__LOGLEVEL_DESC[level] ],
                    ['value', xstr] 
                  ]
            for f in self.__log_handler: f(self,level, fmt) 
    
    ''' Log frame in message '''
    def log_send_receive(self, title ,fmt_array):
        if self.__loglevel_mask & self.__LOGLEVEL_DATA_LOG:
            fmt = [ title,
                    ['timestamp',  str(datetime.datetime.now())],
                  ]
            fmt += fmt_array
            for f in self.__log_handler: f( self,self.__LOGLEVEL_DATA_LOG, fmt ) 
    
    ''' Log '''
    def log(self, *args):
        self.log_level(self.LOGLEVEL_USER, *args)
    
    ''' Log '''
    def logerr(self, *args):
        self.log_level(self.LOGLEVEL_ERROR, *args)
        
    ''' Log '''
    def logwarning(self, *args):
        self.log_level(self.LOGLEVEL_WARNING, *args)

    def loginfo(self, *args):
        self.log_level(self.LOGLEVEL_INFO, *args)

    def logsys(self, *args):
        self.log_level(self.LOGLEVEL_SYSTEM, *args)
        
''' Get syslog singleton '''
__syslog_obj = None

def getSyslog():
    global __syslog_obj
    if __syslog_obj == None:
        __syslog_obj = syslog()
    return __syslog_obj
