""" VIPA test framework TestHarness
"""
import testharness


__author__ = "Lucjan Bryndza"
__copyright__ = "(c) 2012 Lucjan Bryndza"
__license__ = "GPL"
__email__ = "Lucjan_B1@verifone.com"

import ssl
import serial
import socket
import configparser
from testharness.tlvparser import TLVPrepare
from testharness.syslog import getSyslog
from testharness.exceptions import timeoutException
import testharness.utility as tutil
import select
import pyDes

""" Class connection handle the information about the VIPA connection """
class Connection(object):
        '''
        classdocs
        '''
        #Connection handler
        __connection = None
        #Nad value
        __nad = 1
        #Is chained message
        __chained_tx_messages = True
        #Max allowed packet length
        __MAX_PACKET_PROTO_LEN  = 254
        #Header len
        __HEADER_PROTO_LEN = 4
        #Max packet raw length
        __MAX_PACKET_RAW_LEN  = 254 + __HEADER_PROTO_LEN
        #Global timeout 
        __timeout = None
        #Constructor
        __SEQ_NUM = 0
        def __init__(self):
            import os.path as path
            self.__raw_socket = None
            #Read config analyzer
            self.__desc_cfg = configparser.ConfigParser()
            ini_name = path.join(path.dirname(path.realpath(__file__)),'./config/analyse.ini')
            self.__desc_cfg.read( ini_name)
            self.ssl = False

        def __del__(self):
                if self.__connection != None:
                        self.__connection.close()

        """ Enable or disable chained messages """
        def enable_chained_messages( self, state ):
                self.__chained_tx_messages = state

        """ Connect using serial port
        """
        def connect_serial( self, port ,speed, parity = 'N', timeout = None,
                        use_rtscts = False, use_dsrdtr = False, use_xonxoff = False):
                if parity == 'N':
                        parity = serial.PARITY_NONE;
                elif parity == '0':
                        parity = serial.PARITY_ODD;
                elif parity == 'E':
                        parity = serial.PARITY_EVEN;
                self.__connection = serial.Serial( port,
                                baudrate= speed, bytesize= serial.EIGHTBITS, parity = parity,
                                stopbits = serial.STOPBITS_ONE, writeTimeout= timeout, timeout=timeout,
                                dsrdtr = use_dsrdtr, rtscts = use_rtscts, xonxoff = use_xonxoff
                        )
                self.__timeout = timeout

        """ Parse argument line 
            return true if unsolicited is required"""
        def connect(self): 
            slog = getSyslog()
            #Create argument list
            result = tutil.parse_args()
            if 'sslkey' in vars(result): ssl_protocol = True
            else: ssl_protocol = None
            SSLVERIFY = { 'none': ssl.CERT_NONE, 'optional' : ssl.CERT_OPTIONAL, 'required' : ssl.CERT_REQUIRED }
            ctimeout = result.timeout
            if type(ctimeout)==int and ctimeout < 1: ctimeout=1
            sslverify = isslverify=SSLVERIFY[result.sslverify] if 'sslverify' in vars(result) else None
            sslca = result.sslca if 'sslca' in vars(result) else None
            sslcert = result.sslcert if 'sslcert' in vars(result) else None
            sslkey = result.sslkey if 'sslkey' in vars(result) else None
            sslpasswd = result.sslpasswd if 'sslpasswd' in vars(result) else None
            # Information about certificate
            if result.se_whitelist:
                self.ClearCommands=result.se_whitelist.split(',')
            if result.seq_num:
                self.__SEQ_NUM = int(result.seq_num)
            if result.se_cert == None:
                self.send = self.send_standard
                self.receive = self.receive_standard
            else:
                self.send = self.send_se
                self.receive = self.receive_se
                self.tdes=pyDes.triple_des(open(result.se_cert, 'rb').read(), pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
            if result.serial_port!=None and ssl_protocol:
                slog.log('SSL mode CA:', sslca, 'KEYFILE:', sslkey,
                        'CERT:', sslcert, 'VERIFY:', result.sslverify,
                        'CERTPASS:', 'Yes' if result.sslpasswd else 'No' )
            #Parse results and apply class member
            if result.tcp_server!=None:
                slog.log("Argument parse TCP server mode listen on port", int(result.tcp_server))
                self.connect_tcp_server( port = int(result.tcp_server), timeout = ctimeout,
                        ssl_protocol=ssl_protocol, verify_mode=sslverify, ca_cert=sslca,
                        certfile=sslcert, keyfile=sslkey, cert_pass = sslpasswd )
            elif result.tcp_client!=None:
                hostport= result.tcp_client.split(':')
                slog.log("Argument parse TCP client mode trying to connect to", result.tcp_client)
                self.connect_tcp_client(hostport[0], int(hostport[1]) ,ssl_protocol, ctimeout,
                        sslverify, sslca, sslcert, sslkey, sslpasswd )
            else:
                portspeed = result.serial_port.split(':')
                if len( portspeed )==1:  portspeed.append('57600')
                slog.log("Argument parse SERIAL mode connecting to", result.serial_port,
                    ", flow control:", result.flow_ctrl)
                self.connect_serial(portspeed[0], int(portspeed[1]), timeout=ctimeout,
                    use_rtscts = (result.flow_ctrl == 'rts-cts'),
                    use_xonxoff = (result.flow_ctrl == 'xon-xoff'))
            return self.in_waiting(10) > self.__HEADER_PROTO_LEN

        """ Connect to tcp server """
        def connect_tcp_server(self, interface='0.0.0.0', port=16107, timeout = None, ssl_protocol = None,
                                 verify_mode = ssl.CERT_OPTIONAL, ca_cert = None, certfile = None, 
                                 keyfile =None, cert_pass = None):
            slog = getSyslog()
            listen_s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
            listen_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_s.bind((interface,port))
            listen_s.listen(1)
            slog.logsys('Waiting for connections');
            s, addr = listen_s.accept()
            if ssl_protocol == True:
                raw_sock = ssl.wrap_socket(s, keyfile=keyfile, certfile=certfile, cert_reqs=verify_mode, ca_certs = ca_cert, server_side=True)
                raw_sock.settimeout(10)
                self.ssl = True
            else: raw_sock = s
            if timeout != None: raw_sock.settimeout( timeout )
            else: raw_sock.settimeout( None )
            slog.logsys("Connected from", addr )
            if ssl_protocol == True:
                cert = raw_sock.getpeercert()
                slog.logsys('Peer cert', cert)
            self.__connection = socket.SocketIO( raw_sock, "rwb")
            self.__raw_socket = raw_sock
            self.__timeout = timeout


        """ Connect to tcp server
        """
        def connect_tcp_client(self, host, port=16107,ssl_protocol = None, timeout = None, verify_mode = ssl.CERT_OPTIONAL,
                               ca_cert = None, certfile = None, keyfile =None, cert_pass = None ):
            slog = getSyslog()
            s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
            if ssl_protocol == True:
                raw_sock = ssl.wrap_socket(s, keyfile=keyfile, certfile=certfile, cert_reqs=verify_mode, ca_certs = ca_cert)
                raw_sock.settimeout(10)
                self.ssl = True
            else: raw_sock = s
            raw_sock.connect((host,port))
            if ssl_protocol != None: slog.logsys('Server cert is',raw_sock.getpeercert()) 
            slog.logsys('Connected to', host, port  )
            if timeout != None: raw_sock.settimeout(timeout)
            else: raw_sock.settimeout(None)
            self.__connection = socket.SocketIO( raw_sock, "rwb")
            self.__raw_socket = raw_sock
            self.__timeout = timeout
            
        """ Return the number of bytes waiting on the port 
            Socket connection wait maximum amout of time or when 
            new data are available. Serial port always wait selected
            number of time, because select is not avail on the windows for
            the handles other than sockets """
        def in_waiting( self, timeout = 0 ):
            if self.__raw_socket == None:
                import time
                if timeout > 0: time.sleep(timeout)
                return self.__connection.inWaiting()
            else:
                to_read, _, _ = select.select([self.__raw_socket],[], [], timeout)
                if len(to_read) > 0:
                    if self.ssl:
                        return to_read[0].pending()
                    else:
                        received = to_read[0].recv(4096, socket.MSG_PEEK)
                        return len(received)
                else:
                    return 0

        """ Check if data is available
        """
        def is_data_avail( self, timeout = 0 ):
            return self.in_waiting( timeout ) > 0


        """ Send raw data
        """
        def send_raw( self, *args ):
                #from binascii import hexlify
                wr = 0
                data = bytearray();
                for a in args:
                        if type(a)!=int: data += bytearray(a)
                        else: data.append( a )
                #print('< SEND >',len(data),'<>', hexlify(data) )
                while wr < len(data):
                        wr += self.__connection.write( data[wr:] )
                        # getSyslog().logsys("Out buffer after writing %s bytes: %s" % (wr, self.__connection.outWaiting()))
                self.__connection.flush()
                return [data]
        
        """ Prepare log message """
        def log_message(self, title, buf_total, buf_frames, tags,val_extra):
            #To ascii internal convert
            def toascii( inp ):
                if inp==None: return ''
                inp = bytearray(inp if type(inp)!=int else [inp])
                for i, ch in enumerate(inp):
                    if ch<ord(' ') or ch>127: inp[i] = ord('.')
                return str(inp, 'iso8859-1')
            #To hex internal convert
            def tohex( inp ):
                if inp==None: return ''
                inp = bytearray(inp if type(inp)!=int else [inp])
                from binascii import hexlify
                return str(hexlify(inp) if inp!=None else '', 'iso8859-1')
            slog = getSyslog()
            log_array = [
                            [ 'data',
                               [ 'hex',  tohex(buf_total)],
                               [ 'ascii',  toascii(buf_total)]  
                            ]
                        ]
            frames = [ 'frames ']
            for f in  buf_frames: frames.append(['frame', tohex(f)  ])
            log_array.append(frames)
            if type(val_extra)==int:
                asc =  ['ascii', self.__desc_cfg['SW1SW2'].get("%04X"%val_extra,"NA")]
                value_v = [ 'value',  ['hex', val_extra], asc ]
            else:
                sval = tohex(bytearray(val_extra))
                asc =  ['ascii', self.__desc_cfg['CLAINS'].get(sval[:4].upper(),"NA")]
                value_v = ['value', ['hex', sval], asc ]
            tlv_v = ['tlv']
            if tags!=None:
                #Single elem
                if type(tags)==tuple: tags = [tags]
                for idx0 in tags:
                    if type(idx0)!=int and len(idx0)==2:
                        if type(idx0[1])==bytes: idx0[1] = bytearray(idx0[1])
                        if type(idx0[0])==tuple and (type(idx0[1])==bytearray or (type(idx0[1])==list and len(idx0[1])>0 and type(idx0[1][0])==int) ) :
                            tag_v = ['tag', ['value', tohex(idx0[0])], ['desc', 'NA'],
                                        [   'data', 
                                            ['hex', tohex(idx0[1])], 
                                            ['ascii', toascii(idx0[1])] 
                                        ]
                                    ]
                            tlv_v.append(tag_v)
                        elif (type(idx0[0])==tuple or type(idx0[0])==int) and type(idx0[1])==list:
                            tpl_desc = self.__desc_cfg['Templates'].get(tohex(idx0[0]),"NA")
                            tpl_v = [ 'template', ['value', idx0[0]], ['desc', tpl_desc] 
                                    ]
                            for idx1 in idx0[1]:
                                tag_desc = self.__desc_cfg['Tags'].get(tohex(idx1[0]).upper(),'NA')
                                tag_v = [ 'tag', ['value', tohex(idx1[0])], ['desc', tag_desc],
                                             [  'data', 
                                                 ['hex', tohex(idx1[1])], 
                                                 ['ascii', toascii(idx1[1])] 
                                             ]
                                       ] 
                                tpl_v.append(tag_v)
                            tlv_v.append(tpl_v)
                        elif type(idx0[0])==str:
                            unp_v = ['unparsed',
                                       ['hex', tohex(idx0[1])], 
                                       ['ascii', toascii(idx0[1])] 
                                    ]
                            tlv_v.append(unp_v)
                        else:
                            err_v = ['error', str(idx0)]
                            tlv_v.append(err_v)
            #Parsed v
            parsed_v = [ 'parsed ',  value_v, tlv_v]
            log_array.append(parsed_v)
            slog.log_send_receive(title, log_array)
            #Parse tags
            

        """ Send data over the medium
        TODO - ADD 4 bytes of cokolowiek...
        """
        def _send(self, value , tags = None, le_byte = None, log_packet = True, se=False ):
                se = True if (se and not (str(value[0])+ str(value[1])).upper() in self.ClearCommands) else False
                slog = getSyslog()
                slog.loginfo("-- SE --" + str(se))
                from testharness.exceptions import logicalException
                tlvp = TLVPrepare()
                tosend=None
                if len( value ) != 4:
                        logicalException(' Invalid header len must be equal 4')
                log_out_frame_buf = []
                tags_array = None
                le_array = bytearray()
                if le_byte != None:
                    le_array = bytearray([ le_byte & 0xFF ])
                if tags == None:
                        c_pcb = 0
                        tosend=bytearray( value ) + le_array 
                        
                        if se:
                            self.__SEQ_NUM+=1
                            tosend+=self.__SEQ_NUM.to_bytes(4,'big')
                            tosend = self.tdes.encrypt( tosend )
                            c_pcb |= 2
                        w_len = len( tosend )
                        lrc = tutil.lrccalc( self.__nad, c_pcb, w_len, tosend )
                        log_out_frame_buf += self.send_raw( self.__nad, c_pcb, w_len, tosend ,lrc )
                else:
                        tags_array = tlvp.prepare_packet_from_tags(tags)
                        #Prepare length
                        tags_array[0] = 255 if (len(tags_array)-1) > 255 else len(tags_array)-1
                        tags_array = bytearray( value ) + tags_array
                        tags_array += le_array
                        if se:
                            self.__SEQ_NUM+=1
                            tags_array+=self.__SEQ_NUM.to_bytes(4,'big')
                            tags_array=self.tdes.encrypt( tags_array )
                        w_len = len( tags_array )
                        #Send long or short packets depends on the chained msgs enabled
                        if w_len > self.__MAX_PACKET_PROTO_LEN and not self.__chained_tx_messages:
                                raise logicalException('Packet too long > 254 and chained msgs not enabled')
                        if w_len <= self.__MAX_PACKET_PROTO_LEN:
                                c_pcb = 2 if se else 0
                                lrc = tutil.lrccalc( self.__nad, c_pcb, w_len, tags_array )
                                log_out_frame_buf += self.send_raw( self.__nad, c_pcb, w_len ,tags_array ,lrc )            
                        else:
                                total_len = w_len
                                for p in range(0,total_len, self.__MAX_PACKET_PROTO_LEN):
                                        raw_data = tags_array[p:(p+self.__MAX_PACKET_PROTO_LEN) ]
                                        c_pcb = 2 if se else 0
                                        c_pcb |= 1 if len(raw_data)==self.__MAX_PACKET_PROTO_LEN else 0
                                        raw_len = len(raw_data)
                                        lrc = tutil.lrccalc( self.__nad, c_pcb, raw_len, raw_data )
                                        log_out_frame_buf += self.send_raw( self.__nad, c_pcb, raw_len, raw_data ,lrc )
                if not se and log_packet:
                    self.log_message('send', tags_array , log_out_frame_buf, tags, value)
                elif log_packet:
                    if tags == None:
                        self.log_message('send', tags_array, [ self.tdes.decrypt( tosend) ], tags, value )
                    else:
                        self.log_message('send', tags_array, [ self.tdes.decrypt( tags_array ) ], tags, value )

        def send_standard(self, value , tags = None, le_byte = None, log_packet = True ):
            self._send(value , tags, le_byte, log_packet, False)

        ''' nearly the same as above - only has encryption - TODO do it nice '''
        def send_se(self, value , tags = None, le_byte = None, log_packet = True ):
            self._send(value , tags, le_byte, log_packet, True)

        """ Send hexadecimal data """
        def send_rawhex(self, arg):
                self.send_raw( bytearray().fromhex(arg) )

        def __receive( self, parse, timeout, log_packet, se=False ):
                if timeout == None:
                    timeout = self.__timeout
                    req_set = False
                else:
                    req_set = True
                if timeout !=None and timeout > 0 and req_set == True:
                    if self.__raw_socket != None:
                        self.__raw_socket.settimeout( timeout )
                    else:
                        self.__connection.setTimeout( timeout )
                from testharness.exceptions import logicalException
                data_frame = bytearray()
                is_unsolicited = None
                log_out_frame_buf = []
                while True:
                        rxbuf = bytearray()
                        while True:
                                read_value = self.__connection.read( 3 )
                                if timeout!=None and timeout > 0 and len( read_value )==0:
                                    raise timeoutException()
                                rxbuf += read_value
                                if len(rxbuf) < 3: continue
                                nad =  rxbuf[0]
                                pcb =  rxbuf[1]
                                blen = rxbuf[2]
                                if is_unsolicited==None: is_unsolicited = True if pcb&0x40 else False
                                break
                        rxbuf = bytearray()
                        while True:
                                read_value = self.__connection.read( blen )
                                if timeout!=None and timeout > 0 and len( read_value )==0:
                                    raise timeoutException()
                                rxbuf += read_value
                                if len(rxbuf) >= blen: break
                        while True:
                                lrc = self.__connection.read( 1 )
                                if timeout!=None and timeout > 0 and len( lrc )==0:
                                    raise timeoutException()
                                if len( lrc ) >= 1: break
                        calc_lrc = tutil.lrccalc( nad, pcb, blen, rxbuf, lrc )
                        if calc_lrc != 0 and nad == self.__nad:
                                raise logicalException('Invalid LRC')
                        if nad != self.__nad:
                                rxbuf = bytearray()
                                continue
                        data_frame += rxbuf
                        log_out_frame_buf += [ bytearray( [nad] ) +  bytearray( [pcb] ) +  bytearray( [blen] ) + data_frame + lrc ]
                        if pcb&1 == 0: break 
                from struct import unpack
                from binascii import hexlify
                tags=None
                slog = getSyslog()
                if se and ( pcb & 2):
                    data_frame = bytearray(self.tdes.decrypt( data_frame ) )
                    slog.log("Received seq num: ",str(hexlify(  data_frame[ len(data_frame) - 4: ] )))
                    # if se take response except last 4 bytes
                    data_frame = data_frame[:-4]
                slog.loginfo("IN: " + str(hexlify(data_frame)))
                if parse:
                    tlvp = TLVPrepare()
                    tags = tlvp.parse_received_data( data_frame )
                else:
                    tags = data_frame[:-2]
                b_status = unpack("!H",data_frame[-2:])[0] 
                if log_packet:
                    self.log_message('recv', data_frame[:-2] , log_out_frame_buf, tags, b_status)
                return b_status, tags , is_unsolicited

        def receive_se( self, timeout = None, log_packet = True ):
                return self.__receive(True, timeout, log_packet, True )

        """ Receive data from the medium
        """
        def receive_standard( self, timeout = None, log_packet = True ):
                return self.__receive(True, timeout, log_packet )

        def receive_raw( self, timeout = None, log_packet = True ):
                return self.__receive(False, timeout, log_packet )

        """ Set NAD
        """
        def setnad(self, nad_value):
                ret = self.__nad
                self.__nad = nad_value
                return ret

        """Close the connection
        """
        def close(self):
                self.__connection.close( );
