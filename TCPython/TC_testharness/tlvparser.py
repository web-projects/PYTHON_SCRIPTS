'''
Created on 27-03-2012

@author: Lucjan_B1
'''

from binascii import hexlify

class TLVParser(object):
    '''
    classdocs
    '''

    """ Initial constructor """
    def __init__(self, tagbuf ):
        self.__tagbuf = tagbuf
    
    """ Iterate over the tags """
    def __iter__(self):
        for index in self.__tagbuf:
            if len(index)==2:
                if type(index[0])==tuple and type(index[1])==bytearray:
                    yield (index[0], index[1])
                elif type(index[0])==tuple and type(index[1])==list:
                    for idx1 in index[1]:
                        yield (idx1[0], idx1[1])

    """ Get tag from the structure """
    def __get_tag(self, tagval):
        if type(tagval)==int: tagval = (tagval,)
        ret = []
        for idx0 in self.__tagbuf:
            if len(idx0)==2:
                if type(idx0[0])==tuple and type(idx0[1])==bytearray:
                    if idx0[0]==tagval:
                        ret.append(idx0[1])
                elif type(idx0[0])==tuple and type(idx0[1])==list:
                    if idx0[0]==tagval:
                        ret += idx0[1];
                    else:
                        for idx1 in idx0[1]: 
                            if idx1[0]==tagval:
                                ret.append(idx1[1])
        return ret
    
    
    
    """ Conversion constants """
    CONVERT_INT = 1
    CONVERT_STR = 2
    CONVERT_DEF = 3
    CONVERT_HEX_STR = 4
    
    
    """Convert to value """
    def __convert_bytearray(self, b, conversion):
        from struct import unpack
        if conversion == self.CONVERT_INT:
            if len(b)==1: b = unpack("!B", b)[0]
            elif len(b)==2: b = unpack("!H", b)[0]
            elif len(b)==3: 
                b = b'\x00'+b
                b = unpack("!L", b)[0]
            else: b = unpack("!L", b)[0]
        elif conversion==self.CONVERT_STR:
            b = str(b,'iso8859-1')
        elif conversion==self.CONVERT_HEX_STR:
            b = str(hexlify(b),'iso8859-1')
        elif conversion==self.CONVERT_DEF:
            if len(b)==1: b = unpack("!B", b)[0]
            elif len(b)==2: b = unpack("!H", b)[0]
            elif len(b)==4: b = unpack("!L", b)[0]
            else:  b = str(b,'iso8859-1')
        return b
    
    """ Get tag and convert to selected value """
    def getTag(self, tagval, conversion=None):
        if conversion == None:  return self.__get_tag(tagval)
        else:
            ret = self.__get_tag(tagval)
            for i0,r0 in enumerate(ret):
                if type(r0)==bytearray:
                    ret[i0] = self.__convert_bytearray(r0, conversion)
                elif type(r0)==list:
                    ret[i0] = [r0[0], self.__convert_bytearray(r0[1], conversion)] + r0[2:]
        return ret
    
    """ Return number of item in tag 0 if not exist """
    def tagCount(self, tagval):
        return len(self.getTag(tagval))
    
    """ Tag to string convert """
    def __tag_str(self, tag):
        ret = ''
        for t in tag:
            ret += "%02X" % t
        return ret
    
    """ Print data in user friendly format """
    def __str__(self):
        ret = ''
        for idx0 in self.__tagbuf:
            if len(idx0)==2:
                if type(idx0[0])==tuple and type(idx0[1])==bytearray:
                    ret+= 'TAG ' + self.__tag_str(idx0[0]) + ' -> ' + str(idx0[1]) + '\n'
                elif type(idx0[0])==tuple and type(idx0[1])==list:
                    ret += 'TPL ' + self.__tag_str(idx0[0]) + '\n'
                    for idx1 in idx0[1]:
                        ret+= '\tTAG ' + self.__tag_str(idx1[0]) + ' -> ' + str(idx1[1]) + '\n'
                elif type(idx0[0])==str:
                    ret += 'UNPARSED ' + str(idx0[1]) + '\n'
            else:
                ret += 'INVALID VALUE ' + str(idx0) + '\n'
        return ret
    
    
    """ Get unparsed invalid data """
    def getUnparsed(self):
        ret = []
        for idx0 in self.__tagbuf:
            if len(idx0)==2 and type(idx0[0])==str:
                ret += idx0[1]
        return ret
    
''' --------------------------------------------------------------------------- '''
'''Class for the tlv create '''
class TLVPrepare(object):
    """ Prepare byte array from template """
    def __prepare_from_template( self, template, tags ):
        from testharness.exceptions import logicalException
        #if type(template) != int or template>255 or template<0:
        if type(template) != int:
                logicalException(' Template value from 0 to 255 required' )
        t_array = bytearray( )
        tag_buf = self.__prepare_from_tags( tags )
        t_array.append( template )
        t_array += self.__prepare_tlv_length(len(tag_buf) )
        #print('template tlv len', len(tag_buf))
        t_array += tag_buf
        return t_array
    
    """ Decode tlv len """
    def __decode_tlv_length( self, buf ):
        if buf[0] & 0x80 == 0:
                return int(buf[0]),1
        else:
                value = 0
                n_bytes = buf[0] & 0x7F
                for i in range ( 1, n_bytes+1 ):
                        #value =  buf[i] << (( i - 1 )*8)
                        value <<= (i-1)*8
                        value += buf[i]
        return value, n_bytes+1

    """ Prepare bytearray from tags """
    def __prepare_from_tags( self, tags ):
        t_array = bytearray()
        for t in tags:
                raw_value = self.__convert_bytearray(t[1])
                t_array += self.__tuple_bytearray(t[0]) + self.__prepare_tlv_length(len(raw_value)) + raw_value
        #print("tag_len", len(t_array))
        return t_array
    
    """ Convert basetypes to bytearray """
    def __convert_bytearray(self, value):
        tags_array = bytearray()
        if type(value)==list and type(value[0])==int:
            tags_array = bytearray(value)
        elif type(value)==str:
            tags_array  = bytearray(value,'iso8859-1')
        elif type(value)==bytes or type(value)==bytearray:
            tags_array = value
        return tags_array
        
    """Convert tupple to bytearray """
    def __tuple_bytearray(self, value):
        tags_array = bytearray()
        if type(value)==tuple: tags_array = bytearray(value)
        elif type(value)==int: tags_array = bytearray([value])
        return tags_array
        
    """ Tlv len in byte array """
    def __prepare_tlv_length( self, tag_len ):
        from math import log
        #binify
        def binify( value ):
                byts = []
                while value !=0:
                        b = value % 256
                        byts.insert(0, b)
                        value //= 256
                return bytearray( byts )
        #Convert to bye array
        if tag_len<128:
                return bytearray([tag_len])
        else:
                n_bytes = int(log(tag_len, 2)/8.0 + 1)
                ret = bytearray([n_bytes|0x80])
                ret += binify(tag_len)
        return ret

    """  Parse received primitive """
    def __parse_received_primitive( self, data_frame ):
        if len( data_frame ) < 3:
                return data_frame
        #from binascii import hexlify
        #print('< RECVP >',len(data_frame),'<>', hexlify(data_frame) )
        #Constants defs
        VALUE_MASK = 0b11111
        SUBSEQUENT_BYTES = VALUE_MASK
        CONSTRUCTED_DATA_OJBJECTS = 0b100000

        is_template = True if data_frame[0]&CONSTRUCTED_DATA_OJBJECTS else False
        tag = [ data_frame[0] ]
        #from binascii import hexlify
        #print('< RECVP >', is_template )
        if data_frame[0] & VALUE_MASK == SUBSEQUENT_BYTES:
                for i in range(1,len(data_frame)):
                        tag.append( data_frame[i] )
                        if data_frame[i] & 0x80 == 0: break

        tag_len = len(tag)
        #if tag_len>1 and is_template:
        #        return data_frame
        #elif tag_len>3:
        if tag_len>3:
                return data_frame
        tag = tuple( tag )
        tlv_len, tlv_len_b = self.__decode_tlv_length(data_frame[tag_len:])
        if tlv_len > len(data_frame[tag_len + tlv_len_b :]):
                return data_frame
        data_buf = data_frame[tag_len + tlv_len_b : tag_len + tlv_len_b + tlv_len]
        rest_buf = data_frame[tag_len + tlv_len_b + tlv_len : ]
        return tag, data_buf, rest_buf, is_template


    """ Parse receive data function """
    def parse_received_data(self, data_frame_o):
        #from binascii import hexlify
        #print('< RECV >',len(data_frame_o),'<>', hexlify(data_frame_o) )
        ret = []
        data_frame_o = data_frame_o[:-2]
        data_frame = data_frame_o
        while len(data_frame)>0:
                #print('< PROCESSING >',len(data_frame),'<>', hexlify(data_frame) )
                result = self.__parse_received_primitive(data_frame)
                if type(result)==bytearray:
                        #ret.append(['unparsed' , result])
                        ret.append( data_frame_o )
                        #print('----------- ERROR #1 --------------')
                        return ret
                prim, data_buf, data_frame, is_template = result
                if is_template==True:
                        tag_result = []
                        #print('-------- TEMPL',prim,'LEN',len(data_buf),'--------')
                        while len(data_buf)>1:
                                t_result = self.__parse_received_primitive( data_buf )
                                if type(t_result)==bytearray:
                                        #ret.append( ['unparsed', result ] )
                                        ret.append( data_frame_o )
                                        #print('----------- ERROR #2 --------------')
                                        return ret
                                else:
                                    t_prim, t_data_buf, data_buf, t_is_template = t_result
                                    #print('TEMPLATE PARSE>>',t_prim, t_data_buf)
                                    tag_result.append([t_prim , t_data_buf])
                        ret.append( (prim, tag_result) )
                else:
                        #print('-------- TAG',prim,'LEN',len(data_buf),'--------', data_buf)
                        ret.append([prim , data_buf])
                #print('-------- NEXT --------')
        return ret
    
    """ prepare frame """
    def prepare_packet_from_tags(self, tags):
        from testharness.exceptions import invtypeException
        #data only if len is greather than zero
        tags_array =  self.__convert_bytearray( tags )
        #Tags if size is equal to zero
        if len(tags_array) ==0:
                tags_array = bytearray([0])
                #Simple tag
                if type( tags )==list:
                        tags_array += self.__prepare_from_tags( tags )
                #Tag on template
                elif type( tags )==tuple and len(tags)==2:
                        tags_array += self.__prepare_from_template( tags[0], tags[1] )
                #Unknown tag format
                else:
                    raise invtypeException('Unable to send object')
        else:
                tags_array = bytearray([254 if len(tags_array)>254 else len(tags_array)]) + tags_array
        return tags_array
    
    
''' Class for prepare TLV at startup '''
class tagStorage(object):
    
    """ Internal tag storage """
    def __init__( self ):
        self.__tag_buffer = []
    
    """ Store tag into the array of tags"""
    def store(self, tag, value):
        if type(tag)==int: tag = (tag,)
        if type(value)==int: value = [ value ]
        if type(value)==str: value = bytearray(value, 'iso8859-1')
        self.__tag_buffer.append( [ tuple(tag), list(value) ] )
    
    """ Clear the list """
    def clear(self):
        del self.__tag_buffer[:]
    
    """ Get current tag """
    def get(self):
        return self.__tag_buffer
    
    """ Get template """
    def getTagData( self, tag ):
        found = next((x for x in self.__tag_buffer if x[0]==tag ),None)
        if found !=None:
            return found[1]
        else:
            return None

    """ Get template arg """
    def getTemplate(self, template):
        return (template, self.__tag_buffer)  

    """ Embed into template """
    def getAsBytearray(self):
        tlvp = TLVPrepare()
        return tlvp.prepare_packet_from_tags(self.__tag_buffer)[1:]

