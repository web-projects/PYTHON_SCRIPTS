'''
Created on 12-06-2012

@authors: lucjan_b1, kamil_p1
'''

import httplib2
from testharness.exceptions import logicalException
from xml import etree


''' Semtec exception class '''
class encryptException( logicalException ):
    def __init__(self, value):
        logicalException.__init__(self, value)



class encryptor(object):
    '''
    Encrypt semtec message
    '''
    def __init__(self, url = 'http://vsdtest4.semtek.com'):
        '''
        Constructor
        '''
        self.url = url
        self.http = httplib2.Http()
    
    
    ''' Response codes constants'''
    __SRV_RESPONSE_OK = 200
    __SEMTEC_RESULT_SUCCESS = 100

    ''' constants for tracks '''
    __T1SUB = 0x20
    __T2SUB = 0x30

    ''' extra parameters '''
    __p_domain =  'HDA4DOM'
    __p_mid    =  'HDA4MER'
    __p_store  =  'HDA4STORE'
    __p_device =   '*'
    
    ''' Set domain '''
    def set_domain(self, domain):
        self.__p_domain = domain
    ''' Set mid '''
    def set_mid(self, mid):
        self.__p_mid = mid
        ''' Set store '''
    def set_store(self, store):
        self.__p_store = store
    ''' Set device '''
    def set_device(self, device):
        self.__p_device = device
        ''' Set Serial number '''
    def set_TID(self, TID):
        self.TID = TID 
    ''' Set tid '''

    ''' computes lrc over string '''
    def __lrc(self, data, sub):
        res = 0
        for c in data:
          res = (res ^ (ord(c) - sub)) & 0xFF
        res = (res + sub) & 0xFF
        return chr(res)

    ''' extract track2 discretionary data from track2 equivalent '''
    def __t2eq_2_t2(self, t2eq):
        if len(t2eq) == 0:
            raise encryptException('Invalid parameters')
        panSep = t2eq.find('d')
        if panSep == -1:
            raise encryptException('Invalid Track2 Equivalent data')
        t2 = ';'
        t2 += t2eq[:panSep]
        t2 += '='
        panSep += 1
        t2 += t2eq[panSep:]
        if t2[-1] == 'f':
            t2 = t2[:-1]
        t2 += '?'
        t2 += self.__lrc(t2, self.__T2SUB)
        return t2

    ''' create track2 discretionary data based on track2 equivalent data '''
    def __t2_2_t2eq(self, t2):
        if len(t2) == 0:
            raise encryptionException('Invalid parameters')
        panSep = t2.find('=')
        if panSep == -1:
            raise encryptException('Invalid Track2 data')
        t2eq = t2[1:panSep]
        t2eq += 'd'
        panSep += 1
        t2eq += t2[panSep:-1]
        if len(t2eq) % 2:
            t2eq += 'f'
        return t2eq

    ''' create magstripe tracks based on EMV data '''
    def __create_track1(self, pan, expiry, t1dd):
        if len(pan) == 0 or len(expiry) == 0:
            raise encryptException('Invalid parameters')
        t1 = ''
        if len(t1dd) > 0:
            t1 = '%B'
            t1 += pan
            t1 += '^^' # separator, name (empty), separator
            t1 += expiry
            t1 += '201' # service code
            t1 += t1dd
            t1 += '?'
            t1 += self.__lrc(t1, self.__T1SUB)
        return t1
    ''' create magstripe track2, based on EMV data '''
    def __create_track2(self, pan, expiry, t2dd):
        if len(pan) == 0 or len(expiry) == 0:
            raise encryptException('Invalid parameters')
        t2 = ''
        if len(t2dd) > 0:
            t2 = ';'
            t2 += pan
            t2 += '='
            t2 += expiry
            t2 += '201' # service code
            t2 += t2dd
            t2 += '?'
            t2 += self.__lrc(t2, self.__T2SUB)

    ''' calculates T1 and T2 based on EMV values passed, returns decrypted data '''
    def decrypt_emv(self, pan, expiry, t2eq, t2dd='', t1dd='', eparms='', amt=0):
        # EMV transaction
        t2 = ''
        t1 = ''
        if len(t1dd) > 0:
            # T1D present - we have to prepare Track1
            t1 = __create_track1(pan, expiry, t1dd)
            #log.log('Track1: ', t1)
        if len(t2eq) > 0:
            t2 = self.__t2eq_2_t2(t2eq)
            #log.log('track2: ', t2)
        if len(t2dd) > 0:
            # T1D present - we have to prepare Track1
            t2t = __create_track2(pan, expiry, t2d)
            #log.log('Track1: ', t2d)
            if t2t != t2:
                # We have to decrypt twice!!!
                t2t = t2d
        pan_d, expiry_d, t1_d, t2_d = self.decrypt(pan, expiry, t1, t2, eparms)
        # Change t2eq
        t2eq_d = ''
        t2dd_d = ''
        t1dd_d = ''
        if len(t2eq) > 0:
            t2eq_d = self.__t2_2_t2eq(t2_d)
        if len(t2dd) > 0:
            pass
        if len(t1dd) > 0:
            pass
        return pan_d, expiry_d, t2eq_d, t2dd_d, t1dd_d

    ''' decrypts pan, expiry and tracks '''
    def decrypt(self, pan, expiry, T1='', T2='', eparms='', amt=0):
        p_Req = ''
        p_Txn = ''
        p_TxnType = '' 
        if len(T1): 
            T1 = T1.replace('%', '%25')
            T1 = T1.replace(' ', '%20')
        if len(T2): 
            T2 = T2.replace('%', '%25')
            T2 = T2.replace(' ', '%20')
        if len(pan):
            pan = pan.rstrip('f')
            pan = pan.rstrip('F')
        if len(expiry) == 6:
            expiry = expiry[:-2]
        urlreq = self.url + "/cipher.asmx/DecryptV04?Req=%s&Txn=%s&TxnType=%s&Amt=%s&Eparms=%s&Domain=%s&Mid=%s&Store=%s&Tid=%s&Device=%s&T1=%s&T2=%s&Pan=%s&Expiry=%s" \
        % (p_Req.strip(), p_Txn.strip(), p_TxnType.strip(), str(amt).strip(), eparms.strip(), self.__p_domain.strip(), 
           self.__p_mid.strip(), self.__p_store.strip(), 
           self.TID.strip(), self.__p_device.strip(), T1.strip(), T2.strip(), pan.strip(), expiry.strip())
        # print('Request: ', urlreq)
        response, content = self.http.request( urlreq, 'GET')
        if int(response['status']) != self.__SRV_RESPONSE_OK:
            raise encryptException('Invalid response ' + str(response))
        #Parse the XML
        tree = etree.ElementTree.fromstring( content )
        e_result_code = tree.find("{Cipher}ResultCode")
        if e_result_code == None:
            raise encryptException('Result code not found')
        else:
            e_result_code = int( e_result_code.text.strip() )
        e_result_desc = tree.find("{Cipher}ResultDesc")
        if e_result_desc == None:
            raise encryptException('Result description not found')
        else:
            e_result_desc = e_result_desc.text.strip()
        # etree.ElementTree.dump(tree)
        if e_result_code != self.__SEMTEC_RESULT_SUCCESS:
            raise encryptException(e_result_desc + '. INT=' + str(e_result_code))  

        e_pan = ''
        e_expiry = ''
        e_t1 = ''
        e_t2 = ''
        if len(pan) > 0:
            e_pan = tree.find("{Cipher}Pan")
            if e_pan == None:
                raise encryptException("Decrypted PAN not found!")
            e_pan = e_pan.text.strip()
        if len(expiry) > 0:
            e_expiry = tree.find("{Cipher}Expiry")
            if e_expiry == None:
                raise encryptException("Decrypted Expiry not found!")
            e_expiry = e_expiry.text.strip()
        if len(T1) > 0:
            e_t1 = tree.find("{Cipher}T1")
            if e_t1 == None:
                raise encryptException("Decrypted T1 not found!")
            e_t1 = e_t1.text.strip()
        if len(T2) > 0:
            e_t2 = tree.find("{Cipher}T2")
            if e_t2 == None:
                raise encryptException("Decrypted T2 not found!")
            e_t2 = e_t2.text.strip()
        return e_pan, e_expiry, e_t1, e_t2
