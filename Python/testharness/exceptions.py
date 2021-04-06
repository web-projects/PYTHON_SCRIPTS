'''
Created on 15-03-2012

@author: Lucjan_B1
'''

#Logical exception class for example flow etc
class logicalException( Exception ):
    __value = None
    __errcode = None
    # Constructor
    def __init__( self, value ):
        self.__value = value
    # String converter
    def __str__( self ):
        return repr(self.__value)


#Logical exception class for example flow etc
class invResponseException( Exception ):
    __value = None
    __errcode = None
    # Constructor
    def __init__( self, value, errcode ):
        self.__value = value + ' error: ' + hex(errcode)
        self.__errcode = errcode
    #String converter
    def __str__( self ):
        return repr(self.__value)
    #Error code
    def error_code( self ):
        return self.__errcode


#Invalid type exception
class invtypeException( Exception ):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


#Timeout exception
class timeoutException( Exception ):
    def __init__(self, value = 'Timeout occured'):
        self.value = value
    def __str__(self):
        return repr(self.value)

