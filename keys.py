#!/usr/bin/python3

import text

class KeyCmn(object):
    def __init__(self, key, value):
        text.KeyName(key) # key name validation
        self.__key = key
        self.__value = value
        
    @property
    def key(self):
        return self.__key
    
    @property
    def tvalue(self):# text value
        return self.__value
    
    @property
    def text(self):
        if isinstance(self.__value, list):
            values = ",".join(self.__value)
        else:
            values = self.__value
        return self.__key + "=" + values + "\x00"

class TPGT(KeyCmn):# TargetPortalGroupTag
    def __init__(self, value):
        super().__init__("TargetPortalGroupTag", value)
        
    @property
    def value(self):# will return 16-bit binary-value
        return text.BinValue(self.tvalue).Value

class AuthMethod(KeyCmn):
    KRB5 = 0
    SPKM1 = 1
    SPKM2 = 2
    SRP = 3
    CHAP = 4
    NONE = 5
    __text_auth = {"KRB5":KRB5, "SPKM1":SPKM1, "SPKM2":SPKM2, "SRP":SRP, "CHAP":CHAP, "None":NONE}
    def __init__(self, value):
        super().__init__("AuthMethod", value)
        
    @property
    def value(self):# will return list of values
        return [self.__text_auth[auth] for auth in self.tvalue.split(",")]
        
class InitName(KeyCmn):# InitiatorName
    def __init__(self, value):
        super().__init__("InitiatorName", value)
        text.IscsiNameValue(value)
        
    @property
    def value(self):
        return self.tvalue
        
class SessionType(KeyCmn):
    DISCOVERY = 0
    NORMAL = 1
    __text_session = {"Discovery":DISCOVERY, "Normal":NORMAL}
    __session_text = {DISCOVERY:"Discovery", NORMAL:"Normal"}
    def __init__(self, value):
        if isinstance(value, int):
            value = self.__session_text[value]
        super().__init__("SessionType", value)

class MaxRecvDataSegmentLength(KeyCmn): 
    DEFAULT_VAL = 8192
    MAX_VAL = 0xFFFFFF
    MIN_VAL = 512
    def __init__(self, value = None):
        if value == None:
            value = self.DEFAULT_VAL
        if isinstance(value, int):
            int_val = value
            t_val = str(value)
        else:
            int_val = text.NumericalValue(value).Value
            t_val = value
        if int_val < self.MIN_VAL or int_val > self.MAX_VAL:
            raise ValueError
        super().__init__("MaxRecvDataSegmentLength", t_val)
        
    @property
    def value(self):
        return text.NumericalValue(self.tvalue).Value
    
class TargetName(KeyCmn):
    def __init__(self, value):
        super().__init__("TargetName", value)
        text.IscsiNameValue(value)
        
    @property
    def value(self):
        return self.tvalue
    
class TargetAddress(KeyCmn):
    def __init__(self, value):
        super().__init__("TargetAddress", value)
        
    @property
    def address(self):
        return text.ValueList(self.tvalue).Value[0]
    
    @property
    def tpgt(self):
        s = text.ValueList(self.tvalue).Value[1]
        return TPGT(s).value
        
def ParsePayload(pload):
    '''
    Returns KeyClass->KeyObject dictionary
    @param pload: binary payload
    '''
    name_key_tb = {"TargetPortalGroupTag":TPGT, "AuthMethod":AuthMethod, 
                   "InitiatorName":InitName, "SessionType":SessionType,
                   "MaxRecvDataSegmentLength":MaxRecvDataSegmentLength,
                   "TargetName":TargetName, "TargetAddress":TargetAddress}
    ustr = pload.decode("utf8")
    kv_pairs = ustr.split("\x00")
    retval = []
    for kv_pair in kv_pairs:
        if len(kv_pair) != 0:
            tmp = kv_pair.split("=")
            key = tmp[0]
            value = tmp[1:]
            if len(key) != 0 and len(value) == 1:
                value = value[0]
                key_class = name_key_tb[key]
                retval += [key_class(value)]
            else:
                print("multiple (=) char in key value pair")
    return retval

def GenPayload(keys):
    '''
    '''
    retval = ''
    for key in keys:
        retval += key.text
    return retval
    