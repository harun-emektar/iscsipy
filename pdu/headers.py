#!/usr/bin/python3
# Copyright (c) 2015. Harun Emektar
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from utils import ntoi,iton
import logging

#BHS
#Byte/      0       |       1       |       2       |       3       |
#     /             |               |               |               |
#   |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
#   +---------------+---------------+---------------+---------------+
# 0|.|I| Opcode     |F| Opcode-specific fields                      |
#   +---------------+---------------+---------------+---------------+
# 4|TotalAHSLength | DataSegmentLength                              |
#   +---------------+---------------+---------------+---------------+
# 8| LUN or Opcode-specific fields                                  |
#   +                                                               +
#12|                                                                |
#   +---------------+---------------+---------------+---------------+
#16| Initiator Task Tag                                             |
#   +---------------+---------------+---------------+---------------+
#20/ Opcode-specific fields                                         /
# +/                                                                /
#   +---------------+---------------+---------------+---------------+
#48
class BHS():
    # logger for Login pdu
    logger = logging.getLogger("BHS")
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)
    
    LENGTH = 48
    
    OPCODE_NOP_OUT = 0x00
    OPCODE_SCSI_CMD_REQ = 0x01
    OPCODE_TSK_MAN_REQ = 0x02
    OPCODE_LOGIN_REQ = 0x03
    OPCODE_TEXT_REQ = 0x04
    OPCODE_DATA_OUT = 0x05
    OPCODE_LOGOUT_REQ = 0x06
    OPCODE_SNACK_REQ = 0x10
    OPCODE_NOP_IN = 0x20
    OPCODE_SCSI_CMD_RES = 0x21
    OPCODE_TASK_MAN_RES = 0x22
    OPCODE_LOGIN_RES = 0x23
    OPCODE_TEXT_RES = 0x24
    OPCODE_DATA_IN = 0x25
    OPCODE_LOGOUT_RES = 0x26
    OPCODE_R2T = 0x31
    OPCODE_ASYNC_MSG = 0x32
    OPCODE_REJECT = 0x3F
    
    __OPCODE_MASK = 0x3F;
    __IMMEDIATE_MASK = 0x40;
    __FINAL_MASK = 0x80
    
    __opcodes = (OPCODE_NOP_OUT, OPCODE_SCSI_CMD_REQ, OPCODE_TSK_MAN_REQ, OPCODE_LOGIN_REQ,
                 OPCODE_TEXT_REQ, OPCODE_DATA_OUT, OPCODE_LOGOUT_REQ, OPCODE_SNACK_REQ,
                 OPCODE_NOP_IN, OPCODE_SCSI_CMD_RES, OPCODE_TASK_MAN_RES, OPCODE_LOGIN_RES,
                 OPCODE_TEXT_RES, OPCODE_DATA_IN, OPCODE_LOGOUT_RES, OPCODE_R2T,
                 OPCODE_ASYNC_MSG, OPCODE_REJECT)
    def __init__(self,  data):
        if not isinstance(data, (str, bytes, bytearray)):
            raise TypeError
        if len(data) < self.LENGTH:
            raise ValueError
        self.__data = data
        
    def __getitem__(self, key):
        if isinstance(key, slice):
            if key.start == None:
                start = 0
            else:
                start = key.start % self.LENGTH
            if key.stop == None:
                stop = self.LENGTH
            else:
                stop = key.stop % self.LENGTH
            return self.__data[start:stop]
        elif isinstance(key, int):
            if key >= self.LENGTH:
                raise IndexError
            return self.__data[key]
        else:
            raise TypeError
        
    def __setitem__(self, key, seq):
        if isinstance(key, slice):
            start = key.start % self.LENGTH
            stop = key.stop % self.LENGTH
            self.__data[start:stop] = seq
        elif isinstance(key, int):
            if key >= self.LENGTH:
                raise IndexError
            self.__data[key] = seq
        else:
            raise TypeError
    
    @property
    def Opcode(self):
        return ntoi(self.__data[0]) & self.__OPCODE_MASK
    
    @Opcode.setter
    def Opcode(self, ocode):
        if ocode not in self.__opcodes:
            raise ValueError
        self.__data[0] =  (self.__data[0] & ~self.__OPCODE_MASK) | ocode
    
    @property
    def Immediate(self):
        if ntoi(self.__data[0]) & self.__IMMEDIATE_MASK :
            return True
        else:
            return False
        
    @Immediate.setter
    def Immediate(self, i):
        if i:
            self.__data[0] |= self.__IMMEDIATE_MASK
        else:
            self.__data[0] &= ~self.__IMMEDIATE_MASK
    
    @property
    def Final(self):
        if ord(self.__data[1]) & self.__FINAL_MASK :
            return True
        else :
            return False
        
    @Final.setter
    def Final(self, f):
        if f:
            self.__data[1] |= self.__FINAL_MASK
        else:
            self.__data[1] &= ~self.__FINAL_MASK
        
    @property
    def TotalAHSLength(self):
        return ntoi(self.__data[4]) # in units of 4 byte words
    
    @TotalAHSLength.setter
    def TotalAHSLength(self, tashl):
        if tashl > 0xFF or tashl < 0:
            self.logger.warn("TotalAHSLength(%d) is invalid" % tashl)
        self.__data[4] = tashl
    
    @property
    def DataSegmentLength(self):
        return ntoi(self.__data[5:8])
    
    @DataSegmentLength.setter
    def DataSegmentLength(self, dsl):
        if dsl > 0xFFFFFF or dsl < 0:
            self.logger.warn("DataSegmentLength(%d) is bigger than 3 bytes" % dsl)
        self.__data[5:8] = iton(dsl, 3)
        
    @property
    def LUN(self):
        pass
    
    @property
    def InitiatorTaskTag(self):
        return ntoi(self.__data[16:20])
    
    @InitiatorTaskTag.setter
    def InitiatorTaskTag(self, itt):
        if itt > 0xFFFFFFFF or itt < 0:
            self.logger.warn("InitiatorTaskTag(%d) is bigger than 4 bytes" % itt)
        self.__data[16:20] = iton(itt, 4)

#AHS
#Byte/      0       |       1       |       2       |       3       |
#    /              |               |               |               |
#   |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
#   +---------------+---------------+---------------+---------------+
# 0| AHSLength                      | AHSType       | AHS-Specific |
#   +---------------+---------------+---------------+---------------+
# 4/ AHS-Specific                                                   /
# +/                                                                /
#   +---------------+---------------+---------------+---------------+
# x
class AHS:
    AHSTYPE_RESERVED_VALUE = 0
    AHSTYPE_EXTENDED_CDB_VALUE = 1
    AHSTYPE_EXPECTED_BIDIRECTIONAL_READ_DATA_LENGHT_VALUE = 2
    
    def __init__(self,  data):
        pass
    
    @property
    def AHSLength (self):
        pass
        
    @property
    def AHSType(self):
        pass
    
    
#Extended CDB AHS
#Byte/      0       |       1       |       2       |       3       |
#    /              |               |               |               |
#   |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
#   +---------------+---------------+---------------+---------------+
# 0| AHSLength (CDBLength-15)       | 0x01          | Reserved      |
#   +---------------+---------------+---------------+---------------+
# 4/ ExtendedCDB...+padding                                         /
# +/                                                                /
#   +---------------+---------------+---------------+---------------+
# x
class ExtendedCDB (AHS):
    pass
    
#Bidirectional Expected Read-Data Length AHS
#Byte/      0       |       1       |       2       |       3       |
#    /              |               |               |               |
#   |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
#   +---------------+---------------+---------------+---------------+
# 0| AHSLength (0x0005)             | 0x02          | Reserved      |
#   +---------------+---------------+---------------+---------------+
# 4| Expected Read-Data Length                                      |
#   +---------------+---------------+---------------+---------------+
# 8
class BidrectionalExpReadDataLength (AHS):
    pass
