#!/usr/bin/python3
if __name__ == "pdu_common":
    from  headers import *
else:
    from .headers import *
#Byte/     0       |        1      |       2       |       3       |
#    /             |               |               |               |
#  |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
#  +---------------+---------------+---------------+---------------+
# 0/ Basic Header Segment (BHS)                                    /
# +/                                                               /
#  +---------------+---------------+---------------+---------------+
#48/ Additional Header Segment 1 (AHS) (optional)                  /
# +/                                                               /
#  +---------------+---------------+---------------+---------------+
#  / Additional Header Segment 2 (AHS) (optional)                  /
# +/                                                               /
#  +---------------+---------------+---------------+---------------+
#----
#  +---------------+---------------+---------------+---------------+
#  / Additional Header Segment n (AHS) (optional)                  /
# +/                                                               /
#  +---------------+---------------+---------------+---------------+
#----
#  +---------------+---------------+---------------+---------------+
# k/ Header-Digest (optional)                                      /
# +/                                                               /
#  +---------------+---------------+---------------+---------------+
# l/ Data Segment(optional)                                        /
# +/                                                               /
#  +---------------+---------------+---------------+---------------+
# m/ Data-Digest (optional)                                        /
# +/                                                               /
#  +---------------+---------------+---------------+---------------+

class PDU(object):
    def __init__(self,  data, header_digest = False, data_digest = False):
        if data == None:
            data = bytearray(BHS.LENGTH)
        self.__data = data
        self.__h_digest = header_digest
        self.__d_digest = data_digest
        # construct BHS
        self.bhs = BHS(data)
        # construct AHS list according to BHS
        self.__payload = []
        
    def __getitem__(self, key):
        return self.__data.__getitem__(key)
    
    def __setitem__(self, key, value):
        self.__data.__setitem__(key, value)
        
    @property
    def PayloadOffset(self):
        return BHS.LENGTH + self.bhs.TotalAHSLength # dont forget header digest
    
    @property
    def Immediate(self):
        return self.bhs.Immediate
    
    @Immediate.setter
    def Immediate(self, i):
        self.bhs.Immediate = i
    
    @property
    def Opcode(self):
        return self.bhs.Opcode
    
    @Opcode.setter
    def Opcode(self, ocode):
        self.bhs.Opcode = ocode
    
    @property
    def Final(self):
        return self.bhs.Final
    
    @Final.setter
    def Final(self, f):
        self.bhs.Final = f
    
    @property
    def TotalAHSLength(self):
        return self.bhs.TotalAHSLength
    
    @TotalAHSLength.setter
    def TotalAHSLength(self, tahsl):
        self.bhs.TotalAHSLength = tahsl
    
    @property
    def DataSegmentLength(self):
        return self.bhs.DataSegmentLength
    
    @DataSegmentLength.setter
    def DataSegmentLength(self, dsl):
        self.bhs.DataSegmentLength = dsl
    
    @property
    def LUN(self):
        return self.bhs.LUN
    @LUN.setter
    def LUN(self, lun):
        self.bhs.LUN = lun
    
    @property
    def InitiatorTaskTag(self):
        return self.bhs.InitiatorTaskTag
    
    @InitiatorTaskTag.setter
    def InitiatorTaskTag(self, itt):
        self.bhs.InitiatorTaskTag = itt
        
    def AppendData(self, data):
        self.__payload += [data]
        self.DataSegmentLength += len(data)
        
    @property
    def raw_data(self):
        #update DataSegmentLength
        data_len = 0
        for d in self.__payload:
            data_len += len(d)
        if data_len % 4 != 0:
            self.__payload += [bytearray(4 - data_len % 4)]
        #self.DataSegmentLength = data_len
        retval = self.__data
        for p in self.__payload:
            if isinstance(p, str):
                retval += p.encode("utf8")
            else:
                retval += p
        return retval
