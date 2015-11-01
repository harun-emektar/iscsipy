#!/usr/bin/python3

if __name__ == "login_pdu":
    from pdu_common import *
else:
    from .pdu_common import *

#Byte/     0        |       1       |       2       |       3       |
#    /              |               |               |               |
#  |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
#  +---------------+---------------+---------------+---------------+
# 0|.|1| 0x03       |T|C|.|.|CSG|NSG| Version-max   | Version-min   |
#  +---------------+---------------+---------------+---------------+
# 4|TotalAHSLength | DataSegmentLength                              |
#  +---------------+---------------+---------------+---------------+
# 8| ISID                                                           |
#  +                                +---------------+---------------+
#12|                                | TSIH                          |
#  +---------------+---------------+---------------+---------------+
#16| Initiator Task Tag                                             |
#  +---------------+---------------+---------------+---------------+
#20| CID                            | Reserved                      |
#  +---------------+---------------+---------------+---------------+
#24| CmdSN                                                          |
#  +---------------+---------------+---------------+---------------+
#28| ExpStatSN   or    Reserved                                     |
#  +---------------+---------------+---------------+---------------+
#32| Reserved                                                       |
#  +---------------+---------------+---------------+---------------+
#36| Reserved                                                       |
#  +---------------+---------------+---------------+---------------+
#40/ Reserved                                                       /
# +/                                                                /
#  +---------------+---------------+---------------+---------------+
#48/ DataSegment - Login Parameters in Text request Format          /
# +/                                                                /
#  +---------------+---------------+---------------+---------------+        
class LoginCmnPDU(PDU):
    # logger for Login pdu
    logger = logging.getLogger("Login PDU")
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)
    
    TRANSIT_MASK = 0x80
    CONTINUE_MASK = 0x40
    CURRENT_STAGE_MASK = 0x0C
    NEXT_STAGE_MASK = 0x03
    # stages
    SECURITY_NEG = 0
    LOGIN_OPERATIONAL_NEG = 1
    FULL_FEATURE_PHASE = 3
    
    __stages = (SECURITY_NEG, LOGIN_OPERATIONAL_NEG, FULL_FEATURE_PHASE)
        
    @property
    def Transit(self):
        if ntoi(self.bhs[1]) & self.TRANSIT_MASK:
            return True
        else:
            return False
    @Transit.setter
    def Transit(self, t):
        if t:
            self.bhs[1] |= self.TRANSIT_MASK
        else:
            self.bhs[1] &= ~self.TRANSIT_MASK
    
    @property
    def Continue(self):
        if ntoi(self.bhs[1]) & self.CONTINUE_MASK:
            return True
        else:
            return False
    @Continue.setter
    def Continue(self, c):
        if c:
            self.bhs[1] |= self.CONTINUE_MASK
        else:
            self.bhs[1] &= ~self.CONTINUE_MASK
    
    @property
    def CurrentStage(self):
        return (ntoi(self.bhs[1]) & self.CURRENT_STAGE_MASK) >> 2
    
    @CurrentStage.setter
    def CurrentStage(self, cs):
        if cs not in self.__stages:
            raise ValueError
        self.bhs[1] |= cs << 2
    
    @property
    def NextStage(self):
        return ntoi(self.bhs[1]) & self.NEXT_STAGE_MASK
    
    @NextStage.setter
    def NextStage(self, ns):
        if ns not in self.__stages:
            raise ValueError
        self.bhs[1] |= ns
    
    @property
    def VersionMax(self):
        return ntoi(self.bhs[2])
    
    @VersionMax.setter
    def VersionMax(self,vmax):
        if vmax > 0xFF or vmax < 0:
            self.logger.warn("VersionMax(%d) i bigger than 1 byte" % vmax)
        self.bhs[2] = vmax
    
    @property
    def ISID(self):
        return ISID(raw = self.bhs[8:14])
    
    @ISID.setter
    def ISID(self, isid):
        if not isinstance(isid, ISID):
            raise TypeError
        self.bhs[8:14] = isid.raw_data
    
    @property
    def TSIH(self):
        return ntoi(self.bhs[14:16])
    
    @TSIH.setter
    def TSIH(self, tsih):
        if tsih > 0xFFFF or tsih < 0:
            self.logger.warn("TSIH(%d) is bigger than 2 bytes" % tsih)
        self.bhs[14:16] = iton(tsih, 2)
        
#Byte/     0       |       1        |      2       |        3      |
#    /             |                |              |               |
#  |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
#  +---------------+---------------+---------------+---------------+
# 8| T |     A     |              B                |      C        |
#  +---------------+---------------+---------------+---------------+
#12|               D                |
#  +---------------+---------------+
#00b OUI-Format
#    A&B are a 22 bit OUI
#    (the I/G & U/L bits are omitted)
#    C&D 24 bit qualifier
#01b EN - Format (IANA Enterprise Number)
#    A - Reserved
#    B&C EN (IANA Enterprise Number)
#    D - Qualifier
#10b "Random"
#    A - Reserved
#    B&C Random
#    D - Qualifier
#11b A,B,C&D Reserved

class ISID():
    LENGTH = 6
    T_OUI = 0
    T_EN = 1
    T_RANDOM = 2
    T_RESERVED = 3
    
    __types = (T_OUI, T_EN, T_RANDOM, T_RESERVED)
    def __init__(self, raw = None, seq = None):# seq = (T, A, B, C, D)
        if raw == None:
            if len(seq) != 5:
                raise ValueError
            self.__raw = bytearray(self.LENGTH)
            self.T = seq[0]
            self.A = seq[1]
            self.B = seq[2]
            self.C = seq[3]
            self.D = seq[4]
        else:
            if not isinstance(raw, (str, bytes, bytearray)):
                raise TypeError
            if len(raw) != self.LENGTH:
                raise ValueError
            self.__raw = raw
            
    def __getitem__(self, key):
        self.__raw.__getitem__(key)
        
    def __eq__(self, other):
        if not isinstance(other, (str, bytes, bytearray, ISID)):
            raise TypeError
        if isinstance(other, (str, bytes, bytearray)) and len(other) != self.LENGTH:
            raise ValueError
        if other == self.__raw:
            return True
        return False
             
    def __ne__(self, other):
        return not self == other
            
    @property
    def T(self):
        return ntoi(self.__raw[0]) >> 6
    
    @T.setter
    def T(self, t):
        if t not in self.__types:
            raise ValueError
        self.__raw[0] |= t << 6

    @property
    def A(self):
        return ntoi(self.__raw[0]) & 0x3F
    
    @A.setter
    def A(self, a):
        self.__raw[0] |= a & 0x3F
        
    @property
    def B(self):
        return ntoi(self.__raw[1:3])
    
    @B.setter
    def B(self, b):
        self.__raw[1:3] = iton(b, 2)

    @property
    def C(self):
        return ntoi(self.__raw[3])
    
    @C.setter
    def C(self, c):
        self.__raw[3] = c

    @property
    def D(self):
        return ntoi(self.__raw[4:6])
    
    @B.setter
    def D(self, d):
        self.__raw[4:6] = iton(d, 2)

    @property
    def raw_data(self):
        return self.__raw


class LoginPDU(LoginCmnPDU):
    def __init__(self, data = None, header_digest = None, data_digest= None):
        super().__init__(data, header_digest, data_digest)
        if data == None:
            self.Opcode = BHS.OPCODE_LOGIN_REQ
            self.Immediate = True
        
    @property
    def VersionMin(self):
        return ntoi(self.bhs[3])
    
    @VersionMin.setter
    def VersionMin(self, vmin):
        if vmin > 0xFF or vmin < 0:
            self.logger.warn("VersionMin(%d) is bigger than 1 byte" % vmin)
        self.bhs[3] = vmin
            
    @property
    def CID(self):
        return ntoi(self.bhs[20:22])
    
    @CID.setter
    def CID(self, cid):
        if cid > 0xFFFF or cid < 0:
            self.logger.warn("CID(%d) is bigger than 2 bytes" % cid)
        n_cid = iton(cid, 2)
        self.bhs[20:22] = n_cid
    
    @property
    def CmdSN(self):
        return ntoi(self.bhs[24:28])
    
    @CmdSN.setter
    def CmdSN(self, cmdsn):
        if cmdsn > 0xFFFFFFFF or cmdsn < 0:
            self.logger.warn("cmdsn(%d) is bigger than 4 bytes" % cmdsn)
        n_cmdsn = iton(cmdsn, 4)
        self.bhs[24:28] = n_cmdsn
    
    @property
    def ExpStatSN(self):
        return ntoi(self.bhs[28:32])
    
    @ExpStatSN.setter
    def ExpStatSN(self, expstatsn):
        if expstatsn > 0xFFFFFFFF or expstatsn < 0:
            self.logger.warn("expstatsn(%d) is bigger than 4 bytes" % expstatsn)
        n_expstatsn = iton(expstatsn, 4)
        self.bhs[28:32] = n_expstatsn
        
    
#Byte/      0      |       1       |       2       |       3       |
#    /             |               |               |               |
#  |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
#  +---------------+---------------+---------------+---------------+
# 0|.|.| 0x23      |T|C|.|.|CSG|NSG| Version-max   | Version-active|
#  +---------------+---------------+---------------+---------------+
# 4|TotalAHSLength | DataSegmentLength                             |
#  +---------------+---------------+---------------+---------------+
# 8| ISID                                                          |
#  +                               +---------------+---------------+
#12|                               | TSIH                          |
#  +---------------+---------------+---------------+---------------+
#16| Initiator Task Tag                                            |
#  +---------------+---------------+---------------+---------------+
#20| Reserved                                                      |
#  +---------------+---------------+---------------+---------------+
#24| StatSN                                                        |
#  +---------------+---------------+---------------+---------------+
#28| ExpCmdSN                                                      |
#  +---------------+---------------+---------------+---------------+
#32| MaxCmdSN                                                      |
#  +---------------+---------------+---------------+---------------+
#36| Status-Class | Status-Detail | Reserved                       |
#  +---------------+---------------+---------------+---------------+
#40/ Reserved                                                      /
# +/                                                               /
#  +---------------+---------------+---------------+---------------+
#48/ DataSegment - Login Parameters in Text request Format         /
# +/                                                               /
#  +---------------+---------------+---------------+---------------+
class LoginRespPDU(LoginCmnPDU):
    STATUS_CLASS_SUCCESS = 0
    
    STATUS_CLASS_REDIR = 1
    STATUS_DETAIL_REDIR_TGT_MV_TMP = 1 # target moved temporarily
    STATUS_DETAIL_REDIR_TGT_MV_PERM = 1 # target moved permanently
    
    STATUS_CLASS_INIT_ERR = 2
    STATUS_DETAIL_INIT_MISC_ERR = 0 # miscellaneous initiator error
    STATUS_DETAIL_INIT_AUTHEN_FAIL = 1 # authentication failure
    STATUS_DETAIL_INIT_AUTHOR_FAIL = 2 # authorisation failure
    STATUS_DETAIL_INIT_NOT_FOUND = 3
    STATUS_DETAIL_INIT_TGT_REM = 4 # target removed
    STATUS_DETAIL_INIT_UNSUP_VER = 5 # unsupported version
    STATUS_DETAIL_INIT_MANY_CONN = 6 # too many connections
    STATUS_DETAIL_INIT_PARAM = 7 # missing parameter
    STATUS_DETAIL_INIT_CANT_INC_SESSIION = 8 # can't include in session
    STATUS_DETAIL_INIT_SESSION_UNSUP = 9 # session type not supported
    STATUS_DETAIL_INIT_SESSION_NOT_EXIST = 10 # session doesn't exists
    STATUS_DETAIL_INIT_INV_DURING_LOGIN = 11 # invalid during login
    
    STATUS_CLASS_TGT_ERR = 3
    STATIS_DETAIL_TGT_ERR = 0 # target error
    STATUS_DETAIL_TGT_SERV_NA = 1 # service unavailable
    STATUS_DETAIL_TGT_OUT_RESC = 2 # out of resources
    
    @property
    def VersionActive(self):
        return ord(self.bhs[3])
        
    @property
    def StatSN(self):
        return ntoi(self.bhs[24:28])
    
    @property
    def ExpCmdSN(self):
        return ntoi(self.bhs[28:32])
    
    @property
    def MaxCmdSN(self):
        return ntoi(self.bhs[32:36])
    
    @property
    def StatusClass(self):
        return ord(self.bhs[36:37])
    
    @property
    def StatusDetail(self):
        return ord(self.bhs[37:38])
