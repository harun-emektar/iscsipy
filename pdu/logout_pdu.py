#!/usr/bin/python3

if __name__ == "text_pdu":
    from pdu_common import *
else:
    from .pdu_common import *


#Byte/     0       |       1       |       2       |       3       |
#    /             |               |               |               |
#  |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
#  +---------------+---------------+---------------+---------------+
# 0|.|I| 0x06      |1| Reason Code | Reserved                      |
#  +---------------+---------------+---------------+---------------+
# 4|TotalAHSLength | DataSegmentLength                             |
#  +---------------------------------------------------------------+
# 8/ Reserved                                                      /
# +/                                                               /
#  +---------------+---------------+---------------+---------------+
#16| Initiator Task Tag                                            |
#  +---------------+---------------+---------------+---------------+
#20| CID or Reserved               | Reserved                      |
#  +---------------+---------------+---------------+---------------+
#24| CmdSN                                                         |
#  +---------------+---------------+---------------+---------------+
#28| ExpStatSN                                                     |
#  +---------------+---------------+---------------+---------------+
#32/ Reserved                                                      /
# +/                                                               /
#  +---------------+---------------+---------------+---------------+
#48| Header-Digest (Optional)                                      |
#  +---------------+---------------+---------------+---------------+
class LogoutPDU(PDU):
    # logger for Login pdu
    logger = logging.getLogger("Logout PDU")
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)
    
    REASON_CLOSE_SESSION = 0
    REASON_CLOSE_CONN = 1
    REASON_CONN_RECOVERY = 2
    
    __reasons = (REASON_CLOSE_CONN, REASON_CLOSE_SESSION, REASON_CONN_RECOVERY)

    def __init__(self, data = None, header_digest = None, data_digest= None):
        super().__init__(data, header_digest, data_digest)
        if data == None:
            self.Opcode = BHS.OPCODE_LOGOUT_REQ
            self[1] = 0x80

    @property
    def ReasonCode(self):
        return ntoi(self.bhs[1]) & 0x7F
    
    @ReasonCode.setter
    def ReasonCode(self, rcode):
        if rcode not in self.__reasons:
            raise ValueError
        self.bhs[1] |= rcode
    
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
# 0|.|.| 0x26      |1| Reserved    | Response      | Reserved      |
#  +---------------+---------------+---------------+---------------+
# 4|TotalAHSLength | DataSegmentLength                             |
#  +---------------------------------------------------------------+
# 8/ Reserved                                                      /
# +/                                                               /
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
#36| Reserved                                                      |
#  +---------------------------------------------------------------+
#40| Time2Wait                     | Time2Retain                   |
#  +---------------+---------------+---------------+---------------+
#44| Reserved                                                      |
#  +---------------+---------------+---------------+---------------+
#48| Header-Digest (Optional)                                      |
#  +---------------+---------------+---------------+---------------+

class LogoutRespPDU(PDU):
    RESPONSE_SUCC = 0
    RESPONSE_CID_NOT_FOUND = 1
    RESPONSE_RECOVERY_NOT_SUPPORTED = 2
    RESPONSE_FAIL = 3
    
    __responses = (RESPONSE_SUCC, RESPONSE_CID_NOT_FOUND, RESPONSE_RECOVERY_NOT_SUPPORTED, RESPONSE_FAIL)
    @property 
    def Response(self):
        return ntoi(self.bhs[2])
    
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
    def Time2Wait(self):
        return ntoi(self.bhs[40:42])
    
    @property 
    def Time2Retain(self):
        return ntoi(self.bhs[42:44])
