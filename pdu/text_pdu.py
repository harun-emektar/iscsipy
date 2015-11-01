#!/usr/bin/python3

if __name__ == "text_pdu":
    from pdu_common import *
else:
    from .pdu_common import *

#Byte/     0       |        1      |       2       |       3       |
#    /             |               |               |               |
#  |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
#  +---------------+---------------+---------------+---------------+
# 0|.|I| 0x04      |F|C| Reserved                                  |
#  +---------------+---------------+---------------+---------------+
# 4|TotalAHSLength | DataSegmentLength                             |
#  +---------------+---------------+---------------+---------------+
# 8| LUN or Reserved                                               |
#  +                                                               +
#12|                                                               |
#  +---------------+---------------+---------------+---------------+
#16| Initiator Task Tag                                            |
#  +---------------+---------------+---------------+---------------+
#20| Target Transfer Tag or 0xffffffff                             |
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
#  / DataSegment (Text)                                            /
# +/                                                               /
#  +---------------+---------------+---------------+---------------+
#  | Data-Digest (Optional)                                        |
#  +---------------+---------------+---------------+---------------+
class TextCmnPDU(PDU):
    # logger for Login pdu
    logger = logging.getLogger("Text PDU")
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)

    FINAL_MASK = 0x80
    CONTINUE_MASK = 0x40

    @property
    def Final(self):
        if ntoi(self.bhs[1]) & self.FINAL_MASK:
            return True
        else:
            return False

    @Final.setter
    def Final(self, f):
        if f:
            self.bhs[1] |= self.FINAL_MASK
        else:
            self.bhs[1] &= ~self.FINAL_MASK

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
    def TargetTransferTag(self):
        return ntoi(self.bhs[20:24])

    @TargetTransferTag.setter
    def TargetTransferTag(self, ttt):
        if ttt > 0xFFFFFFFF or ttt < 0:
            self.logger.warn("TargetTransferTag(%d) is bigger than 4 bytes" % ttt)
        self.bhs[20:24] = iton(ttt, 4)

class TextPDU(TextCmnPDU):
    def __init__(self, data = None, header_digest = None, data_digest= None):
        super().__init__(data, header_digest, data_digest)
        if data == None:
            data = bytearray(BHS.LENGTH)
            self.Opcode = BHS.OPCODE_TEXT_REQ

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

 
#Byte/      0      |        1      |       2       |       3       |
#    /             |               |               |               |
#  |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
#  +---------------+---------------+---------------+---------------+
# 0|.|.| 0x24      |F|C| Reserved                                  |
#  +---------------+---------------+---------------+---------------+
# 4|TotalAHSLength | DataSegmentLength                             |
#  +---------------+---------------+---------------+---------------+
# 8| LUN or Reserved                                               |
#  +                                                               +
#12|                                                               |
#  +---------------+---------------+---------------+---------------+
#16| Initiator Task Tag                                            |
#  +---------------+---------------+---------------+---------------+
#20| Target Transfer Tag or 0xffffffff                             |
#  +---------------+---------------+---------------+---------------+
#24| StatSN                                                        |
#  +---------------+---------------+---------------+---------------+
#28| ExpCmdSN                                                      |
#  +---------------+---------------+---------------+---------------+
#32| MaxCmdSN                                                      |
#  +---------------+---------------+---------------+---------------+
#36/ Reserved                                                      /
# +/                                                               /
#  +---------------+---------------+---------------+---------------+
#48| Header-Digest (Optional)                                      |
#  +---------------+---------------+---------------+---------------+
#  / DataSegment (Text)                                            /
# +/                                                               /
#  +---------------+---------------+---------------+---------------+
#  | Data-Digest (Optional)                                        |
#  +---------------+---------------+---------------+---------------+
class TextRespPDU(TextCmnPDU):
    @property
    def StatSN(self):
        return ntoi(self.bhs[24:28])
    
    @property
    def ExpCmdSN(self):
        return ntoi(self.bhs[28:32])
    
    @property
    def MaxCmdSN(self):
        return ntoi(self.bhs[32:36])
    
