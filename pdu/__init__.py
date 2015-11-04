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

if __name__ != "__main__":
    from .headers import *
    from .pdu_common import *
    from .login_pdu import *
    from .text_pdu import *
    from .logout_pdu import *
else:
    from headers import *
    from pdu_common import *
    from login_pdu import *
    from text_pdu import *
    from logout_pdu import *
# unit tests
if __name__ == "__main__":
    import unittest
    class TestBHS (unittest.TestCase):
        valid_BHS_data = '\x23\x87\x00\x00\x00\x00\x00\x00\x80\x58\x4c\x57\x24\x25\x00\x09\x00\x00\x00\x47\x00\x00\x00\x00\x00\x00\x00\x13\x00\x00\x00\x01\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        valid_BHS_data_opcode = 0x23
        valid_BHS_data_Immed = False
        valid_BHS_data_final = True
        valid_BHS_data_AHS_len = 0
        valid_BHS_data_len = 0
        valid_BHS_data_init_task_tag = 0x47
        
        def testInvalidParams(self):
            self.assertRaises(TypeError, BHS, 4)
            self.assertRaises(ValueError, BHS, "")
            self.assertRaises(ValueError, BHS, "a")
            self.assertRaises(ValueError, BHS, "".join(["a" for i in range(BHS.LENGTH - 1)]))
            
        def testValidParam(self):
            self.assertTrue(isinstance(BHS(self.valid_BHS_data), BHS))
            test_BHS = BHS(self.valid_BHS_data)
            self.assertEqual(test_BHS.Immediate, self.valid_BHS_data_Immed)
            self.assertEqual(test_BHS.Opcode, self.valid_BHS_data_opcode)
            self.assertEqual(test_BHS.Final, self.valid_BHS_data_final)
            self.assertEqual(test_BHS.TotalAHSLength, self.valid_BHS_data_AHS_len)
            self.assertEqual(test_BHS.DataSegmentLength, self.valid_BHS_data_len)
            self.assertEqual(test_BHS.InitiatorTaskTag, self.valid_BHS_data_init_task_tag)
            self.assertEqual(test_BHS[0], '\x23')
            self.assertEqual(test_BHS[8:12], '\x80\x58\x4c\x57')            
            self.assertEqual(test_BHS[-1], '\x00')
            
    class TestLoginPDU(unittest.TestCase):
        valid_LoginPDU_data = "\x43\x00\x00\x00\x00\x00\x00\x6e\x80\x04\x09\x00\x00\x00\x00\x00\x00\x04\x00\x01\x04\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x49\x6e\x69\x74\x69\x61\x74\x6f\x72\x4e\x61\x6d\x65\x3d\x69\x71\x6e\x2e\x32\x30\x30\x36\x2d\x31\x31\x2e\x32\x00\x54\x61\x72\x67\x65\x74\x4e\x61\x6d\x65\x3d\x69\x71\x6e\x2e\x32\x30\x30\x36\x2d\x31\x31\x2e\x31\x2e\x70\x79\x74\x68\x6f\x6e\x2e\x69\x73\x63\x73\x69\x2e\x74\x61\x72\x67\x65\x74\x2d\x31\x00\x53\x65\x73\x73\x69\x6f\x6e\x54\x79\x70\x65\x3d\x4e\x6f\x72\x6d\x61\x6c\x00\x41\x75\x74\x68\x4d\x65\x74\x68\x6f\x64\x3d\x43\x48\x41\x50\x00\x00\x00"
        valid_LoginPDU_data_opcode = 0x03
        valid_LoginPDU_data_immed = True
        valid_LoginPDU_data_transit = False
        valid_LoginPDU_data_continue = False
        valid_LoginPDU_data_current_stage = 0
        valid_LoginPDU_data_next_stage = 0
        valid_LoginPDU_data_version_max = 0
        valid_LoginPDU_data_version_min = 0
        valid_LoginPDU_data_total_ahs_len = 0
        valid_LoginPDU_data_data_len = 0x6e
        valid_LoginPDU_data_isid =  ISID(raw = "\x80\x04\x09\x00\x00\x00")
        valid_LoginPDU_data_tsih = 0
        valid_LoginPDU_data_init_task_tag = 0x40001
        valid_LoginPDU_data_cid = 0x409
        valid_LoginPDU_data_cmdsn = 0
        valid_LoginPDU_data_expstatsn = 0
        valid_LoginPDU_data_payload_index = 48
        
        def testValidParams(self):
            self.assertTrue(isinstance(LoginPDU(self.valid_LoginPDU_data), LoginPDU))
            test_LoginPDU = LoginPDU(self.valid_LoginPDU_data)
            self.assertEqual(test_LoginPDU.Opcode, self.valid_LoginPDU_data_opcode)
            self.assertEqual(test_LoginPDU.Immediate, self.valid_LoginPDU_data_immed)
            self.assertEqual(test_LoginPDU.Transit, self.valid_LoginPDU_data_transit)
            self.assertEqual(test_LoginPDU.Continue, self.valid_LoginPDU_data_continue)
            self.assertEqual(test_LoginPDU.CurrentStage, self.valid_LoginPDU_data_current_stage)
            self.assertEqual(test_LoginPDU.NextStage, self.valid_LoginPDU_data_next_stage)
            self.assertEqual(test_LoginPDU.VersionMax, self.valid_LoginPDU_data_version_max)
            self.assertEqual(test_LoginPDU.VersionMin, self.valid_LoginPDU_data_version_min)
            self.assertEqual(test_LoginPDU.TotalAHSLength, self.valid_LoginPDU_data_total_ahs_len)
            self.assertEqual(test_LoginPDU.DataSegmentLength, self.valid_LoginPDU_data_data_len)
            self.assertEqual(test_LoginPDU.ISID, self.valid_LoginPDU_data_isid)
            self.assertEqual(test_LoginPDU.TSIH, self.valid_LoginPDU_data_tsih)
            self.assertEqual(test_LoginPDU.InitiatorTaskTag, self.valid_LoginPDU_data_init_task_tag)
            self.assertEqual(test_LoginPDU.CID, self.valid_LoginPDU_data_cid)
            self.assertEqual(test_LoginPDU.CmdSN, self.valid_LoginPDU_data_cmdsn)
            self.assertEqual(test_LoginPDU.ExpStatSN, self.valid_LoginPDU_data_expstatsn)
            self.assertEqual(test_LoginPDU.PayloadOffset, self.valid_LoginPDU_data_payload_index)
            
        def testAssignment(self):
            test_LoginPDU = LoginPDU()
#            for b in test_LoginPDU:
#                self.assertEqual(b, 0)
            test_LoginPDU.Opcode = BHS.OPCODE_LOGOUT_REQ
            self.assertEqual(test_LoginPDU.Opcode, BHS.OPCODE_LOGOUT_REQ)
#            self.assertFalse(test_LoginPDU.Immediate)
            test_LoginPDU.Immediate = True
            self.assertTrue(test_LoginPDU.Immediate)
            self.assertFalse(test_LoginPDU.Transit)
            test_LoginPDU.Transit = True
            self.assertTrue(test_LoginPDU.Transit)
            self.assertFalse(test_LoginPDU.Continue)
            test_LoginPDU.Continue = True
            self.assertTrue(test_LoginPDU.Continue)
            self.assertEqual(test_LoginPDU.CurrentStage, 0)
            test_LoginPDU.CurrentStage = LoginPDU.LOGIN_OPERATIONAL_NEG
            self.assertEqual(test_LoginPDU.CurrentStage, LoginPDU.LOGIN_OPERATIONAL_NEG)
            self.assertEqual(test_LoginPDU.NextStage, 0)
            test_LoginPDU.NextStage = LoginPDU.FULL_FEATURE_PHASE
            self.assertEqual(test_LoginPDU.NextStage, LoginPDU.FULL_FEATURE_PHASE)
            self.assertEqual(test_LoginPDU.VersionMax, 0)
            test_LoginPDU.VersionMax = 11
            self.assertEqual(test_LoginPDU.VersionMax, 11)
            self.assertEqual(test_LoginPDU.VersionMin, 0)
            test_LoginPDU.VersionMin = 13
            self.assertEqual(test_LoginPDU.VersionMin, 13)
            self.assertEqual(test_LoginPDU.TotalAHSLength, 0)
            test_LoginPDU.TotalAHSLength = 254
            self.assertEqual(test_LoginPDU.TotalAHSLength, 254)
            self.assertEqual(test_LoginPDU.DataSegmentLength, 0)
            test_LoginPDU.DataSegmentLength = 0xFFFF
            self.assertEqual(test_LoginPDU.DataSegmentLength, 0xFFFF)
            test_LoginPDU.DataSegmentLength = 0x10FFFFFF
            self.assertEqual(test_LoginPDU.DataSegmentLength, 0xFFFFFF)
#            self.assertEqual(test_LoginPDU.TSIH, 0)
            test_LoginPDU.TSIH = 11
            self.assertEqual(test_LoginPDU.TSIH, 11)
            test_LoginPDU.TSIH = 0xFF1234
            self.assertEqual(test_LoginPDU.TSIH, 0x1234)
            self.assertEqual(test_LoginPDU.InitiatorTaskTag, 0)
            test_LoginPDU.InitiatorTaskTag = 0xFF12345678
            self.assertEqual(test_LoginPDU.InitiatorTaskTag, 0x12345678)
            test_LoginPDU.InitiatorTaskTag = 12
            self.assertEqual(test_LoginPDU.InitiatorTaskTag, 12)
            self.assertEqual(test_LoginPDU.CID, 0)
            test_LoginPDU.CID = 10
            self.assertEqual(test_LoginPDU.CID, 10)
            test_LoginPDU.CID = 0xFF1234
            self.assertEqual(test_LoginPDU.CID, 0x1234)
            self.assertEqual(test_LoginPDU.CmdSN, 0)
            test_LoginPDU.CmdSN = 11
            self.assertEqual(test_LoginPDU.CmdSN, 11)
            test_LoginPDU.CmdSN = 0xFF12345678
            self.assertEqual(test_LoginPDU.CmdSN, 0x12345678)
            self.assertEqual(test_LoginPDU.ExpStatSN, 0)
            test_LoginPDU.ExpStatSN = 11
            self.assertEqual(test_LoginPDU.ExpStatSN, 11)
            test_LoginPDU.ExpStatSN = 0xFF12345678
            self.assertEqual(test_LoginPDU.ExpStatSN, 0x12345678)
            
            
    class TestLoginRespPDU(unittest.TestCase):
        valid_LoginRespPDU_data = "\x23\x00\x00\x00\x00\x00\x00\x35\x80\x04\x09\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x54\x61\x72\x67\x65\x74\x50\x6f\x72\x74\x61\x6c\x47\x72\x6f\x75\x70\x54\x61\x67\x3d\x31\x00\x54\x61\x72\x67\x65\x74\x41\x6c\x69\x61\x73\x3d\x0a\x00\x41\x75\x74\x68\x4d\x65\x74\x68\x6f\x64\x3d\x43\x48\x41\x50\x00\x00\x00\x00"
        valid_LoginRespPDU_data_opcode = 0x23
        valid_LoginRespPDU_data_immed = False
        valid_LoginRespPDU_data_transit = False
        valid_LoginRespPDU_data_continue = False
        valid_LoginRespPDU_data_current_stage = 0
        valid_LoginRespPDU_data_next_stage = 0
        valid_LoginRespPDU_data_version_max = 0
        valid_LoginRespPDU_data_version_act = 0
        valid_LoginRespPDU_data_total_ahs_len = 0
        valid_LoginRespPDU_data_data_len = 0x35
        valid_LoginRespPDU_data_isid =  ISID(raw = "\x80\x04\x09\x00\x00\x00")
        valid_LoginRespPDU_data_tsih = 0
        valid_LoginRespPDU_data_init_task_tag = 0x40001
        valid_LoginRespPDU_data_statsn = 0
        valid_LoginRespPDU_data_expcmdsn = 0
        valid_LoginRespPDU_data_maxcmdsn = 1
        valid_LoginRespPDU_data_stat_class = 0
        valid_LoginRespPDU_data_stat_detail = 0
        valid_LoginRespPDU_data_payload_index = 48
        
        def testValidParams(self):
            self.assertTrue(isinstance(LoginRespPDU(self.valid_LoginRespPDU_data), LoginRespPDU))
            test_LoginRespPDU = LoginRespPDU(self.valid_LoginRespPDU_data)
            self.assertEqual(test_LoginRespPDU.Opcode, self.valid_LoginRespPDU_data_opcode)
            self.assertEqual(test_LoginRespPDU.Immediate, self.valid_LoginRespPDU_data_immed)
            self.assertEqual(test_LoginRespPDU.Transit, self.valid_LoginRespPDU_data_transit)
            self.assertEqual(test_LoginRespPDU.Continue, self.valid_LoginRespPDU_data_continue)
            self.assertEqual(test_LoginRespPDU.CurrentStage, self.valid_LoginRespPDU_data_current_stage)
            self.assertEqual(test_LoginRespPDU.NextStage, self.valid_LoginRespPDU_data_next_stage)
            self.assertEqual(test_LoginRespPDU.VersionMax, self.valid_LoginRespPDU_data_version_max)
            self.assertEqual(test_LoginRespPDU.VersionActive, self.valid_LoginRespPDU_data_version_act)
            self.assertEqual(test_LoginRespPDU.TotalAHSLength, self.valid_LoginRespPDU_data_total_ahs_len)
            self.assertEqual(test_LoginRespPDU.DataSegmentLength, self.valid_LoginRespPDU_data_data_len)
            self.assertEqual(test_LoginRespPDU.ISID, self.valid_LoginRespPDU_data_isid)
            self.assertEqual(test_LoginRespPDU.TSIH, self.valid_LoginRespPDU_data_tsih)
            self.assertEqual(test_LoginRespPDU.InitiatorTaskTag, self.valid_LoginRespPDU_data_init_task_tag)
            self.assertEqual(test_LoginRespPDU.StatSN, self.valid_LoginRespPDU_data_statsn)
            self.assertEqual(test_LoginRespPDU.ExpCmdSN, self.valid_LoginRespPDU_data_expcmdsn)
            self.assertEqual(test_LoginRespPDU.MaxCmdSN, self.valid_LoginRespPDU_data_maxcmdsn)
            self.assertEqual(test_LoginRespPDU.StatusClass, self.valid_LoginRespPDU_data_stat_class)
            self.assertEqual(test_LoginRespPDU.StatusDetail, self.valid_LoginRespPDU_data_stat_detail)
            self.assertEqual(test_LoginRespPDU.PayloadOffset, self.valid_LoginRespPDU_data_payload_index)

    unittest.main()