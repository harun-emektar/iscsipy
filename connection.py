#!/usr/bin/python3

import logging
import socket
import _thread
import queue
import pdu
import traceback
from utils import dump
import keys
import events
from session import InitSession

class Conn():
    STATE_FREE = 1
    STATE_XPT_WAIT = 2
    STATE_XPT_UP = 3
    STATE_IN_LOGIN = 4
    STATE_LOGGED_IN = 5
    STATE_IN_LOGOUT = 6
    STATE_LOGOUT_REQUEST = 7
    STATE_CLEANUP_WAIT = 8
    
    def __init__(self):
        pass

class InitConn(Conn):
    # logger for initiator connection
    logger = logging.getLogger("Init Con")
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)
    
    # default port number
    DEFAULT_PORT = 3260 # for iscsi
    
    EVENT_CLOSE_SESSION = 1 # logout reesp on another connection for "close session" T18 T13 T8 T7 T2
    EVENT_UNSUCC_LOGOUT_RESP = 2 # logout response with failure nonzero status T17
    EVENT_XPT_TOUT = 3 # transport timeout T17 T7
    EVENT_XPT_DISCONN = 4 # transport reset or disconnect T17 T16 T15 T7
    EVENT_ASYNC_DROP_CONN = 5 # async pdu with "drop connection" for this cid T16 T15 T17
    EVENT_ASYNC_DROP_ALL = 6 # aysnc pdu with "drop all connections" T16 T15 T17
    EVENT_ASYNC_LOGOUT = 7 # async pdu with "request logout" T14 T11 T12
    EVENT_SUCC_LOGOUT_RESP = 8 # successful logout resp is received T13
    EVENT_REQ_LOUT = 9 # start logout T9 T10
    EVENT_UNSUCC_LOGIN_FINAL = 10 # nonzero status for login respond is received T7
    EVENT_SUCC_LOGIN_FINAL = 11 # successful final login respond is received T5
    EVENT_CONN_ESTAB = 12 # connection established T4
    EVENT_UNSUCC_CONN_ESTAB = 13 # unsuccessful connection establishment T2
    EVENT_CONN_REQ = 14 # connection is requested T1
    
    class Msg():
        ID_PDU = 0
        ID_EXIT = 1
        def __init__(self, id, data = None):
            self.id = id
            self.data = data
    
    def __init__(self, portal, event_listener, session, cid):
        '''
        Initiator connection constructor
        @param portal: ip or domain name of port
        @param event_listener: events will be sent to that listener
        '''
        super().__init__()
        self.__state = self.STATE_FREE
        
        pindex = portal.find(":")
        if pindex == -1:
            portal += ":" + str(self.DEFAULT_PORT)
            pindex = portal.find(":")
        self.__soc = socket.create_connection((portal[:pindex], portal[pindex + 1:]))
        self.__cid = cid
        self.__expstatsn = -1
        self.__session = session
        self.__state = self.STATE_IN_LOGIN
        self.__auth = keys.AuthMethod("None")
        self.__keys = [self.__auth]
        self.__cs = pdu.LoginPDU.SECURITY_NEG
        self.__ns = pdu.LoginPDU.LOGIN_OPERATIONAL_NEG
        
        self.__listener = event_listener
        self.__senderq = queue.Queue(0)
        self.__sender_tid = _thread.start_new_thread(self.__SenderThread, tuple())
        self.__recv_tid = _thread.start_new_thread(self.__RecvThread, tuple())    
        
    def __del__(self):
        # close socket
        self.__soc.close()
        self.__senderq.put_nowait(self.Msg(self.Msg.ID_EXIT))
        
        # kill threads
        pass
            
    def __ProcessPDU(self, recv_pdu):
        print("PDU (0x%x) received" % recv_pdu.Opcode)
        self.__listener.Signal(events.Event(events.Event.ID_PDU_RECV, recv_pdu))
    
    def __SenderThread(self):
        try:
            while True:
                msg = self.__senderq.get(True)
                if msg.id == self.Msg.ID_PDU:
                    out_pdu = msg.data
                    if self.__expstatsn != -1:
                        out_pdu.ExpStatSN = self.__expstatsn
                        self.__expstatsn += 1
                        self.__expstatsn &= 0xFFFFFFFF
                    self.__soc.send(out_pdu.raw_data)
                else:
                    break
        except:
            traceback.print_exc()    
        print("connection sender thread exits") 
    
    def __RecvThread(self):
        try:
            read_len = pdu.BHS.LENGTH
            max_read_len = pdu.BHS.LENGTH
            data = b""
            bhs = None
            while True:
                #print ("read_len %d, max_read_len %d, len(data) %d" % (read_len, max_read_len, len(data)))
                data += self.__soc.recv(read_len)
                if len(data) < max_read_len:
                    # read more
                    read_len = max_read_len - len(data)
                    continue
                if bhs == None:
                    bhs = pdu.BHS(data)
                    max_read_len = pdu.BHS.LENGTH + bhs.TotalAHSLength + bhs.DataSegmentLength
                    if max_read_len % 4 != 0:
                        max_read_len += 4 - max_read_len % 4
                    read_len = max_read_len - read_len
                    
                if len(data) != max_read_len:
                    continue
                
                recv_pdu = pdu.PDU(data)
                self.__ProcessPDU(recv_pdu)
                
                bhs = None
                read_len = pdu.BHS.LENGTH
                max_read_len = pdu.BHS.LENGTH
                data = b""
        except:
            traceback.print_exc()
        print("connection receiver thread exits")
            
    @property
    def auth_method(self):
        return self.__auth

    @property
    def cid(self):
        return self.__cid
            
    @property
    def state(self):
        return self.__state
    
    @property
    def keys(self):
        return self.__keys
    
    @property
    def expstatsn(self):
        return self.__expstatsn
    
    @expstatsn.setter
    def expstatsn(self, expstatsn):
        if self.__expstatsn == -1:
            self.__expstatsn = expstatsn
        
    def ProcessEvent(self, event):
        if not isinstance(event, int):
            raise TypeError
        if self.__state == self.STATE_FREE:
            if event == self.EVENT_CONN_REQ:# T1
                self.__state = self.XPT_WAIT
            else:
                # invalid event
                self.logger.warn("invalid event (%d) received while in state (%d)" % (event, self.__state))
        elif self.__state == self.STATE_XPT_WAIT: 
            if event == self.EVENT_UNSUCC_CONN_ESTAB or event == self.EVENT_CLOSE_SESSION: # T2
                self.__state = self.FREE
            elif event == self.EVENT_CONN_ESTAB: # T4
                self.__state = self.STATE_IN_LOGIN
            else:
                self.logger.warn("invalid event (%d) received while in state (%d)" % (event, self.__state))
        elif self.__state == self.STATE_IN_LOGIN: 
            # T7
            if event == self.EVENT_CLOSE_SESSION or event == self.EVENT_XPT_TOUT or event == self.EVENT_XPT_DISCONN:
                self.__state = self.STATE_FREE
            elif event == self.EVENT_SUCC_LOGIN_FINAL: # T5
                self.__state = self.STATE_LOGGED_IN
            else:
                self.logger.warn("invalid event (%d) received while in state (%d)" % (event, self.__state))
        elif self.__state == self.STATE_LOGGED_IN:
            if event == self.EVENT_CLOSE_SESSION: # T8
                self.__state = self.STATE_FREE
            elif event == self.EVENT_ASYNC_LOGOUT: # T11
                self.__state = self.STATE_LOGOUT_REQUEST
            # T15
            elif event == self.EVENT_XPT_DISCONN or event == self.EVENT_ASYNC_DROP_CONN or event == self.EVENT_ASYNC_DROP_ALL:
                self.__state = self.STATE_CLEANUP_WAIT
            elif event == self.EVENT_REQ_LOUT: # T9
                self.__state = self.STATE_IN_LOGOUT
            else:
                self.logger.warn("invalid event (%d) received while in state (%d)" % (event, self.__state))
        elif self.__state == self.STATE_IN_LOGOUT:
            # T17
            if event == self.EVENT_UNSUCC_LOGOUT_RESP or event == self.EVENT_XPT_TOUT or \
            event == self.EVENT_XPT_DISCONN or event == self.EVENT_ASYNC_DROP_CONN or \
            event == self.EVENT_ASYNC_DROP_ALL:
                self.__state = self.STATE_CLEANUP_WAIT
            elif event == self.EVENT_ASYNC_LOGOUT: # T14
                pass
            else:
                self.logger.warn("invalid event (%d) received while in state (%d)" % (event, self.__state))
        elif self.__state == self.STATE_LOGOUT_REQUEST:
            if event == self.EVENT_REQ_LOUT: # T10
                self.__state = self.STATE_IN_LOGOUT
            elif event == self.EVENT_XPT_DISCONN or event == self.EVENT_ASYNC_DROP_CONN or \
            event == self.EVENT_ASYNC_DROP_ALL: # T16
                self.__state = self.STATE_CLEANUP_WAIT
            elif event == self.EVENT_ASYNC_LOGOUT: # T12
                pass
            else:
                self.logger.warn("invalid event (%d) received while in state (%d)" % (event, self.__state))
        elif self.__state == self.STATE_CLEANUP_WAIT:
            pass
        else:
            pass
        
    def SendPdu(self, pdu):
        self.__senderq.put_nowait(self.Msg(self.Msg.ID_PDU, pdu))
        

class TargetConn(Conn):
    pass

#if __name__ == "__main__":
#    import unittest
#    class TestInitConn(unittest.TestCase):
#        def testStateTransitions(self):
#            con = InitConn()
#            self.assertRaises(TypeError, con.ProcessEvent, "event")
#            self.assertEqual(con.State, con.STATE_FREE)
#            con.ProcessEvent(con.EVENT_CLOSE_SESSION)
#            self.assertEqual(con.State, con.STATE_FREE)
#            con.ProcessEvent(con.EVENT_CONN_REQ)
#            self.assertEqual(con.State, con.STATE_XPT_WAIT)
#            pass
#    unittest.main()
#    
if __name__ == "__main__":
    InitConn("localhost:3260")
    import time
    time.sleep(3)
    