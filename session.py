#!/usr/bin/python3

import pdu
import keys
import queue
import traceback
import _thread
import events


class Session():
    pass

class InitSession(Session):
    STATE_FREE = 0
    STATE_LOGGED_IN = 1
    STATE_FAILED = 0
    
    TYPE_DISCOVERY = 0
    TYPE_NORMAL = 1
    
    EVENT_SUCC_LOGIN = 0
    EVENT_SUCC_LOGOUT = 1
    
    __ISID = pdu.ISID(raw = None, seq = (2,0,0,0,1))# T=random A,B,C,D
    
    class Msg():
        ID_LOGIN = 0
        ID_SEND_TEXT = 1
        ID_LOGOUT = 3
        ID_EXIT = 4
        
        def __init__(self, id, data = None):
            self.id = id
            self.data = data
            
    class Cmd():
        def __init__(self, sent_pdu, cid, session):
            self.sent_pdu = sent_pdu
            self.cid = cid
            sent_pdu.CmdSN = session._InitSession__cmdsn
            if not sent_pdu.Immediate:
                session._InitSession__cmdsn += 1
            sent_pdu.InitiatorTaskTag = session._InitSession__itt
            session._InitSession__itt += 1
            session._InitSession__cmds[sent_pdu.InitiatorTaskTag] = self
    
    def __init__(self, init, portal, tgt_name = None):
        self.init = init # initiator
        self.__cid = 1
        self.__tsih = 0
        self.__isid = pdu.ISID(self.__ISID.raw_data[0:])
        self.__ISID.D += 1
        self.__cmdsn = 1
        self.__expcmdsn = 0
        self.__maxcmdsn = 1
        self.__itt = 1
        self.__portal = portal
        self.__init_event_listener = init.evt_lisener
        if tgt_name == None:
            self.__session_type = keys.SessionType("Discovery")
        else:
            self.__session_type = keys.SessionType("Normal")
        self.__init_name = keys.InitName(init.name)
        self.__keys = [self.__init_name, self.__session_type]
        self.__state = self.STATE_FREE
        self.__genq = queue.Queue(0)
        self.__pdu_listener = events.EventListener()
        self.__connections = {self.__cid:InitConn(portal, self.__pdu_listener, self, self.__cid)}
        self.__cid += 1
        self.__cmds = {} # itt:cmd list
        self.__sender_tid = _thread.start_new_thread(self.__PduGenThread, tuple())
        self.__recv_tid = _thread.start_new_thread(self.__PduProcessThread, tuple())    

    def __del__(self):
        # close connection
        del self.__connections
        # kill threads
        self.__genq.put_nowait(self.Msg(self.Msg.ID_EXIT))
        self.__pdu_listener.Signal(self.Msg(self.Msg.ID_EXIT))
        
    def __SendLogin(self, conn, cmd = None):
        # generate pdu
        if cmd == None:# first login pdu
            l_pdu = pdu.LoginPDU()
            if conn.auth_method.value == [keys.AuthMethod.NONE]:
                l_pdu.Transit = True
            else:
                l_pdu.Transit = False
            l_pdu.CurrentStage = pdu.LoginPDU.SECURITY_NEG
            l_pdu.NextStage = pdu.LoginPDU.LOGIN_OPERATIONAL_NEG
            l_pdu.AppendData(keys.GenPayload(self.__keys + conn.keys))
            cmd = self.Cmd(l_pdu, conn.cid, self)
            
        else: # this will continuation of logging in
            l_pdu = pdu.LoginPDU()
            if cmd.resp_pdu.Transit:
                l_pdu.CurrentStage = cmd.resp_pdu.NextStage
                l_pdu.NextStage = pdu.LoginPDU.FULL_FEATURE_PHASE                
            else:
                # send empty login
                l_pdu.CurrentStage = cmd.resp_pdu.CurrentStage
                l_pdu.NextStage = cmd.resp_pdu.NextStage  
            l_pdu.Transit = True
            l_pdu.InitiatorTaskTag = cmd.resp_pdu.InitiatorTaskTag
            l_pdu.CmdSN = self.__cmdsn
            
        if l_pdu.CurrentStage == pdu.LoginPDU.FULL_FEATURE_PHASE:
            # login complete
            conn.ProcessEvent(conn.EVENT_SUCC_LOGIN_FINAL) # update connection state
            self.ProcessEvent(self.EVENT_SUCC_LOGIN) # update session state
            self.__init_event_listener.Signal(events.Event(events.Event.ID_LOGGED_IN))# notify initiator
            del self.__cmds[cmd.resp_pdu.InitiatorTaskTag]
            return
        l_pdu.ISID = self.__isid
        l_pdu.CID = conn.cid
        
        # send pdu
        conn.SendPdu(l_pdu)
        
    def __ProcessLoginResp(self, resp_pdu):
        # check login resp pdu fields are valid
        if resp_pdu.StatusClass != pdu.LoginRespPDU.STATUS_CLASS_SUCCESS:
            self.logger.error("login response with status class(%d) detail(%d)" % (resp_pdu.StatusClass, resp_pdu.StatusDetail))
            return
        if resp_pdu.ISID != self.__isid:
            self.logger.error("login response received from wrong session")
            return
#        if resp_pdu.TSIH != 0:
#            self.logger.error("target didn't assign a valid tsih for this connection")
#            return
        if self.__tsih != 0 and self.__tsih != resp_pdu.TSIH:
            self.logger.error("target response with wrong tsid")
            return
        self.__tsih = resp_pdu.TSIH
        # find related cmd for itt in pdu
        try:
            cmd = self.__cmds[resp_pdu.InitiatorTaskTag]
            cmd.resp_pdu = resp_pdu
        except:
            self.logger.error("login response for wrong initiator task id")
            return
            
        conn = self.__connections[cmd.cid]
            
        conn.expstatsn = resp_pdu.StatSN
            
        # parse data segment create key value pairs
        offset = resp_pdu.PayloadOffset
        end = offset + resp_pdu.DataSegmentLength
        payload = resp_pdu[offset:end]
        keys_dic = keys.ParsePayload(payload)
            
        # send login pdu
        self.__SendLogin(conn, cmd)
        
    def __SendText(self, conn, text, cmd = None):
        if cmd == None:# first pdu, create cmd
            t_pdu = pdu.TextPDU()
            t_pdu.Final = True # according to text length 
            t_pdu.TargetTransferTag = 0xFFFFFFFF
            t_pdu.AppendData(text)
            cmd = self.Cmd(t_pdu, conn.cid, self)
        conn.SendPdu(t_pdu)
        
    def __ProcessTextResp(self, text_resp):
        if text_resp.Final and not text_resp.Continue:
            # find command
            try:
                cmd = self.__cmds[text_resp.InitiatorTaskTag]
                cmd.resp_pdu = text_resp
            except:
                self.logger.error("login response for wrong initiator task id")
                return
            offset = text_resp.PayloadOffset
            end = text_resp.PayloadOffset + text_resp.DataSegmentLength
            text = text_resp[offset:end]
            self.__init_event_listener.Signal(events.Event(events.Event.ID_TEXT_RESP, text))
        else:
            self.logger.warn("TODO: handle continues text pdu sequences")
            # TODO: handle continues sequences
            
    def __SendLogout(self, conn, cmd = None):
        if cmd == None:
            lo_pdu = pdu.LogoutPDU()
            lo_pdu.ReasonCode = lo_pdu.REASON_CLOSE_SESSION
            cmd = self.Cmd(lo_pdu, conn.cid, self)
        else:
            pass
        conn.SendPdu(lo_pdu)
        
    def __ProcessLogoutResp(self, logout_resp):
        try:
            cmd = self.__cmds[logout_resp.InitiatorTaskTag]
            cmd.resp_pdu = logout_resp
            if logout_resp.Response == pdu.LogoutRespPDU.RESPONSE_SUCC:
                #self.ProcessEvent(event)
                self.__init_event_listener.Signal(events.Event(events.Event.ID_LOGGED_OUT))
        except KeyError:
            self.logger.error("login response for wrong initiator task id")
            return
            
        
    def __ProcessPDU(self, recv_pdu):
        if recv_pdu.Opcode == pdu.BHS.OPCODE_LOGIN_RES:
            login_resp = pdu.LoginRespPDU(recv_pdu.raw_data)
            #print dump(data)
            
            self.__ProcessLoginResp(login_resp)
            recv_pdu = login_resp
            
        elif recv_pdu.Opcode == pdu.BHS.OPCODE_TEXT_RES:
            text_resp = pdu.TextRespPDU(recv_pdu.raw_data)
            self.__ProcessTextResp(text_resp)
            recv_pdu = text_resp
            
        elif recv_pdu.Opcode == pdu.BHS.OPCODE_LOGOUT_RES:
            lout_resp = pdu.LogoutRespPDU(recv_pdu.raw_data)
            self.__ProcessLogoutResp(lout_resp)
            recv_pdu = lout_resp
        else:
            self.logger.warn("not able to process pdu with opcode (%d)" % bhs.Opcode)
            
        if recv_pdu.MaxCmdSN >= recv_pdu.ExpCmdSN:
            if recv_pdu.MaxCmdSN > self.__maxcmdsn:
                self.__maxcmdsn = recv_pdu.MaxCmdSN
            if recv_pdu.ExpCmdSN > self.__expcmdsn:
                self.__expcmdsn = recv_pdu.ExpCmdSN
        else:
            self.logger.warn("expcmdsn and maxcmdsn values are ignored") 

        
    def __PduGenThread(self):
        try:
#            import rpdb2
#            rpdb2.settrace()
            while True:
                msg = self.__genq.get(True)
                # process msg here
                if msg.id == msg.ID_LOGIN:
                    # use first connection
                    # TODO: implement multi connection
                    self.__SendLogin(self.__connections[1])
                elif msg.id == msg.ID_SEND_TEXT:
                    self.__SendText(self.__connections[1], msg.data)
                elif msg.id == msg.ID_LOGOUT:
                    self.__SendLogout(self.__connections[1])
                elif msg.id == msg.ID_EXIT:
                    break
        except:
            traceback.print_exc()     
        print("session pdu generator thread exits")
    
    def __PduProcessThread(self):
        try:
#            import rpdb2
#            rpdb2.settrace()
            while True:
                event = self.__pdu_listener.Wait()
                if isinstance(event, self.Msg) and event.id == self.Msg.ID_EXIT:
                    break
                # process msg here
                self.__ProcessPDU(event.data)
                
        except:
            traceback.print_exc()
        print("sesssion pdu processor thread exits")     
        
    @property
    def state(self):
        return self.__state
    
    def Login(self):
        '''
        Perform login on given connection if not given then use first connection in session
        @param conn: Login to be performed
        '''
        if self.__state == self.STATE_FREE:
            self.__genq.put_nowait(self.Msg(self.Msg.ID_LOGIN))
        elif self.__state == self.STATE_LOGGED_IN:
            self.logger.warn("Session (%s) has already logged in" % self.__isid.raw_data)
        else:
            self.logger.warn("Session (%s) failed" % self.__isid.raw_data)
            
    def SendText(self, text):
        # check state whether it's been logged in
        if self.__state == self.STATE_LOGGED_IN:
            self.__genq.put_nowait(self.Msg(self.Msg.ID_SEND_TEXT, text))
        else:
            self.logger.error("Session (%s) hasn't logged in yet" % self.__isid.raw_data)
            
            
    def Logout(self):
        if self.__state == self.STATE_LOGGED_IN:
            self.__genq.put_nowait(self.Msg(self.Msg.ID_LOGOUT))
        else:
            self.logger.error("Session (%s) hasn't logged in yet" % self.__isid.raw_data)
        
    def ProcessEvent(self, event):
        if not isinstance(event, int):
            raise TypeError
        if self.__state == self.STATE_FREE:
            if event == self.EVENT_SUCC_LOGIN:
                self.__state = self.STATE_LOGGED_IN
        elif self.__state == self.STATE_LOGGED_IN:
            if event == self.EVENT_SUCC_LOGOUT:
                self.__state = self.STATE_FREE
        elif self.__state == self.STATE_FAILED:
            pass
        else:
            pass

class TgtSession(Session):
    STATE_FREE = 0
    STATE_ACTIVE = 1
    STATE_LOGGED_IN = 2
    STATE_FAILED = 3
    STATE_IN_CONTINUE = 4

#cyclic import from connection to session again    
from connection import InitConn, Conn
