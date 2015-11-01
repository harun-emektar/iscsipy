#!/usr/bin/python3

from session import InitSession
import logging
import events
import keys
from utils import ntoi

class TargetAddrInfo():
    def __init__(self, addr, tpgt):
        self.__addr = str(addr)
        self.__tpgt = ntoi(tpgt)

    @property
    def addr(self):
        return self.__addr
    
    @property
    def tpgt(self):
        return self.__tpgt


class TargetInfo():
    def __init__(self, name, addr_list):
        self.__addr_list = addr_list
        self.__name = name
        
    @property
    def name(self):
        return self.__name
    
    @property
    def addr_list(self):
        return self.__addr_list

class Initiator():
    # logger for initiator
    logger = logging.getLogger("Initiator")
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)
    
    # return values
    RET_SUCCESS = 0
    RET_NO_CONN = 1
    RET_LOGIN_FAIL = 2
    RET_FAIL = 3
    
    def __init__(self, name):
        '''
        Initiator constructor
        @param name: initiator name either iqn or 

        '''
        if not isinstance(name, str):
            raise TypeError
        self.__name = name
        self.__sessions = []
        self.__event_listener = events.EventListener()
        
    @property
    def name(self):
        return self.__name
    
    @property
    def evt_lisener(self):
        return self.__event_listener
            
    def Connect(self, portal):
        '''
        Connect to a portal
        @param portal: ip or domain name of portal
        '''
        self.__sessions += [InitSession(self, portal)]
        
    def Login(self, portal = None, tgt_name = None):
        '''
        Perform a login on given portal or existing connection
        @param portal: to be logging in it it's noe use first established connection
        @param tgt_name: target to be accessed if it's none, logging in for discovery
        '''
        if portal == None and tgt_name == None:
            if len(self.__sessions) == 0:
                self.logger.warn("No connection to perform login")
            else:
                self.__sessions[0].Login()
                evnt = self.__event_listener.Wait()
                if evnt.id == evnt.ID_LOGGED_IN:
                    return self.RET_SUCCESS
                else:
                    return self.RET_LOGIN_FAIL
        
    
    def Discovery(self, portal = None):
        '''
        Make discovery on given portal
        @param portal: ip or domain name of portal
        '''
        if portal == None: # use first session
            if len(self.__sessions) == 0:
                self.logger.warn("No connection to perform Discovery")
            else:
                session = self.__sessions[0]
                if session.state == InitSession.STATE_LOGGED_IN:
                    session.SendText("SendTargets=All")
                    event = self.__event_listener.Wait()
                    # parse text response
                    targets = keys.ParsePayload(event.data)
                    if event.id == event.ID_TEXT_RESP:
                        t = event.data
                        targets = keys.ParsePayload(t)
                        t_name = None
                        retval = []
                        for t in targets:
                            if isinstance(t, keys.TargetName):
                                t_name = t.value
                                retval += [TargetInfo(t_name, [])]
                            elif isinstance(t, keys.TargetAddress):
                                retval[-1].addr_list.append(TargetAddrInfo(t.address, t.tpgt))
                                t_name = None
                            else:
                                self.logger.error("dicovery response isn't in correct format")
                        return retval

                    else:
                        return self.RET_LOGIN_FAIL
                    
    def Logout(self):
        if len(self.__sessions) == 0:
            self.logger.warn("No Connection to logout")
        else:
            self.__sessions[0].Logout()
            evnt = self.__event_listener.Wait()
            if evnt.id == evnt.ID_LOGGED_OUT:
                del self.__sessions[0]
                self.__event_listener.Wait()
                return self.RET_SUCCESS
            else:
                return self.RET_FAIL
            