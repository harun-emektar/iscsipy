#!/usr/bin/python3

import queue

class Event():
    ID_EMPTY_QUEUE = 0
    ID_PDU_RECV = 1
    ID_LOGGED_IN = 2
    ID_TEXT_RESP = 3
    ID_LOGGED_OUT = 4
    def __init__(self, id, data = None):
        self.__id = id
        self.__data = data
        
    @property
    def id(self):
        return self.__id
    
    @property
    def data(self):
        return self.__data

class EventListener():
    '''
    Class for waiting events to happen.
    '''
    def __init__(self):
        self.__queue = queue.Queue(0)
        pass
    
    def Wait(self, timeout = None):
        try:
            return self.__queue.get(True, timeout)
        except queue.Empty:
            return Event(Event.ID_EMPTY_QUEUE)
    
    def Signal(self, event):
        self.__queue.put_nowait(event)
    