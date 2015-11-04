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
    