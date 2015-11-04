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

def ntoi(data):
    if isinstance(data, (str, bytearray, bytes)):
        retval = 0
        for i in range(len(data)):
            b = data[i]
            if isinstance(b, str):
                b = ord(b)
            retval |= b << (len(data) - i -1) * 8
        return retval
    elif isinstance(data, int):
        return data
    else:
        raise TypeError 

def iton(i, ln = 0):
    if isinstance(i, int):
        retval = bytearray(0)
        len_tmp = ln
        while i != 0:
            byte = i & 0xFF
            retval.insert(0, byte)
            i >>= 8
            if len_tmp != 0:
                len_tmp -= 1
                if len_tmp == 0:
                    break
            
        if len(retval) < ln:
            for z in range(ln - len(retval)):
                retval.insert(0, 0)
        return retval
    else:
        raise TypeError
    

FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

def dump(src, length=8):
    N=0; result=''
    while src:
        s,src = src[:length],src[length:]
        hexa = ' '.join(["%02X"%ord(x) for x in s])
        s = s.translate(FILTER)
        result += "%04X   %-*s   %s\n" % (N, length*3, hexa, s)
        N+=length
    return result

