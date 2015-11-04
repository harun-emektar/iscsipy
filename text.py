#!/usr/bin/python3
# -*- coding: utf8 -*-
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

import base64
from utils import ntoi, iton


class Format():
    def __init__(self, ustr):
        if not isinstance(ustr, str):
            raise TypeError

class StandardLabel(Format):
    def __init__(self, ustr):
        super().__init__(ustr)
        for c in ustr:
            if not c.isalpha() and not c.isdigit() and c not in ".-+@_":
                raise TypeError

        if not ustr[0].isupper() or len(ustr) > 63:
            raise TypeError

class KeyName(StandardLabel):
    pass

class TextValue(Format):
    def __init__(self, ustr):
        super().__init__(ustr)
        if len(ustr) == 0:
            raise TypeError
        for c in ustr:
            if not c.isalpha() and not c.isdigit() and c not in ".-+@_/[]:":
                raise TypeError

class IscsiNameValue(Format):
    def __init__(self, ustr):
        super().__init__( ustr)
        if len(ustr) == 0:
            raise TypeError
        for c in ustr:
            if not c.isalpha() and not c.isdigit() and c not in "-.:":
                raise TypeError

class BooleanValue(Format):
    def __init__(self, ustr):
        super().__init__(ustr)
        if ustr != "Yes" and ustr != "No":
            raise TypeError
        if ustr == "Yes":
            self.__value = True
        else:
            self.__value = False

    @property
    def Value(self):
        return self.__value

class HexConstant(Format):
    def __init__(self, ustr):
        super().__init__(ustr)
        if ustr[:2] != "0x" and ustr[:2] != "0X":
            raise TypeError
        for c in ustr[2:]:
            if c not in "abcdefABCDEF" and not c.isdigit():
                raise TypeError

class DecimalConstant(Format):
    def __init__(self, ustr):
        super().__init__(ustr)
        if len(ustr) == 0:
            raise TypeError
        for c in ustr:
            if not c.isdigit():
                raise TypeError
        if int(ustr) > 0xFFFFFFFFFFFFFFFF:
            raise TypeError

class Base64Constant(Format):
    def __init__(self, ustr):
        super().__init__(ustr)
        if ustr[:2] != "0b" and ustr[:2] != "0B":
            raise TypeError
        base64.b64decode(bytes(ustr[2:], "utf8"))

class NumericalValue(Format):
    def __init__(self, ustr):
        super().__init__(ustr)
        try:
            HexConstant(ustr)
            if int(ustr,16) > 0xFFFFFFFFFFFFFF:
                raise TypeError
            self.__value = int(ustr, 16)
        except TypeError:
            DecimalConstant(ustr)
            self.__value = int(ustr)

    @property
    def Value(self):
        return self.__value

class LargeNumericalValue(Format):
    def __init__(self, ustr):
        super().__init__(ustr)
        try:
            HexConstant(ustr)
            self.__value = int(ustr,16)
        except TypeError:
            Base64Constant(ustr)
            binstr = base64.b64decode(bytes(ustr[2:], "utf8"))
            self.__value = ntoi(binstr)

    @property
    def Value(self):
        return self.__value

class NumericRange(Format):
    def __init__(self,ustr):
        super().__init__(ustr)
        tilde = ustr.find("~")
        self.__min = NumericalValue(ustr[:tilde]).Value
        self.__max = NumericalValue(ustr[tilde + 1:]).Value
        if self.__max < self.__min:
            raise TypeError

    @property
    def Min(self):
        return self.__min

    @property
    def Max(self):
        return self.__max

    @property
    def Range(self):
        return (self.__min, self.__max)

class RegBinValue(Format):
    def __init__(self, ustr):
        super().__init__(ustr)
        try:
            DecimalConstant(ustr)
            i = int(ustr)
            self.__value = iton(i)
        except TypeError:
            try:
                HexConstant(ustr)
                i = int(ustr, 16)
                self.__value = iton(i)
            except TypeError:
                Base64Constant(ustr)
                self.__value = base64.b64decode(bytes(ustr[2:], "utf8"))
        if len(self.__value) > 8 :
            raise TypeError

    @property
    def Value(self):
        return self.__value

    def __get_val(self):
        return self.__value

class LargeBinValue(Format):
    def __init__(self, ustr):
        super().__init__(ustr)
        try:
            HexConstant(ustr)
            i = int(ustr, 16)
            self.__value = iton(i)
        except TypeError:
            Base64Constant(ustr)
            self.__value = base64.b64decode(bytes(ustr[2:], "utf8"))

    @property
    def Value(self):
        return self.__value

    def __get_val(self):
        return self.__value

class BinValue(Format):
    def __init__(self, ustr):
        super().__init__(ustr)
        try:
            rbv = RegBinValue(ustr)
            self.__value = rbv.Value
        except TypeError:
            lbv = LargeBinValue(ustr)
            self.__value = lbv.Value

    @property
    def Value(self):
        return self.__value

class SimpleValue(Format):
    def __init__(self, ustr):
        super().__init__(ustr)
        if len(ustr.encode("utf8")) > 255:
            raise TypeError

class ValueList(Format):
    def __init__(self, ustr):
        super().__init__(ustr)
        self.__list = ustr.split(",")

    @property
    def Value(self):
        # return list of str
        return self.__list


if __name__ == "__main__":
    import unittest
    class TestFormat(unittest.TestCase):
        def testInvalidParam(self):
            self.assertRaises(TypeError, Format, 4)

        def testValidParam(self):
            self.assertTrue(isinstance(Format("unicode"), Format))

    class TestStdLabel(unittest.TestCase):
        def testInvalidParam(self):
            self.assertRaises(TypeError, StandardLabel, "abcd~/>?abcd")
            chars = ["A" for i in range(64)]
            ustr = "".join(chars)
            self.assertRaises(TypeError, StandardLabel, ustr)
            self.assertRaises(TypeError, StandardLabel, 4)
            self.assertRaises(TypeError, StandardLabel, "a")

        def testValidParam(self):
            self.assertTrue(isinstance(StandardLabel("Abctüâüşöğç.-+@_"), StandardLabel))

    class TestTextValue(unittest.TestCase):
        def testInvalidParam(self):
            self.assertRaises(TypeError, TextValue, "~/>?abcd")

        def testValidParam(self):
            self.assertTrue(isinstance(TextValue("Abctüâüşöğç.-+@_/[]:"), TextValue))

    class TestBooleanValue(unittest.TestCase):
        def testInvalidParam(self):
            self.assertRaises(TypeError,BooleanValue, 4)
            self.assertRaises(TypeError,BooleanValue, "Yep")

        def testValidParam(self):
            self.assertTrue(isinstance(BooleanValue("Yes"), BooleanValue))
            self.assertTrue(BooleanValue("Yes").Value)
            self.assertTrue(isinstance(BooleanValue("No"), BooleanValue))
            self.assertFalse(BooleanValue("No").Value)

    class TestHexConstant(unittest.TestCase):
        def testInvalidParam(self):
            self.assertRaises(TypeError, HexConstant, 4.0)
            self.assertRaises(TypeError, HexConstant, "abcd")
            self.assertRaises(TypeError, HexConstant, "0xabcdeg")

        def testValidParam(self):
            self.assertTrue(isinstance(HexConstant("0xabcdef0123456789"), HexConstant))

    class TestDecimalConstant(unittest.TestCase):
        def testInvalidParam(self):
            self.assertRaises(TypeError, DecimalConstant, "ah")
            self.assertRaises(TypeError, DecimalConstant, "0x12345")
            self.assertRaises(TypeError, DecimalConstant, "18446744073709551616")
        def testValidParam(self):
            self.assertTrue(isinstance(DecimalConstant("18446744073709551615"), DecimalConstant))

    class TestB64Constant(unittest.TestCase):
        def testInvalidParam(self):
            self.assertRaises(TypeError, Base64Constant, "ah")
        def testValidParam(self):
            self.assertTrue(isinstance(Base64Constant("0b01234567890xzy/+=="), Base64Constant))

    class TestNumericalValue(unittest.TestCase):
        def testInvalidParam(self):
            self.assertRaises(TypeError, NumericalValue, "aha")
            self.assertRaises(TypeError, NumericalValue, "0xFFFFFFFFFFFFFFFFFF")
            self.assertRaises(TypeError, NumericalValue, "18446744073709551616")

        def testValidParam(self):
            self.assertTrue(isinstance(NumericalValue("00012345"), NumericalValue))
            self.assertEqual(NumericalValue("000012345").Value, 12345)
            self.assertTrue(isinstance(NumericalValue("0x00012345"), NumericalValue))
            self.assertEqual(NumericalValue("0x000012345").Value, 0x12345)

    class TestLargeNumValue(unittest.TestCase):
        def testInvalidParam(self):
            self.assertRaises(TypeError, LargeNumericalValue, "aha")
            self.assertRaises(TypeError, LargeNumericalValue, "12345")

        def testValidParam(self):
            self.assertTrue(isinstance(LargeNumericalValue("0b01234567890xzy/+=="), LargeNumericalValue))
            self.assertTrue(isinstance(LargeNumericalValue("0xFFFFFFFFFFFFFFFFFF"), LargeNumericalValue))

    class TestNumRange(unittest.TestCase):
        def testInvalidParam(self):
            self.assertRaises(TypeError, NumericRange, "0b0123")
            self.assertRaises(TypeError, NumericRange, "123~abc")
            self.assertRaises(TypeError, NumericRange, "abc~123")
            self.assertRaises(TypeError, NumericRange, "0x123~123")
            self.assertRaises(TypeError, NumericRange, "123~12")
            self.assertRaises(TypeError, NumericRange, "123~18446744073709551616")
            self.assertRaises(TypeError, NumericRange, "123~~1234")

        def testValidParam(self):
            self.assertTrue(isinstance(NumericRange("123~123"), NumericRange))
            self.assertEqual(NumericRange("123~123").Max, 123)
            self.assertEqual(NumericRange("123~123").Min, 123)

    class TestRegBinValue(unittest.TestCase):
        def testInvalidParam(self):
            self.assertRaises(TypeError, RegBinValue, "oh")
            self.assertRaises(TypeError, RegBinValue, "0xFFFFFFFFFFFFFFFFFF")
            self.assertRaises(TypeError, RegBinValue, "18446744073709551616")
            self.assertRaises(TypeError, RegBinValue, "0b////////////")

        def testValidParam(self):
            self.assertTrue(isinstance(RegBinValue("18446744073709551615"), RegBinValue))
            self.assertEqual(RegBinValue("18446744073709551615").Value, b"\xff\xff\xff\xff\xff\xff\xff\xff")
            self.assertTrue(isinstance(RegBinValue("0xffffffffffffffff"), RegBinValue))
            self.assertEqual(RegBinValue("0xffffffffffffffff").Value, b"\xff\xff\xff\xff\xff\xff\xff\xff")
            self.assertTrue(isinstance(RegBinValue("0b//////////8="), RegBinValue))
            self.assertEqual(RegBinValue("0b//////////8=").Value, b"\xff\xff\xff\xff\xff\xff\xff\xff")

    class TestLargeBinValue(unittest.TestCase):
        def testInvalidParam(self):
            self.assertRaises(TypeError, LargeBinValue, "1234")
            self.assertRaises(TypeError, LargeBinValue, "aha")

        def testValidParam(self):
            self.assertTrue(isinstance(LargeBinValue("0xffffffffffffffffff"), LargeBinValue))
            self.assertEqual(LargeBinValue("0xffffffffffffffffff").Value, b"\xff\xff\xff\xff\xff\xff\xff\xff\xff")
            self.assertTrue(isinstance(LargeBinValue("0b//////////8="), LargeBinValue))
            self.assertEqual(LargeBinValue("0b//////////8=").Value, b"\xff\xff\xff\xff\xff\xff\xff\xff")

    class TestBinValue(unittest.TestCase):
        def testInvalidParam(self):
            self.assertRaises(TypeError, BinValue, "aha")

        def testValidParam(self):
            self.assertTrue(isinstance(BinValue("18446744073709551615"), BinValue))
            self.assertEqual(BinValue("18446744073709551615").Value, b"\xff\xff\xff\xff\xff\xff\xff\xff")
            self.assertTrue(isinstance(BinValue("0xffffffffffffffffff"), BinValue))
            self.assertEqual(BinValue("0xffffffffffffffffff").Value, b"\xff\xff\xff\xff\xff\xff\xff\xff\xff")
            self.assertTrue(isinstance(BinValue("0b//////////8="), BinValue))
            self.assertEqual(BinValue("0b//////////8=").Value, b"\xff\xff\xff\xff\xff\xff\xff\xff")


    unittest.main()