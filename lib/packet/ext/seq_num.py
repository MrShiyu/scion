# Copyright 2016 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`seq_num` --- sequence number extension header
=========================================================
"""
# Stdlib
import struct

# SCION
from lib.packet.ext_hdr import HopByHopExtension
from lib.types import ExtHopByHopType
from lib.util import Raw


class SeqNumExt(HopByHopExtension):
    """
    Packets with this extension receives a sequence number when generated
    0B       1        2        3        4        5        6        7
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | xxxxxxxxxxxxxxxxxxxxxxxx | Sequence Number                   |padding |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    """
    NAME = "SeqNum"
    EXT_TYPE = ExtHopByHopType.SEQ_NUM
    LEN = 5

    def __init__(self, raw=None):
        """
        :param bytes raw: Raw data containing IS_ACK and PROBE_ID
        """
        self.seq_num = 0
        super().__init__(raw)

    def _parse(self, raw):
        """
        Parse payload to extract values

        :param bytes raw: Raw payload
        """
        super()._parse(raw)
        data = Raw(raw, self.NAME, self.LEN)
        self.seq_num = struct.unpack("!I", data.pop(4))[0] #because !I stands for unsigned integer! [0] gets four bytes!
        print("seq_num successfully parsed, the sequence number is " + str(self.seq_num))

    @classmethod
    def from_values(cls, seq_num):
        """"
        Create an instance of the class PathProbe from the provided values

        :param bool is_ack: True if this packet is an ACK of a previous probe
        :param int probe_id: ID value to use for this probe packet
        """
        inst = cls()
        inst.seq_num = seq_num
        print ("seq_num successfully created")
        return inst

    def pack(self):
        """
        Pack into byte string
        """
        raw = struct.pack("!IB", self.seq_num, False)
        self._check_len(raw)
        print("seq_num successfully packed, the sequence number is " + str(self.seq_num))
        return raw

    def __str__(self):
        """
        Return string representation
        """
        return "%s(%sB): Sequence Number: %s" % (
            self.NAME, len(self), self.seq_num)
