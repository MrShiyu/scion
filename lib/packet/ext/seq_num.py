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
from lib.packet.path import SCIONPath


class SeqNumExt(HopByHopExtension):
    """
    Packets with this extension receives a sequence number when generated
    0B       1        2        3        4        5        6        7
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | xxxxxxxxxxxxxxxxxxxxxxxx | Sequence Number                   |hop_no  |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |     Mac of ISD_0 (use MD5, ouput 16 bytes, two line)                                     |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    .............more Macs for more ISDs on the forwarding path..............
    
    """
    NAME = "SeqNum"
    EXT_TYPE = ExtHopByHopType.SEQ_NUM
    PADDING = 1
    FIRST_LEN = 4 + PADDING
    MAC_LEN = 16

    def __init__(self, raw=None):
        """
        :param bytes raw: Raw data containing IS_ACK and PROBE_ID
        """
        self.seq_num = 0
        self.macs = []
        self.curr_hop = 0
        self.total_hop = 0
        super().__init__(raw)


    def _parse(self, raw):
        """
        Parse payload to extract values

        :param bytes raw: Raw payload
        """
        super()._parse(raw)
        self.curr_hop = raw[4]
        data = Raw(raw, self.NAME, self.FIRST_LEN + (self.curr_hop * self.MAC_LEN * 2))
        self.seq_num = struct.unpack("!I", data.pop(4))[0] #because !I stands for unsigned integer! [0] gets four bytes!
        data.pop(1)
        mac_list = list(struct.unpack("!16b", data.pop(self.MAC_LEN * self.curr_hop)))
        for mac in mac_list:
            self.macs.append(mac)
        #for a, b, c, d in zip(mac_list[0::4], mac_list[1::4], mac_list[2::4], mac_list[3::4]):
        #    isdas = a+b+c+d
        #    self.macs.append(isdas)
        print("seq_num successfully parsed, the sequence number is " + str(self.seq_num))
        print("the mac list is " + str(mac_list))




    @classmethod
    def from_values(cls, seq_num, as_hop, isd_list):
        """"
        Construct extension with allocated space for `num of hops`.      
        """
        inst = cls()
        inst.seq_num = seq_num
        inst.curr_hop = 0
        inst._init_size(as_hop*(int(cls.MAC_LEN/8)))
        maclist = [isd_list[i] for i in range(as_hop)]
        for s in maclist:
            if len(s) < inst.MAC_LEN:
                diff = inst.MAC_LEN - len(s)
                s += "x" * diff
            inst.macs.append(s.encode('utf-8'))
        return inst



    def pack(self):
        """
        Pack into byte string
        """
        packed = []
        packed.append(struct.pack("!I", self.seq_num))
        packed.append(struct.pack("!B", self.curr_hop))
        for mac in self.macs:
            packed.append(struct.pack("!16s", mac))
        raw = b"".join(packed)
        self._check_len(raw)
        print("seq_num successfully packed, the sequence number is " + str(self.seq_num))
        print("current hop is " + str(self.curr_hop))
        print("the macs are " + str(self.macs))
        return raw

    def __str__(self):
        """
        Return string representation
        """
        return "%s(%sB): Sequence Number: %s, current hop for mac: %d" % (
            self.NAME, len(self), self.seq_num, self.curr_hop)


