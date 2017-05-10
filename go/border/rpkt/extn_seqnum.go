// Copyright 2016 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file contains the router's representation of the SeqNum hop-by-hop
// extension.

package rpkt

import (
	"fmt"
	//"time"
	"strings"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/digest"
	"github.com/netsec-ethz/scion/go/border/conf"
	//"github.com/netsec-ethz/scion/go/border/seqnumtest"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"crypto/hmac"
	"crypto/md5"
	"bytes"
	//"github.com/netsec-ethz/scion/go/lib/assert"
	"github.com/netsec-ethz/scion/go/border/seqnumtest"
)

var _ rExtension = (*rSeqNum)(nil)

const MAC_LEN = 16

const test_num_packet = 80 //depending on the number of packets sent from the pktgen.py


// rSeqNum is the router's representation of the Seqnum extension.
type rSeqNum struct {
	rp       *RtrPkt
	Num      uint32
	curr_hop uint8
	total_hop uint8
	raw      common.RawBytes
	mac	[]byte //here use md5, has the output length of 16 bytes
	log.Logger
}

// rSeqNumFromRaw creates an rSeqNum instance from raw bytes, keeping a
// reference to the location in the packet's buffer.
func rSeqNumFromRaw(rp *RtrPkt, start, end int) (*rSeqNum, *common.Error) {
	t := &rSeqNum{rp: rp, raw: rp.Raw[start:end]}
	seq := make([]byte, 4)
	for i:=0; i<4; i++ {
		seq[i] = byte(t.raw[i])
	}
	t.Num = common.Order.Uint32(seq)
	t.curr_hop = t.raw[4]
	t.total_hop = uint8(len(t.raw)-common.ExtnFirstLineLen)/(common.LineLen * 2)
	offset := common.ExtnFirstLineLen + common.LineLen * 2 * int(t.curr_hop)
	t.mac = make([]byte, MAC_LEN)
	copy(t.mac, t.raw[offset:offset+16])
	fmt.Println("the t raw is ", t.raw[offset:offset+16], "current hop is ", t.curr_hop, "the t.mac is ", t.mac)
	t.Logger = rp.Logger.New("ext", "sequenceNumber")
	return t, nil
}


func (t *rSeqNum) RegisterHooks(h *hooks) *common.Error {
	h.Process = append(h.Process, t.Process)
	return nil
}

func (t *rSeqNum) Process() (HookResult, *common.Error) {
	start := seqnumtest.T_start()
	defer seqnumtest.T_track(start, test_num_packet)
	//return HookContinue, nil
	//s := fmt.Sprintf("the sequence number of this packet is %d", t.Num)
	//t.Logger.Debug(s)
	seg_for_mac := []byte(t.rp.Raw[8:50])
	//FIXME: the common header changes on the way. But need to think carefully which bits to use
	//so that it 1. doesn't change on the way 2. uniquely distinguishes each packet


	//if packet goes out from an AS
	if strings.Compare(conf.C.IA.String(), t.rp.srcIA.String()) == 0{
		t.Num = digest.D.Curr_seq_num
		common.Order.PutUint32(t.raw[0:4], t.Num)
		offset := common.ExtnFirstLineLen
		for i:= 0; i < int(t.total_hop); i++ {
			offset += common.LineLen*i*2
			asname := parseAs([]byte(t.raw[offset:offset+16]))
			if _, ok := digest.D.Seq_info[asname]; !ok {
				//t.Logger.Debug("the As to be added at the time of assigning MAC is " + asname)
				digest.D.AddAsEntry(asname)
			}
			mac_code := computeMac(seg_for_mac, digest.D.Seq_info[asname].MacKey)
			copy(t.raw[offset:offset+16], mac_code)
		}
	}else{
		//if packet goes through this router

		//if it comes from border router in the same AS
		if t.rp.DirFrom == DirLocal{
			return HookContinue, nil
		}

		//add seq info entry if not existed
		if _, ok := digest.D.Seq_info[t.rp.srcIA.String()]; !ok {
			digest.D.AddAsEntry(t.rp.srcIA.String())
		}
		val := digest.D.Seq_info[t.rp.srcIA.String()]

		//authentication
		if !t.authenticate(seg_for_mac, val.MacKey)  {
			//t.Logger.Debug("authentication failed")
			return HookContinue, nil//common.NewError("authentication failed")
		}else{
			//t.Logger.Debug("authentication passed")
		}

		//seq_num check
		if !val.Valid {
			val.Seq_num = t.Num
			val.Valid = true
			//s := fmt.Sprintf("valid flag is set to %b, sequence number is %d", digest.D.Seq_info[t.rp.srcIA.String()].Valid, digest.D.Seq_info[t.rp.srcIA.String()].Seq_num)
			//t.Logger.Debug(s)
		}
		curr_seq := val.Seq_num
		if (!checkSeqWin(t.Num, digest.D.Seq_num_window, curr_seq)){
			//seq num out of sliding window.
			//t.Logger.Debug(ss)
			//t.Logger.Debug("seq num out of sliding window. Should drop this packet")
			return HookContinue, common.NewError("seq num out of sliding window. Should drop this packet")
		}else{
			//check if need to update sequence number
			if checkSeqUpdate(t.Num, curr_seq) {
				//aq := fmt.Sprintf("the stored seq num for %s is %d", t.rp.srcIA.String(), curr_seq)
				//t.Logger.Debug(aq)
				val.Seq_num = t.Num
				digest.TTLupdate(t.rp.srcIA.String(), 0)
				//a := fmt.Sprintf("the stored seq num for %s update to %d", t.rp.srcIA.String(), t.Num)
				//t.Logger.Debug(a)
			}
		}

		//digest check
		//use the seqnum extension header(which contains seqnum and all MAC code, enough for digest computation)
		if digest.Check([]byte(t.raw)) {
			//t.Logger.Error("the digest is already in the digest store, should drop this packet")
			//e := common.NewError("the digest is already in the digest store, should drop this packet")
			return HookContinue, nil
		}
		digest.Add([]byte(t.raw))
		//t.Logger.Debug("packet digest successfully added")
	}
	return HookContinue, nil
}


func computeMac(message, key []byte) []byte {
	mac := hmac.New(md5.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func (t *rSeqNum)authenticate(message, key []byte) bool {
	expectedMAC := computeMac(message, key)
	t.curr_hop += 1
	t.raw[4] = t.curr_hop
	return hmac.Equal(t.mac, expectedMAC)
}

//here we assume the length of the macEntry is the valid length of a mac entry
func parseAs(macEntry []byte) string{
	n := bytes.Index(macEntry, []byte{'x'})
	return string(macEntry[:n])
}


//check if the current num is within valid sequence number window
func checkSeqWin(num, winsize, storedseq uint32) bool{
	if storedseq <= winsize {
		if num>=0 && num <= storedseq {return true}
		if num> storedseq && (storedseq +digest.Seq_num_range - num)<= winsize {return true}
		//consider wrap around
		return false
	}else{
		if num + digest.Seq_num_range - storedseq < winsize {return true}
		//FIXME: at wrap around time, set a limit as winsize, so that we consider the wrap around packet seq num as bigger
		//the limit can be discussed
		return num + winsize >= storedseq
	}

}

func checkSeqUpdate(packetSeq, storedSeq uint32) bool{
	if packetSeq + digest.Seq_num_range - storedSeq <= digest.D.Seq_num_window { return true}
	//FIXME: at wrap around time, set a limit as winsize, so that we consider the wrap around packet seq num as bigger
	return packetSeq > storedSeq
}

// GetExtn returns the spkt.SeqNum representation. The big difference
// between the two representations is that the latter doesn't have an
// underlying buffer, so instead it has a slice of TracerouteEntry's.
func (t *rSeqNum) GetExtn() (common.Extension, *common.Error) {
	s := spkt.NewSeqNum() //FIXME: Change this when the defition of NewSeqNum is changed
	s.Num = t.Num
	return s, nil
}

func (t *rSeqNum) Len() int {
	return common.LineLen
}

func (t *rSeqNum) Class() common.L4ProtocolType {
	return common.HopByHopClass
}

func (t *rSeqNum) Type() common.ExtnType {
	return common.ExtnSeqNumType
}

func (t *rSeqNum) String() string {
	// Delegate string representation to spkt.Traceroute
	e, _ := t.GetExtn()
	return e.String()
}
