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

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/digest"
	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	//"crypto/hmac"
	//"crypto/md5"
	"bytes"
	"crypto/aes"
	//"github.com/netsec-ethz/scion/go/lib/addr"
	//"github.com/netsec-ethz/scion/go/border/seqnumtest"
	"crypto/subtle"
	"github.com/dchest/cmac"
	//"github.com/netsec-ethz/scion/go/border/seqnumtest"
)

var _ rExtension = (*rSeqNum)(nil)

const MAC_LEN = 16

const BLOCK_SIZE = 16 //the block size for aes encryption

const test_num_packet = 10000


// rSeqNum is the router's representation of the Seqnum extension.
type rSeqNum struct {
	rp       *RtrPkt
	Num      uint32
	curr_hop uint8
	total_hop uint8
	raw      common.RawBytes
	mac	[]byte
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
	copy(t.mac, t.raw[offset:offset+MAC_LEN])
	//fmt.Println("the t raw is ", t.raw[offset:offset+16], "current hop is ", t.curr_hop, "the t.mac is ", t.mac)
	//t.Logger = rp.Logger.New("ext", "sequenceNumber")
	return t, nil
}


func (t *rSeqNum) RegisterHooks(h *hooks) *common.Error {
	h.Process = append(h.Process, t.Process)
	return nil
}

func (t *rSeqNum) Process() (HookResult, *common.Error) {
	//start := seqnumtest.T_start()
	//defer seqnumtest.T_track(start, test_num_packet)
	//return HookContinue, nil
	s := fmt.Sprintf("the sequence number of this packet is %d", t.Num)
	log.Debug(s)
	//log.Debug(s)
	seg_for_mac := t.getBytesForMac()

	//if packet goes out from an AS
	if (conf.C.IA.A == t.rp.srcIA.A) && (conf.C.IA.I == t.rp.srcIA.I){
		//assign sequence number
		t.Num = digest.D.Curr_seq_num
		common.Order.PutUint32(t.raw[0:4], t.Num)
		s := fmt.Sprintf("the sequence number of this packet is changed to %d", t.Num)
		log.Debug(s)
		offset := common.ExtnFirstLineLen
		//compute and write mac
		for i:= 0; i < int(t.total_hop); i++ {
			offset += common.LineLen*i*2
			asname := parseAs([]byte(t.raw[offset:offset+16]))
			if _, ok := digest.D.Seq_info[asname]; !ok {
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
			//log.Debug("authentication failed")
			return HookContinue, common.NewError("authentication failed")
		}else{
			//log.Debug("authentication passed")
		}

		//seq_num check
		if !val.Valid {
			val.Seq_num = t.Num
			val.Valid = true
			digest.TTLupdate(t.rp.srcIA.String(), 0)
			s := fmt.Sprintf("valid flag is set to %b, sequence number is %d", digest.D.Seq_info[t.rp.srcIA.String()].Valid, digest.D.Seq_info[t.rp.srcIA.String()].Seq_num)
			log.Debug(s)
		}
		curr_seq := val.Seq_num

		if checkAhead(t.Num, curr_seq, digest.Seq_num_range){
			aq := fmt.Sprintf("the stored seq num for %s is %d", t.rp.srcIA.String(), curr_seq)
			log.Debug(aq)
			val.Seq_num = t.Num
			digest.TTLupdate(t.rp.srcIA.String(), 0)
			a := fmt.Sprintf("the stored seq num for %s update to %d", t.rp.srcIA.String(), t.Num)
			log.Debug(a)
		}else {
			if !checkSeqWin(t.Num, digest.D.Seq_num_window, curr_seq, digest.Seq_num_range) {
				//seq num out of sliding window.
				//t.Logger.Debug(ss)
				log.Debug("seq num out of seqnum window. Should drop this packet")
				return HookContinue, nil//common.NewError("seq num out of sliding window. Should drop this packet")
			}
		}

		//digest check
		//use the seqnum extension header(which contains seqnum and all MAC code, enough for digest computation)
		if digest.Check([]byte(t.raw)) {
			//log.Error("the digest is already in the digest store, should drop this packet")
			//e := common.NewError("the digest is already in the digest store, should drop this packet")
			return HookContinue, nil
		}
		digest.Add([]byte(t.raw))
		log.Debug("packet digest successfully added")
	}
	return HookContinue, nil
}


////using hmac to compute MAC
//func computeMac(message, key []byte) []byte {
//	mac := hmac.New(md5.New, key)
//	mac.Write(message)
//	return mac.Sum(nil)
//}
////using hmac to authenticate MAC
//func (t *rSeqNum)authenticate(message, key []byte) bool {
//	expectedMAC := computeMac(message, key)
//	t.curr_hop += 1
//	t.raw[4] = t.curr_hop
//	return hmac.Equal(t.mac, expectedMAC)
//}


//using cmac to compute MAC
func computeMac(message, key []byte) []byte {
	c, _ := aes.NewCipher(key)
	mac,_ := cmac.New(c)
	mac.Write(message)
	return mac.Sum(nil)
}
//using cmac to authenticate MAC
func (t *rSeqNum)authenticate(message, key []byte) bool {
	expectedMAC := computeMac(message, key)
	t.curr_hop += 1
	t.raw[4] = t.curr_hop
	return subtle.ConstantTimeCompare(t.mac, expectedMAC) == 1
}



func (t *rSeqNum) getBytesForMac() []byte{
	head_length := t.rp.idxs.path
	l4index := t.rp.idxs.nextHdrIdx.Index
	length := head_length + (len(t.rp.Raw)-l4index)
	length = length - length%BLOCK_SIZE //make the length multiple of blocksize
	buffer := make([]byte, length)
	copy(buffer[:head_length], t.rp.Raw[:head_length])
	copy(buffer[head_length:], t.rp.Raw[l4index:(length-head_length)])
	buffer[5] = 0
	buffer[6] = 0
	return buffer
}



//here we assume the length of the macEntry is the valid length of a mac entry
func parseAs(macEntry []byte) string{
	n := bytes.Index(macEntry, []byte{'x'})
	return string(macEntry[:n])
}

//return true if packetseq is ahead of storedseq
func checkAhead(packetseq, storedseq, totalseq uint32) bool{
	return (storedseq - packetseq)%totalseq > (packetseq - storedseq)%totalseq
}

//return true if packetseq is within seqNo window
//this function works with the assumption that packetseq is behind storedseq
func checkSeqWin(packetseq, winsize, storedseq, totalseq uint32) bool{
	if packetseq > storedseq {
		storedseq = storedseq + totalseq
	}
	return packetseq + winsize >= storedseq
}



// GetExtn returns the spkt.SeqNum representation. The big difference
// between the two representations is that the latter doesn't have an
// underlying buffer, so instead it has a slice of TracerouteEntry's.

func (t *rSeqNum) GetExtn() (common.Extension, *common.Error) {
	s := spkt.NewSeqNum()
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
