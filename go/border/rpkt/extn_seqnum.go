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
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spkt"
)

var _ rExtension = (*rSeqNum)(nil)


// rTraceroute is the router's representation of the Traceroute extension.
type rSeqNum struct {
	rp        *RtrPkt
	Num 	  uint32
	raw 	  common.RawBytes
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
	t.Num = common.Order.Uint32(seq) //FIXME: possible mistake at byte parsing
	t.Logger = rp.Logger.New("ext", "sequenceNumber")
	return t, nil
}


func (t *rSeqNum) RegisterHooks(h *hooks) *common.Error {
	h.Process = append(h.Process, t.Process)
	return nil
}

// FIXME: Now process only writes the number in the logger/print the number,
// need to be modified to check sliding window afterwards
func (t *rSeqNum) Process() (HookResult, *common.Error) {
	s := fmt.Sprintf("the sequence number of this string is %d", t.Num)
	t.Logger.Debug(s)
	if strings.Compare(conf.C.IA.String(), t.rp.srcIA.String()) == 0{
		seq := digest.D.Curr_seq_num
		common.Order.PutUint32(t.raw[0:4], seq)
		t.Num = seq
		s := fmt.Sprintf("the seq number changed to %d ", seq)
		t.Logger.Debug(s)
	}else {
		if val, ok := digest.D.Seq_info[t.rp.srcIA.String()]; ok {
			if !val.Valid {
				val.Seq_num = t.Num
				val.Valid = true
				s := fmt.Sprintf("valid flag is set to %b, sequence number is %d", digest.D.Seq_info[t.rp.srcIA.String()].Valid, digest.D.Seq_info[t.rp.srcIA.String()].Seq_num)
				t.Logger.Debug(s)
			}
			curr_seq := val.Seq_num
			if (!checkSeqWin(t.Num, digest.D.Seq_num_window, curr_seq)){
				//seq num out of sliding window.
				ss := fmt.Sprintf("packet num is %d, stored num is %d ", t.Num, curr_seq)
				//t.Logger.Debug(ss)
				//t.Logger.Debug("seq num out of sliding window. Should drop this packet")
				return HookContinue, common.NewError(ss, "seq num out of sliding window. Should drop this packet")
			}else{
				//check if need to update sequence number
				if checkSeqUpdate(t.Num, curr_seq) {
					aq := fmt.Sprintf("the stored seq num for %s is %d", t.rp.srcIA.String(), curr_seq)
					t.Logger.Debug(aq)
					val.Seq_num = t.Num
					digest.TTLupdate(t.rp.srcIA.String(), 0)
					a := fmt.Sprintf("the stored seq num for %s update to %d", t.rp.srcIA.String(), t.Num)
					t.Logger.Debug(a)
				}
			}
		}else{
			new_seq := digest.Curr_seq{Seq_num: 15,
				TTL: digest.SeqIncplusDelta}
			digest.D.Seq_info[t.rp.srcIA.String()] = &new_seq
			t.Logger.Debug("create a new entry for ", t.rp.srcIA.String())
		}
		if digest.Check([]byte(t.rp.Raw)) {
			t.Logger.Error("the digest is already in the digest store, should drop this packet")
			e := common.NewError("the digest is already in the digest store, should drop this packet")
			fmt.Println("the digest is already in the digest store, should drop this packet")
			return HookContinue, e
		}
		digest.Add([]byte(t.rp.Raw))
		t.Logger.Debug("packet digest successfully added")
	}

	return HookContinue, nil
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
