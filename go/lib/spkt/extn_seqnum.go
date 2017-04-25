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

package spkt

import (
	//"bytes"
	"fmt"

	//"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
)

var _ common.Extension = (*SeqNum)(nil)



type SeqNum struct {
	Num uint32
}

//FIXME:for now it takes no arguments, and takes a constant number. Change afterwards
func NewSeqNum() *SeqNum {
	t := &SeqNum{}
	t.Num = 0
	return t
}


//length of the header is one line
func (t *SeqNum) Write(b common.RawBytes) *common.Error {
	common.Order.PutUint32(b, t.Num)
	offset := 4 //length of uint32
	for i:= offset; i < common.ExtnFirstLineLen; i++ {
		b[i] = byte(0)
	}
	return nil
}

func (t *SeqNum) Pack() (common.RawBytes, *common.Error) {
	b := make(common.RawBytes, t.Len())
	if err := t.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

//FIXME: need to be fixed when NewSeqNum takes an argument
func (t *SeqNum) Copy() common.Extension {
	c := NewSeqNum()
	return c
}

func (t *SeqNum) Reverse() (bool, *common.Error) {
	// Nothing to do.
	return true, nil
}

func (t *SeqNum) Len() int {
	return common.LineLen
}

func (t *SeqNum) Class() common.L4ProtocolType {
	return common.HopByHopClass
}

func (t *SeqNum) Type() common.ExtnType {
	return common.ExtnSeqNumType
}

func (t *SeqNum) String() string {
	s := fmt.Sprintf("SeqeunceNumber: %d", t.Num)
	return s
}



