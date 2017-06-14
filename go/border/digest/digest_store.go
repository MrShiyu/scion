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

// Package digest holds the digest of each packet, for access by the
// router's various packages.
package digest

import (//"fmt"
	"time"
	//"strings"
	"github.com/netsec-ethz/scion/go/border/conf"
	//log "github.com/inconshreveable/log15"
)

var defaultKEY = []byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
//key length for AES could be 128bit

// Conf is the main digest structure.
type DigestStore struct {
	Curr_seq_num   uint32	//the current seq num for this AS
	Seq_num_window uint32               //FIXME: need to reconcile with the BF coverage period
	Seq_info       map[string]*Curr_seq //map from the name of the border router to its current sequence number
	filter         []BlockedFilter
	length         int
}

const Seq_num_range = 100

//information needed for sequence number update
type Curr_seq struct{
	Seq_num uint32
	TTL     time.Duration //NOTE: maybe change to pure number
	Valid   bool          //flag, shows if the sequence number starts to be valid
	MacKey  []byte	      //shared key for mac computation
}

// D is a pointer to the current configuration.
var D *DigestStore

// Load sets up the configuration, loading it from the supplied config directory.
func Load(capacity, size, number int) {
	// Declare a new Conf instance, and load the topology config.
	digest := &DigestStore{}
	digest.Curr_seq_num = 0
	filter := make([]BlockedFilter, number)
	digest.length = number
	for i := 0; i < number; i++ {
		filter[i] = NewBlockedBloomFilter(capacity, size)
	}
	digest.filter = filter
	digest.Seq_num_window = 20 //FIXME: number needs discussing
	info := make(map[string]*Curr_seq)
	digest.Seq_info = info
	// Save Digest
	D = digest
	for _, ifs := range conf.C.TopoMeta.IFMap{
		v:= ifs.IF.IA.String()
		D.AddAsEntry(v)
	}
}

func (D *DigestStore)AddAsEntry(asname string){
	new_seq := Curr_seq{Seq_num: 0,
		TTL: SeqIncplusDelta,
		Valid: false,
		MacKey: defaultKEY}
	D.Seq_info[asname] = &new_seq
	//log.Debug("create a new entry for " + asname)
	//ss := fmt.Sprintf("the As %s has sequence number %d initial TTL %d", asname,new_seq.Seq_num, int64(new_seq.TTL))
	//log.Debug(ss)
}

func Add(byte_str []byte){
	D.filter[Writeable].BlockAdd(byte_str)
	//s := fmt.Sprintf("digest successfully added to filter %d", Writeable)
	//log.Debug(s)
}

//Check if data is in the whole block filter
func Check(byte_str []byte) bool{
	for i:=0; i<D.length; i++{
		if D.filter[i].BlockCheck(byte_str){
			return true
		}
	}
	return false
}


var Writeable = 0

func Rotate() {
	if Writeable < D.length - 1 {
		Writeable++
	}else{
		Writeable = 0
	}
	D.filter[Writeable].Reset()
	//s := fmt.Sprintf("%dth filter is now writeable and reset to 0", Writeable)
	//log.Debug(s)
}


const SeqIncFreq = 10 * time.Millisecond

const delta = time.Millisecond //account for clock askew

const SeqIncplusDelta = SeqIncFreq + delta

func TTLupdate(as string, augment time.Duration){
	//augment is a negative TTL that remains from the last session
	D.Seq_info[as].TTL = SeqIncplusDelta + augment
	//s:=fmt.Sprintf("the TTL of the sequence number for %s is reinitialized to %d", as, D.Seq_info[as].TTL)
	//log.Debug(s)
}
