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
package seqnumtest

import(
	"time"
	"github.com/gavv/monotime"
	log "github.com/inconshreveable/log15"
	"fmt"
)

type Tstat struct{
	total_time time.Duration
	exec_count int
}

var t *Tstat

func Load(){
	newstat := &Tstat{}
	newstat.total_time = 0*time.Nanosecond
	newstat.exec_count = 0
	t = newstat
}

func T_start() time.Duration{
	return monotime.Now()
}

func T_track(start time.Duration, count int){
	elapsed := monotime.Since(start)
	t.total_time += elapsed
	t.exec_count += 1
	//if t.exec_count%40 == 0 {
	//	s := fmt.Sprintf("%d packets processed", t.exec_count)
	//	log.Debug(s)
	//}
	if t.exec_count == count {
		//log.Debug("the total elaped time is " + T.total_time.String())
		average := t.total_time.Nanoseconds()/int64(t.exec_count)
		//convert to microsecond
		converted := float64(average)/float64(1000)
		s := fmt.Sprintf("the execution time per packet with replay suppression is %f microsecond", converted)
		log.Debug(s)
		t.exec_count = 0
		t.total_time = 0*time.Nanosecond
	}
}

