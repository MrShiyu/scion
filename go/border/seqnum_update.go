package main

import (
	"time"
	"fmt"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/border/digest"
)

// ifIDFreq is how often IFID packets are sent to the neighbouring AS.
const seqIncFreq = 10 * time.Millisecond


func SeqNumInc() {
	defer liblog.PanicLog()
	for range time.Tick(ifIDFreq) {
		if digest.D.Curr_seq_num< 20 {
			//FIXME: now set the range of seqnum to 0-20(to show that it gets reset to 0.) Can be changed
			digest.D.Curr_seq_num++
			s := fmt.Sprintf("sequence number gets incremented to %d", digest.D.Curr_seq_num)
			log.Debug(s)
		}else{
			digest.D.Curr_seq_num = 0
			log.Debug("seq num reset to 0")
		}
	}
}



