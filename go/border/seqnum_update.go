package main

import (
	"time"
	"fmt"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/border/digest"
)

const seq_num_range = digest.Seq_num_range
//FIXME: now set the range of seqnum to 0-100(to show that it gets reset to 0.) Can be changed

func SeqNumInc() {
	defer liblog.PanicLog()
	for range time.Tick(digest.SeqIncFreq) {
		if digest.D.Curr_seq_num< seq_num_range {
			digest.D.Curr_seq_num++
			s := fmt.Sprintf("sequence number gets incremented to %d", digest.D.Curr_seq_num)
			log.Debug(s)
		}else{
			digest.D.Curr_seq_num = 0
			//log.Debug("seq num reset to 0")
		}
	}
}

const rotateFreq = 100 *time.Millisecond

func BfRotate(){
	defer liblog.PanicLog()
	for range time.Tick(rotateFreq){
		digest.Rotate()
	}
}

const TTLcheckFreq = 5*time.Millisecond

func TTLcheck(){
	defer liblog.PanicLog()
	for range time.Tick(TTLcheckFreq){
		for k,v := range digest.D.Seq_info{
			TTLoneAScheck(k,v)
		}
	}
}

func TTLoneAScheck(name string, conf *digest.Curr_seq){
	if conf.Valid {
		digest.D.Seq_info[name].TTL -= TTLcheckFreq
		//s:= fmt.Sprintf("the TTL after subtracting is %d", digest.D.Seq_info[name].TTL)
		//log.Debug(s)
		if conf.TTL <= 0{
			augmented := conf.TTL
			digest.TTLupdate(name,augmented)
			if digest.D.Seq_info[name].Seq_num< seq_num_range {
				digest.D.Seq_info[name].Seq_num++
				s := fmt.Sprintf("stored sequence number of AS %s gets incremented to %d", name, digest.D.Seq_info[name].Seq_num)
				log.Debug(s)
			}else{
				digest.D.Seq_info[name].Seq_num = 0
				s:= fmt.Sprintf("stored seq num of AS %s reset to 0", name)
				log.Debug(s)
			}
		}
	}
}