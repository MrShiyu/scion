package main

import (
	"time"

	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/border/digest"
)

const seq_num_range = digest.Seq_num_range


func SeqNumInc() {
	defer liblog.PanicLog()
	for range time.Tick(digest.SeqIncFreq) {
		if digest.D.Curr_seq_num< seq_num_range -1 {
			digest.D.Curr_seq_num++
		}else{
			digest.D.Curr_seq_num = 0
		}
	}
}

const rotateFreq = 121 *time.Millisecond

func BfRotate(){
	defer liblog.PanicLog()
	for range time.Tick(rotateFreq){
		digest.Rotate()
	}
}


func TTLcheck(){
	defer liblog.PanicLog()
	for range time.Tick(digest.TTLcheckFreq){
		for k,v := range digest.D.Seq_info{
			TTLoneAScheck(k,v)
		}
	}
}

func TTLoneAScheck(name string, conf *digest.Curr_seq){
	if conf.Valid {
		digest.D.Seq_info[name].TTL -= digest.TTLcheckFreq
		if conf.TTL <= 0{
			augmented := conf.TTL
			digest.TTLupdate(name,augmented)
			if digest.D.Seq_info[name].Seq_num< seq_num_range - 1 {
				digest.D.Seq_info[name].Seq_num++
			}else{
				digest.D.Seq_info[name].Seq_num = 0
			}
		}
	}
}