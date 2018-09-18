package qln

import (
	"sync"
)

// NewQchanFromState returns a new Qchan constructed from the state given.  Does
// it really make sense to have this here?
func NewQchanFromState(qcs QchanState) *Qchan {

	qc := Qchan{
		ChanState:   &qcs,
		Delay:       5, // Make this serailized later?
		ClearToSend: make(chan bool),
		ChanMtx:     sync.Mutex{},
	}

	return &qc

}
