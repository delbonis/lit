package xln

import (
	"github.com/mit-dci/lit/lncore"
)

const (
	// PartTypePeerBal is a peer balance.
	PartTypePeerBal = "peerbal"
)

type partpeerbal struct {
	LnAddress lncore.LnAddr
}

func (*partpeerbal) TypeName() string {
	return PartTypePeerBal
}

func (part *partpeerbal) Clone() PartitionData {
	return &partpeerbal{
		LnAddress: part.LnAddress,
	}
}
