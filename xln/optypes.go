package xln

import (
	"fmt"
)

const (
	// OpTypePush is the push op type.
	OpTypePush = "push"
)

type optypepush struct {
}

func (*optypepush) Name() string {
	return OpTypePush
}

type oppush struct {
	Delta uint64
}

func (*oppush) TypeName() string {
	return OpTypePush
}

func (op *oppush) Apply(state *ChannelState) (*ChannelState, error) {

	s2 := state.Clone() // Make a copy of it, never modify the one passed in.

	p1 := s2.GetPartition("p1bal")
	p2 := s2.GetPartition("p2bal")

	// Verify they're both just "plain balances".
	if p1.Type != PartTypePeerBal || p2.Type != PartTypePeerBal {
		return nil, fmt.Errorf("unknown partition format")
	}

	// Apply the balance change, hopefully this is how Go's aliasing works.
	p1.Balance -= op.Delta
	p2.Balance += op.Delta

	return s2, nil

}
