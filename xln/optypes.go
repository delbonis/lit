package xln

import (
	"fmt"
)

type optypepush struct {
}

func (*optypepush) Name() string {
	return "push"
}

type oppush struct {
	Delta uint64
}

func (*oppush) TypeName() string {
	return "push"
}

func (op *oppush) Apply(state *ChannelState) (*ChannelState, error) {

	s2 := state.Clone() // Make a copy of it, never modify the one passed in.

	p1, ok := s2.GetPartition("p1bal").Data.(*partpeerbal)
	if !ok {
		return nil, fmt.Errorf("unknown partition layout")
	}

	p2, ok := s2.GetPartition("p2bal").Data.(*partpeerbal)
	if !ok {
		return nil, fmt.Errorf("unknown partition layout")
	}

	// Apply the balance change, hopefully this is how Go's aliasing works.
	p1.Balance -= op.Delta
	p2.Balance += op.Delta

	return s2, nil

}
