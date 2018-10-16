package xln

import (
	"github.com/mit-dci/lit/crypto/koblitz"
	"github.com/mit-dci/lit/lncore"
	"github.com/mit-dci/lit/wire"
)

// ChannelCtx is all of the information needed for a channel to exist.
type ChannelCtx struct {

	// Ident is just some random identifier.
	Ident string

	// RootKey is the root key for addresses we use in this channel.
	RootKey koblitz.PrivateKey

	// CounterpartyAddr is the LN address of the remote peer.
	CounterpartyAddr lncore.LnAddr

	// RootState is the first-level channel information.
	RootState ChannelState

	// where should we store the root key?
}

// ChannelState is the actual state used to derive signatures.
type ChannelState struct {
	Num        uint64
	Partitions []ChannelPartition
}

// GetPartition searches the channel's partitions.
func (cs *ChannelState) GetPartition(id string) *ChannelPartition {
	for _, p := range cs.Partitions {
		if p.Ident == id {
			return &p
		}
	}
	return nil
}

// ApplyTransition applies a list of operations to this channel state.  If there
// is an error it will return the index of the operation that errored and the
// error that it returned when attempting to apply it.
func (cs *ChannelState) ApplyTransition(ops []ChannelOp) (*ChannelState, int, error) {

	cur := cs.Clone()
	for i, op := range ops {
		next, err := op.Apply(cur)
		if err != nil {
			return nil, i, err
		}
		cur = next
	}

	return &cur, -1, nil

}

// Clone returns a new deep copy of this
func (cs *ChannelState) Clone() ChannelState {
	nparts := make([]ChannelPartition, len(cs.Partitions))
	for i := range cs.Partitions {
		nparts[i] = cs.Partitions[i].Clone()
	}

	return ChannelState{
		Num:        cs.Num,
		Partitions: nparts,
	}
}

// ChannelPartition represents
type ChannelPartition struct {

	// Ident is just a unique identifier, like "p1bal"
	Ident string

	// Type is which type of partiton this is, like "refund" or "htlc".
	Type string

	// Data is the important information for properly generating txouts.
	Data PartitionData
}

// Clone returns a new deep copy of this partition.
func (cp *ChannelPartition) Clone() ChannelPartition {
	return ChannelPartition{
		Ident: cp.Ident,
		Type:  cp.Type,
		Data:  cp.Data.Clone(),
	}
}

// PartitionType is something to represent
type PartitionType interface {

	// Name is the name of this type of partiton, like "balance" or "htlc".
	Name() string

	// Serialize takes some PartitionData and makes it into something on-disk.
	Serialize(PartitionData) ([]byte, error)

	// Deserialize is the reverse of the above.
	Deserialize([]byte) (PartitionData, error)

	// GenerateTxouts returns any/all txouts that should be made for this partition, might not be broadcast directly.
	GenerateTxouts(PartitionData) ([]wire.TxOut, error)
}

// PartitionData is the actual data for a partition.
type PartitionData interface {
	// TypeName returns what the .Name() of this data's PartitionType returns.
	TypeName() string

	// Clone returns a new deep copy of this partition data.
	Clone() PartitionData
}
