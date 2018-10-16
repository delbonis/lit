package xln

// OpType is some type of operation that can be done to some channel state.
type OpType interface {
	Name() string
	Serialize(ChannelOp) ([]byte, error)
	Deserialize([]byte) (ChannelOp, error)
}

// ChannelOp is an operation that can be done to a channel.
type ChannelOp interface {
	TypeName() string

	// Apply takes a channel state and returns a new channel state with the operation applied to it.
	// TODO Needs some external context here so that you can't make a "push" that takes a bunch of money from the other party.
	Apply(*ChannelState) (*ChannelState, error)

	// IsSecret is a flag if this operation shouldn't be told to the other party
	// until actually signing the transaction, for things like applying
	// preimages to channels to settle and HTLC.
	IsSecret() bool
}
