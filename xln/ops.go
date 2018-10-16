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
	Apply(ChannelState) (ChannelState, error)
}
