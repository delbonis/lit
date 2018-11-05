package xln

import (
	"github.com/mit-dci/lit/crypto/koblitz"
	"github.com/mit-dci/lit/lncore"
)

// ChannelParticipant is a participant in a channel.
type ChannelParticipant struct {
	ReturnAddress []byte
}

// ChannelCtx is all of the information needed for a channel to exist.
type ChannelCtx struct {

	// Ident is just some random identifier.
	Ident string

	// RootKey is the root key for addresses we use in this channel.
	RootKey koblitz.PrivateKey

	// Participants is a map of LN addresses to participants in the channel.
	Partitipants map[lncore.LnAddr]ChannelParticipant

	// RootState is the first-level channel information.
	RootState ChannelState
}
