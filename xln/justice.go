package xln

import (
	"github.com/mit-dci/lit/wire"
)

// JusticeRule is how we know how to inoke justice.
type JusticeRule struct {

	// OnSee is txout we have to see on-chain before caring about this rule.
	OnSee wire.TxOut

	// Publish is the txin we should publish when invoking this rule.
	Publish wire.TxIn

	// MinHeight is the height at which we should invoke this rule, -1 for now.
	MinHeight int64
}
