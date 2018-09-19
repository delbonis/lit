package qln

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/mit-dci/lit/btcutil/chaincfg/chainhash"
	"github.com/mit-dci/lit/crypto/koblitz"
	"github.com/mit-dci/lit/elkrem"
	"github.com/mit-dci/lit/lnutil"
	"github.com/mit-dci/lit/logging"
	"github.com/mit-dci/lit/portxo"
)

// Uhh, quick channel.  For now.  Once you get greater spire it upgrades to
// a full channel that can do everything.
type Qchan struct {
	// S for stored (on disk), D for derived

	ChanState *QchanState

	Delay uint16 // blocks for timeout (default 5 for testing)

	ClearToSend chan bool // send a true here when you get a rev
	ChanMtx     sync.Mutex
	// exists only in ram, doesn't touch disk

}

type QchanState struct {
	Txo       portxo.PorTxo `json:"txo"`       // underlying utxo data
	CloseData QCloseData    `json:"closedata"` // closing outpoint

	MyPub    []byte `json:"mpub"` // my channel specific pubkey
	TheirPub []byte `json:"opub"` // their channel specific pubkey

	MyRefundPub    []byte `json:"mrpub"` // my refund pubkey for channel break
	TheirRefundPub []byte `json:"orpub"` // their pubkey for channel break

	MyHakdBase    []byte `json:"mhakdbase"` // my base point for HAKD and timeout keys
	TheirHakdBase []byte `json:"ohakdbase"` // their base point for HAKD and timeout keys

	WatchRefundAddr []byte `json:"wraddr"` // PKH for penalty tx

	ElkSnd *elkrem.ElkremSender   `json:"elks"` // from channel specific key (for making elk stuff)
	ElkRcv *elkrem.ElkremReceiver `json:"elkr"` // stored in db

	Commitment *StatCom `json:"statecom"`

	LastUpdate uint64 `json:"updateunix"` // unix timestamp of last update (milliseconds)
}

// 4 + 1 + 8 + 32 + 4 + 33 + 33 + 1 + 5 + 32 + 64 = 217 bytes
type HTLC struct {
	Idx uint32 `json:"idx"`

	Incoming bool     `json:"incoming"`
	Amt      int64    `json:"amt"`
	RHash    [32]byte `json:"hash"`
	Locktime uint32   `json:"locktime"`

	MyHTLCBase    []byte `json:"mbase"`
	TheirHTLCBase []byte `json:"obase"`

	KeyGen portxo.KeyGen `json:"keygen"`

	Sig [64]byte `json:"sig"`

	R              [16]byte `json:"preimage"`
	Clearing       bool     `json:"clearing"`
	Cleared        bool     `json:"cleared"`
	ClearedOnChain bool     `json:"clearedchain"` // To keep track of what HTLCs we claimed on-chain
}

// StatComs are State Commitments.
// all elements are saved to the db.
type StatCom struct {
	StateIdx uint64 `json:"idx"` // this is the n'th state commitment

	WatchUpTo uint64 `json:"watchidx"` // have sent out to watchtowers up to this state  ( < stateidx)

	MyAmt int64 `json:"myamt"` // my channel allocation

	Fee int64 `json:"fee"` // symmetric fee in absolute satoshis

	Data [32]byte `json:"data"`

	// their Amt is the utxo.Value minus this
	Delta int32 `json:"delta"` // fund amount in-transit; is negative for the pusher
	// Delta for when the channel is in a collision state which needs to be resolved
	Collision int32 `json:"collision"`

	// Elkrem point from counterparty, used to make
	// Homomorphic Adversarial Key Derivation public keys (HAKD)
	ElkPoint     [33]byte `json:"elk0"` // saved to disk, current revealable point
	NextElkPoint [33]byte `json:"elk1"` // Point stored for next state
	N2ElkPoint   [33]byte `json:"elk2"` // Point for state after next (in case of collision)

	sig [64]byte `json:"sigother"` // Counterparty's signature for current state
	// don't write to sig directly; only overwrite via fn() call

	// note sig can be nil during channel creation. if stateIdx isn't 0,
	// sig should have a sig.
	// only one sig is ever stored, to prevent broadcasting the wrong tx.
	// could add a mutex here... maybe will later.

	HTLCIdx       uint32 `json:"htlcidx"`
	InProgHTLC    *HTLC  `json:"htlcinprog"`  // Current in progress HTLC
	CollidingHTLC *HTLC  `json:"htlccollide"` // HTLC for when the channel is colliding

	CollidingHashDelta     bool `json:"collhd"` // True when colliding between a DeltaSig and HashSig/PreImageSig
	CollidingHashPreimage  bool `json:"collhp"` // True when colliding between HashSig and PreimageSig
	CollidingPreimages     bool `json:"collpp"` // True when colliding between PreimageSig and PreimageSig
	CollidingPreimageDelta bool `json:"collpd"` // True when colliding between a DeltaSig and HashSig/PreImageSig

	// Analogous to the ElkPoints above but used for generating their pubkey for the HTLC
	NextHTLCBase [33]byte `json:"htlcbasenext"`
	N2HTLCBase   [33]byte `json:"htlcbasenext2"`

	MyNextHTLCBase [33]byte `json:"mhtlcbn"`
	MyN2HTLCBase   [33]byte `json:"mhtlcbn2"`

	// Any HTLCs associated with this channel state (can be nil)
	HTLCs []HTLC `json:"htlcs"`

	Failed bool `json:"failed"` // S there was a fatal error with the channel
	// meaning it cannot be used safely
}

// QCloseData is the output resulting from an un-cooperative close
// of the channel.  This happens when either party breaks non-cooperatively.
// It describes "your" output, either pkh or time-delay script.
// If you have pkh but can grab the other output, "grabbable" is set to true.
// This can be serialized in a separate bucket

type QCloseData struct {
	// 3 txid / height pairs are stored.  All 3 only are used in the
	// case where you grab their invalid close.
	CloseTxid   chainhash.Hash `json:"txid"`
	CloseHeight int32          `json:"height"`
	Closed      bool           `json:"closed"` // if channel is closed; if CloseTxid != -1
}

func NewQchan(cidx, pidx, ct uint32) *Qchan {
	qc := new(Qchan)
	qc.ChanState = new(QchanState)
	qc.ChanState.Commitment = new(StatCom)
	qc.ChanState.Commitment.ElkPoint = [33]byte{}
	qc.ChanState.Commitment.NextElkPoint = [33]byte{}
	qc.ChanState.Commitment.N2ElkPoint = [33]byte{}

	// elkrems
	elksroot := [32]byte{}
	qc.ChanState.ElkSnd = elkrem.NewElkremSender(elksroot)
	qc.ChanState.ElkRcv = elkrem.NewElkremReceiver()

	// FIXME This is not a particularly good way to do this.  It should be dependent on the coin driver.
	qc.ChanState.MyPub = make([]byte, 33)
	qc.ChanState.TheirPub = make([]byte, 33)
	qc.ChanState.MyRefundPub = make([]byte, 33)
	qc.ChanState.TheirRefundPub = make([]byte, 33)
	qc.ChanState.MyHakdBase = make([]byte, 33)
	qc.ChanState.TheirHakdBase = make([]byte, 33)
	qc.ChanState.WatchRefundAddr = make([]byte, 33)

	return qc
}

// ChannelInfo prints info about a channel.
func (nd *LitNode) QchanInfo(q *Qchan) error {
	// display txid instead of outpoint because easier to copy/paste
	logging.Infof("CHANNEL %s h:%d %s cap: %d\n",
		q.ChanState.Txo.Op.String(), q.ChanState.Txo.Height, q.ChanState.Txo.KeyGen.String(), q.ChanState.Txo.Value)
	logging.Infof("\tPUB mine:%x them:%x REFBASE mine:%x them:%x BASE mine:%x them:%x\n",
		q.ChanState.MyPub[:4], q.ChanState.TheirPub[:4], q.ChanState.MyRefundPub[:4], q.ChanState.TheirRefundPub[:4],
		q.ChanState.MyHakdBase[:4], q.ChanState.TheirHakdBase[:4])
	if q.ChanState.Commitment == nil || q.ChanState.ElkRcv == nil {
		logging.Errorf("\t no valid state or elkrem\n")
	} else {
		logging.Infof("\ta %d (them %d) state index %d\n",
			q.ChanState.Commitment.MyAmt, q.ChanState.Txo.Value-q.ChanState.Commitment.MyAmt, q.ChanState.Commitment.StateIdx)

		logging.Infof("\tdelta:%d HAKD:%x elk@ %d\n",
			q.ChanState.Commitment.Delta, q.ChanState.Commitment.ElkPoint[:4], q.ChanState.ElkRcv.UpTo())
		elkp, _ := q.ElkPoint(false, q.ChanState.Commitment.StateIdx)
		myRefPub := lnutil.AddPubsEZ(q.ChanState.MyRefundPub, elkp[:])
		theirRefPub := lnutil.AddPubsEZ(q.ChanState.TheirRefundPub, q.ChanState.Commitment.ElkPoint[:])
		logging.Infof("\tMy Refund: %x Their Refund %x\n", myRefPub[:4], theirRefPub[:4])
	}

	if !q.ChanState.CloseData.Closed { // still open, finish here
		return nil
	}

	logging.Infof("\tCLOSED at height %d by tx: %s\n",
		q.ChanState.CloseData.CloseHeight, q.ChanState.CloseData.CloseTxid.String())
	//	clTx, err := t.GetTx(&q.CloseData.CloseTxid)
	//	if err != nil {
	//		return err
	//	}
	//	ctxos, err := q.GetCloseTxos(clTx)
	//	if err != nil {
	//		return err
	//	}

	//	if len(ctxos) == 0 {
	//		logging.Infof("\tcooperative close.\n")
	//		return nil
	//	}

	//	logging.Infof("\tClose resulted in %d spendable txos\n", len(ctxos))
	//	if len(ctxos) == 2 {
	//		logging.Infof("\t\tINVALID CLOSE!!!11\n")
	//	}
	//	for i, u := range ctxos {
	//		logging.Infof("\t\t%d) amt: %d spendable: %d\n", i, u.Value, u.Seq)
	//	}
	return nil
}

// Peer returns the local peer index of the channel
func (q *Qchan) Peer() uint32 {
	if q == nil {
		return 0
	}
	return q.ChanState.Txo.KeyGen.Step[3] & 0x7fffffff
}

// Idx returns the local index of the channel
func (q *Qchan) Idx() uint32 {
	if q == nil {
		return 0
	}
	return q.ChanState.Txo.KeyGen.Step[4] & 0x7fffffff
}

// Coin returns the coin type of the channel
func (q *Qchan) Coin() uint32 {
	if q == nil {
		return 0
	}
	return q.ChanState.Txo.KeyGen.Step[1] & 0x7fffffff
}

// ImFirst decides who goes first when it's unclear.  Smaller pubkey goes first.
func (q *Qchan) ImFirst() bool {
	return bytes.Compare(q.ChanState.MyRefundPub[:], q.ChanState.TheirRefundPub[:]) == -1
}

// GetChanHint gives the 6 byte hint mask of the channel.  It's derived from the
// hash of the PKH output pubkeys.  "Mine" means the hint is in the tx I store.
// So it's actually a hint for them to decode... which is confusing, but consistent
// with the "mine" bool for transactions, so "my" tx has "my" hint.
// (1<<48 - 1 is the max valid value)
func (q *Qchan) GetChanHint(mine bool) uint64 {
	// could cache these in memory for a slight speedup
	var h []byte
	if mine {
		h = chainhash.DoubleHashB(append(q.ChanState.MyRefundPub[:], q.ChanState.TheirRefundPub[:]...))
	} else {
		h = chainhash.DoubleHashB(append(q.ChanState.TheirRefundPub[:], q.ChanState.MyRefundPub[:]...))
	}

	if len(h) != 32 {
		return 1 << 63
	}
	// get 6 bytes from that hash (leave top 2 bytes of return value empty)
	x := make([]byte, 8)

	copy(x[2:8], h[2:8])

	return lnutil.BtU64(x)
}

// GetDHSecret gets a per-channel shared secret from the Diffie-Helman of the
// two pubkeys in the fund tx.
func (nd *LitNode) GetDHSecret(q *Qchan) ([]byte, error) {
	if nd.SubWallet[q.Coin()] == nil {
		return nil, fmt.Errorf("Not connected to coin type %d\n", q.Coin())
	}
	if nd == nil || q == nil {
		return nil, fmt.Errorf("GetDHPoint: nil node or channel")
	}

	theirPub, err := koblitz.ParsePubKey(q.ChanState.TheirPub[:], koblitz.S256())
	if err != nil {
		return nil, err
	}
	priv, err := nd.SubWallet[q.Coin()].GetPriv(q.ChanState.Txo.KeyGen)
	// if this breaks, return
	if err != nil {
		return nil, err
	}

	return koblitz.GenerateSharedSecret(priv, theirPub), nil
}

// GetChannelBalances returns myAmt and theirAmt in the channel
// that aren't locked up in HTLCs in satoshis
func (q *Qchan) GetChannelBalances() (int64, int64) {
	value := q.ChanState.Txo.Value

	for _, h := range q.ChanState.Commitment.HTLCs {
		if !h.Cleared {
			value -= h.Amt
		}
	}

	myAmt := q.ChanState.Commitment.MyAmt
	theirAmt := value - myAmt

	return myAmt, theirAmt
}

// Bytes returns the byte representation of this qchanstate.
func (s *QchanState) Bytes() []byte {
	b, err := json.Marshal(s)
	if err != nil {
		return []byte{}
	}
	return []byte(b)
}

// QchanStateFromBytes returns a qchanstate if it can parse the bytes
// properly, or an error.
func QchanStateFromBytes(buf []byte) (*QchanState, error) {

	qcs := new(QchanState)
	err := json.Unmarshal(buf, qcs)

	if err != nil {
		return nil, err
	}

	return qcs, nil

}
