package qln

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/mit-dci/lit/logging"

	"github.com/mit-dci/lit/consts"
	"github.com/mit-dci/lit/lnutil"
	"github.com/mit-dci/lit/portxo"
)

// Grab the coins that are rightfully yours! Plus some more.
// For right now, spend all outputs from channel close.
//func Grab(args []string) error {
//	return SCon.GrabAll()
//}

/*

3 messages

pusher -> puller
DeltaSig: how much is being sent, and a signature for that state

pusher <- puller
SigRev: A signature and revocation of previous state

pusher -> puller
Rev: revocation

Every revocation contains the elkrem hash being revoked, and the next elkpoint.

SendNextMsg logic:

Message to send: channel state (sanity check)

DeltaSig:
delta < 0
you must be pushing.

SigRev:
delta > 0
you must be pulling.

Rev:
delta == 0
you must be done.

(note that puller also sends a (useless) rev once they've received the rev and
have their delta set to 0)

Note that when there's nothing to send, it'll send a REV message,
revoking the previous state which has already been revoked.

We could distinguish by writing to the db that we've sent the REV message...
but that doesn't seem that useful because we don't know if they got it so
we might have to send it again anyway.
*/

/*

2 options for dealing with push collision:
sequential and concurrent.
sequential has a deterministic priority which selects who to continue
the go-ahead node completes the push, then waits for the other node to push.

DeltaSig collision handling:

Send a DeltaSig.  Delta < 0.
Receive a DeltaSig with Delta < 0; need to send a GapSigRev
COLLISION: Set the collision flag (delta-(130))
update amount with increment from received deltaSig
verify received signature & save to disk, update state number
*your delta value stays the same*
Send GapSigRev: revocation of previous state, and sig for next state
Receive GapSigRev
Clear collision flag
set delta = -delta (turns positive)
Update amount,  verity received signature & save to disk, update state number
Send Rev for previous state
Receive Rev for previous state


*/

// SendNextMsg determines what message needs to be sent next
// based on the channel state.  It then calls the appropriate function.
func (nd *LitNode) ReSendMsg(qc *Qchan) error {

	// DeltaSig
	if qc.ChanState.Commitment.Delta < 0 {
		logging.Infof("Sending previously sent DeltaSig\n")
		return nd.SendDeltaSig(qc)
	}

	// SigRev
	if qc.ChanState.Commitment.Delta > 0 {
		logging.Infof("Sending previously sent SigRev\n")
		return nd.SendSigRev(qc)
	}

	// Rev
	return nd.SendREV(qc)
}

// PushChannel initiates a state update by sending a DeltaSig
func (nd *LitNode) PushChannel(qc *Qchan, amt uint32, data [32]byte) error {
	if qc.ChanState.Commitment.Failed {
		return fmt.Errorf("cannot push, channel failed")
	}

	// sanity checks
	if amt >= consts.MaxSendAmt {
		return fmt.Errorf("max send 1G sat (1073741823)")
	}
	if amt == 0 {
		return fmt.Errorf("have to send non-zero amount")
	}

	// see if channel is busy
	// lock this channel
	cts := false
	for !cts {
		qc.ChanMtx.Lock()
		select {
		case <-qc.ClearToSend:
			cts = true
		default:
			qc.ChanMtx.Unlock()
		}
	}
	// ClearToSend is now empty

	// reload from disk here, after unlock
	err := nd.ReloadQchanState(qc)
	if err != nil {
		// don't clear to send here; something is wrong with the channel
		nd.FailChannel(qc)
		qc.ChanMtx.Unlock()
		return err
	}

	// check that channel is confirmed, if non-test coin
	wal, ok := nd.SubWallet[qc.Coin()]
	if !ok {
		qc.ClearToSend <- true
		qc.ChanMtx.Unlock()
		return fmt.Errorf("Not connected to coin type %d\n", qc.Coin())
	}

	if !wal.Params().TestCoin && qc.ChanState.Txo.Height < 100 {
		qc.ClearToSend <- true
		qc.ChanMtx.Unlock()
		return fmt.Errorf(
			"height %d; must wait min 1 conf for non-test coin\n", qc.ChanState.Txo.Height)
	}

	myAmt, theirAmt := qc.GetChannelBalances()
	myAmt -= qc.ChanState.Commitment.Fee - int64(amt)
	theirAmt += int64(amt) - qc.ChanState.Commitment.Fee

	// check if this push would lower my balance below minBal
	if myAmt < consts.MinOutput {
		qc.ClearToSend <- true
		qc.ChanMtx.Unlock()
		return fmt.Errorf("want to push %s but %s available after %s fee and %s",
			lnutil.SatoshiColor(int64(amt)),
			lnutil.SatoshiColor(myAmt),
			lnutil.SatoshiColor(qc.ChanState.Commitment.Fee),
			lnutil.SatoshiColor(consts.MinOutput))
	}
	// check if this push is sufficient to get them above minBal
	if theirAmt < consts.MinOutput {
		qc.ClearToSend <- true
		qc.ChanMtx.Unlock()
		return fmt.Errorf(
			"pushing %s insufficient; counterparty bal %s fee %s MinOutput %s",
			lnutil.SatoshiColor(int64(amt)),
			lnutil.SatoshiColor(theirAmt),
			lnutil.SatoshiColor(qc.ChanState.Commitment.Fee),
			lnutil.SatoshiColor(consts.MinOutput))
	}

	// if we got here, but channel is not in rest state, try to fix it.
	if qc.ChanState.Commitment.Delta != 0 {
		nd.FailChannel(qc)
		qc.ChanMtx.Unlock()
		return fmt.Errorf("channel not in rest state")
	}

	qc.ChanState.Commitment.Data = data
	logging.Infof("Sending message %x", data)

	qc.ChanState.Commitment.Delta = int32(-amt)

	if qc.ChanState.Commitment.Delta == 0 {
		nd.FailChannel(qc)
		qc.ChanMtx.Unlock()
		return errors.New("PushChannel: Delta cannot be zero")
	}

	// save to db with ONLY delta changed
	err = nd.SaveQchanState(qc)
	qc.ChanState.LastUpdate = uint64(time.Now().UnixNano() / 1000)
	if err != nil {
		// don't clear to send here; something is wrong with the channel
		nd.FailChannel(qc)
		qc.ChanMtx.Unlock()
		return err
	}
	// move unlock to here so that delta is saved before

	logging.Infof("PushChannel: Sending DeltaSig")

	err = nd.SendDeltaSig(qc)
	if err != nil {
		// don't clear; something is wrong with the network
		qc.ChanMtx.Unlock()
		return err
	}

	logging.Infof("PushChannel: Done: sent DeltaSig")

	logging.Infof("got pre CTS... \n")
	// block until clear to send is full again
	qc.ChanMtx.Unlock()

	timeout := time.NewTimer(time.Second * consts.ChannelTimeout)

	cts = false
	for !cts {
		qc.ChanMtx.Lock()
		select {
		case <-qc.ClearToSend:
			cts = true
		case <-timeout.C:
			nd.FailChannel(qc)
			qc.ChanMtx.Unlock()
			return fmt.Errorf("channel failed: operation timed out")
		default:
			qc.ChanMtx.Unlock()
		}
	}

	logging.Infof("got post CTS... \n")
	// since we cleared with that statement, fill it again before returning
	qc.ClearToSend <- true
	qc.ChanMtx.Unlock()

	return nil
}

// SendDeltaSig initiates a push, sending the amount to be pushed and the new sig.
func (nd *LitNode) SendDeltaSig(q *Qchan) error {
	// increment state number, update balance, go to next elkpoint
	q.ChanState.Commitment.StateIdx++
	q.ChanState.Commitment.MyAmt += int64(q.ChanState.Commitment.Delta)
	q.ChanState.Commitment.ElkPoint = q.ChanState.Commitment.NextElkPoint
	q.ChanState.Commitment.NextElkPoint = q.ChanState.Commitment.N2ElkPoint
	// N2Elk is now invalid

	// make the signature to send over

	// TODO: There are extra signatures required now
	sig, HTLCSigs, err := nd.SignState(q)
	if err != nil {
		return err
	}

	if q.ChanState.Commitment.Delta == 0 {
		return errors.New("Delta cannot be zero")
	}

	outMsg := lnutil.NewDeltaSigMsg(q.Peer(), q.ChanState.Txo.Op, -q.ChanState.Commitment.Delta, sig, HTLCSigs, q.ChanState.Commitment.Data)

	logging.Infof("Sending DeltaSig: %v", outMsg)

	nd.tmpSendLitMsg(outMsg)

	return nil
}

// DeltaSigHandler takes in a DeltaSig and responds with a SigRev (normally)
// or a GapSigRev (if there's a collision)
// Leaves the channel either expecting a Rev (normally) or a GapSigRev (collision)
func (nd *LitNode) DeltaSigHandler(msg lnutil.DeltaSigMsg, qc *Qchan) error {
	logging.Infof("Got DeltaSig: %v", msg)

	var collision bool
	//incomingDelta := uint32(math.Abs(float64(msg.Delta))) //int32 (may be negative, but should not be)
	incomingDelta := msg.Delta

	// we should be clear to send when we get a deltaSig
	select {
	case <-qc.ClearToSend:
	// keep going, normal
	default:
		// collision
		collision = true
	}

	logging.Infof("COLLISION is (%t)\n", collision)

	// load state from disk
	err := nd.ReloadQchanState(qc)
	if err != nil {
		nd.FailChannel(qc)
		return fmt.Errorf("DeltaSigHandler ReloadQchan err %s", err.Error())
	}

	// TODO we should send a response that the channel is closed.
	// or offer to double spend with a cooperative close?
	// or update the remote node on closed channel status when connecting
	// TODO should disallow 'break' command when connected to the other node
	// or merge 'break' and 'close' UI so that it breaks when it can't
	// connect, and closes when it can.
	if qc.ChanState.CloseData.Closed {
		return fmt.Errorf("DeltaSigHandler err: %d, %d is closed.",
			qc.Peer(), qc.Idx())
	}

	clearingIdxs := make([]uint32, 0)
	for _, h := range qc.ChanState.Commitment.HTLCs {
		if h.Clearing {
			clearingIdxs = append(clearingIdxs, h.Idx)
		}
	}

	inProgHTLC := qc.ChanState.Commitment.InProgHTLC

	if collision {
		if qc.ChanState.Commitment.InProgHTLC != nil {
			// Collision between DeltaSig-HashSig
			// Remove the in prog HTLC for checking signatures,
			// add it back later to send gapsigrev
			qc.ChanState.Commitment.InProgHTLC = nil
			qc.ChanState.Commitment.CollidingHashDelta = true

			var kg portxo.KeyGen
			kg.Depth = 5
			kg.Step[0] = 44 | 1<<31
			kg.Step[1] = qc.Coin() | 1<<31
			kg.Step[2] = UseHTLCBase
			kg.Step[3] = qc.ChanState.Commitment.HTLCIdx + 2 | 1<<31
			kg.Step[4] = qc.Idx() | 1<<31

			qc.ChanState.Commitment.MyNextHTLCBase = qc.ChanState.Commitment.MyN2HTLCBase
			qc.ChanState.Commitment.MyN2HTLCBase, err = nd.GetUsePub(kg,
				UseHTLCBase)
		} else if len(clearingIdxs) > 0 {
			// Collision between DeltaSig-PreimageSig
			// Remove the clearing state for signature verification and
			// add back afterwards.
			for _, idx := range clearingIdxs {
				qh := &qc.ChanState.Commitment.HTLCs[idx]
				qh.Clearing = false
			}
			qc.ChanState.Commitment.CollidingPreimageDelta = true
		} else {
			// Collision between DeltaSig-DeltaSig

			// incoming delta saved as collision value,
			// existing (negative) delta value retained.
			qc.ChanState.Commitment.Collision = int32(incomingDelta)
			logging.Infof("delta sig COLLISION (%d)\n", qc.ChanState.Commitment.Collision)
		}
	}
	// detect if channel is already locked, and lock if not
	//	nd.PushClearMutex.Lock()
	//	if nd.PushClear[qc.Idx()] == nil {
	//		nd.PushClear[qc.Idx()] = make(chan bool, 1)
	//	} else {
	// this means there was a collision
	// reload from disk; collision may have happened after disk read
	//		err := nd.ReloadQchan(qc)
	//		if err != nil {
	//			return fmt.Errorf("DeltaSigHandler err %s", err.Error())
	//		}

	//	}

	if qc.ChanState.Commitment.Delta > 0 {
		logging.Infof(
			"DeltaSigHandler err: chan %d delta %d, expect rev, send empty rev",
			qc.Idx(), qc.ChanState.Commitment.Delta)

		return nd.SendREV(qc)
	}

	// If we collide with an HTLC operation, we can use the incoming Delta also.
	if !collision || qc.ChanState.Commitment.InProgHTLC != nil {
		// no collision, incoming (positive) delta saved.
		qc.ChanState.Commitment.Delta = int32(incomingDelta)
	}

	// they have to actually send you money
	if incomingDelta < 1 {
		nd.FailChannel(qc)
		return fmt.Errorf("DeltaSigHandler err: delta %d", incomingDelta)
	}

	myAmt, theirAmt := qc.GetChannelBalances()
	theirAmt -= int64(incomingDelta) + qc.ChanState.Commitment.Fee
	myAmt += int64(incomingDelta) - qc.ChanState.Commitment.Fee

	// check if this push is takes them below minimum output size
	if theirAmt < consts.MinOutput {
		nd.FailChannel(qc)
		return fmt.Errorf(
			"pushing %s reduces them too low; counterparty bal %s fee %s consts.MinOutput %s",
			lnutil.SatoshiColor(int64(incomingDelta)),
			lnutil.SatoshiColor(theirAmt),
			lnutil.SatoshiColor(qc.ChanState.Commitment.Fee),
			lnutil.SatoshiColor(consts.MinOutput))
	}

	// check if this push would lower my balance below minBal
	if myAmt < consts.MinOutput {
		nd.FailChannel(qc)
		return fmt.Errorf("want to push %s but %s available after %s fee and %s consts.MinOutput",
			lnutil.SatoshiColor(int64(incomingDelta)),
			lnutil.SatoshiColor(myAmt),
			lnutil.SatoshiColor(qc.ChanState.Commitment.Fee),
			lnutil.SatoshiColor(consts.MinOutput))
	}

	// update to the next state to verify
	qc.ChanState.LastUpdate = uint64(time.Now().UnixNano() / 1000)
	qc.ChanState.Commitment.StateIdx++
	// regardless of collision, raise amt
	qc.ChanState.Commitment.MyAmt += int64(incomingDelta)

	logging.Infof("Got message %x", msg.Data)
	qc.ChanState.Commitment.Data = msg.Data

	// verify sig for the next state. only save if this works
	stashElk := qc.ChanState.Commitment.ElkPoint
	qc.ChanState.Commitment.ElkPoint = qc.ChanState.Commitment.NextElkPoint
	// TODO: There are more signatures required
	err = qc.VerifySigs(msg.Signature, msg.HTLCSigs)
	if err != nil {
		nd.FailChannel(qc)
		return fmt.Errorf("DeltaSigHandler err %s", err.Error())
	}
	qc.ChanState.Commitment.ElkPoint = stashElk

	// After verification of signatures, add back the clearing state in case
	// of PreimageSig-DeltaSig collisions
	for _, idx := range clearingIdxs {
		qh := &qc.ChanState.Commitment.HTLCs[idx]
		qh.Clearing = true
	}

	qc.ChanState.Commitment.InProgHTLC = inProgHTLC
	// (seems odd, but everything so far we still do in case of collision, so
	// only check here.  If it's a collision, set, save, send gapSigRev

	// save channel with new state, new sig, and positive delta set
	// and maybe collision; still haven't checked
	err = nd.SaveQchanState(qc)
	if err != nil {
		nd.FailChannel(qc)
		return fmt.Errorf("DeltaSigHandler SaveQchanState err %s", err.Error())
	}

	if qc.ChanState.Commitment.Collision != 0 ||
		qc.ChanState.Commitment.CollidingHashDelta ||
		qc.ChanState.Commitment.CollidingPreimageDelta {
		err = nd.SendGapSigRev(qc)
		if err != nil {
			nd.FailChannel(qc)
			return fmt.Errorf("DeltaSigHandler SendGapSigRev err %s", err.Error())
		}
	} else { // saved to db, now proceed to create & sign their tx
		err = nd.SendSigRev(qc)
		if err != nil {
			nd.FailChannel(qc)
			return fmt.Errorf("DeltaSigHandler SendSigRev err %s", err.Error())
		}
	}
	return nil
}

// SendGapSigRev is different; it signs for state+1 and revokes state-1
func (nd *LitNode) SendGapSigRev(q *Qchan) error {
	// state should already be set to the "gap" state; generate signature for n+1
	// the signature generation is similar to normal sigrev signing
	// in these "send_whatever" methods we don't modify and save to disk

	// state has been incremented in DeltaSigHandler so n is the gap state
	// revoke n-1
	elk, err := q.ChanState.ElkSnd.AtIndex(q.ChanState.Commitment.StateIdx - 1)
	if err != nil {
		return err
	}

	// send elkpoint for n+2
	n2ElkPoint, err := q.N2ElkPointForThem()
	if err != nil {
		return err
	}

	// go up to n+2 elkpoint for the signing
	q.ChanState.Commitment.ElkPoint = q.ChanState.Commitment.N2ElkPoint
	// state is already incremented from DeltaSigHandler, increment *again* for n+1
	// (note that we've moved n here.)
	q.ChanState.Commitment.StateIdx++
	// amt is delta (negative) plus current amt (collision already added in)
	q.ChanState.Commitment.MyAmt += int64(q.ChanState.Commitment.Delta)

	if q.ChanState.Commitment.InProgHTLC != nil {
		if !q.ChanState.Commitment.InProgHTLC.Incoming {
			q.ChanState.Commitment.MyAmt -= q.ChanState.Commitment.InProgHTLC.Amt
		}
	}

	if q.ChanState.Commitment.CollidingHTLC != nil {
		if !q.ChanState.Commitment.CollidingHTLC.Incoming {
			q.ChanState.Commitment.MyAmt -= q.ChanState.Commitment.CollidingHTLC.Amt
		}
	}

	for _, h := range q.ChanState.Commitment.HTLCs {
		if h.Clearing && !h.Cleared && (h.Incoming != (h.R == [16]byte{})) {
			q.ChanState.Commitment.MyAmt += h.Amt
		}
	}

	// sign state n+1

	// TODO: send the sigs
	sig, HTLCSigs, err := nd.SignState(q)
	if err != nil {
		return err
	}

	// send
	// GapSigRev is op (36), sig (64), ElkHash (32), NextElkPoint (33)
	// total length 165

	outMsg := lnutil.NewGapSigRev(q.Peer(), q.ChanState.Txo.Op, sig, *elk, n2ElkPoint, HTLCSigs, q.ChanState.Commitment.MyN2HTLCBase)

	logging.Infof("Sending GapSigRev: %v", outMsg)

	nd.tmpSendLitMsg(outMsg)

	return nil
}

// SendSigRev sends a SigRev message based on channel info
func (nd *LitNode) SendSigRev(q *Qchan) error {

	// revoke n-1
	elk, err := q.ChanState.ElkSnd.AtIndex(q.ChanState.Commitment.StateIdx - 1)
	if err != nil {
		return err
	}

	// state number and balance has already been updated if the incoming sig worked.
	// go to next elkpoint for signing
	// note that we have to keep the old elkpoint on disk for when the rev comes in
	q.ChanState.Commitment.ElkPoint = q.ChanState.Commitment.NextElkPoint
	// q.State.NextElkPoint = q.State.N2ElkPoint // not needed
	// n2elk invalid here

	// TODO: send the sigs
	sig, HTLCSigs, err := nd.SignState(q)
	if err != nil {
		return err
	}

	// send commitment elkrem point for next round of messages
	n2ElkPoint, err := q.N2ElkPointForThem()
	if err != nil {
		return err
	}

	outMsg := lnutil.NewSigRev(q.Peer(), q.ChanState.Txo.Op, sig, *elk, n2ElkPoint, HTLCSigs, q.ChanState.Commitment.MyN2HTLCBase)

	logging.Infof("Sending SigRev: %v", outMsg)

	nd.tmpSendLitMsg(outMsg)
	return nil
}

// GapSigRevHandler takes in a GapSigRev, responds with a Rev, and
// leaves the channel in a state expecting a Rev.
func (nd *LitNode) GapSigRevHandler(msg lnutil.GapSigRevMsg, q *Qchan) error {
	logging.Infof("Got GapSigRev: %v", msg)

	// load qchan & state from DB
	err := nd.ReloadQchanState(q)
	if err != nil {
		nd.FailChannel(q)
		return fmt.Errorf("GapSigRevHandler err %s", err.Error())
	}

	// check if we're supposed to get a GapSigRev now. Collision should be set
	if q.ChanState.Commitment.Collision == 0 &&
		q.ChanState.Commitment.CollidingHTLC == nil &&
		!q.ChanState.Commitment.CollidingHashPreimage &&
		!q.ChanState.Commitment.CollidingHashDelta &&
		!q.ChanState.Commitment.CollidingPreimageDelta &&
		!q.ChanState.Commitment.CollidingPreimages {
		nd.FailChannel(q)
		return fmt.Errorf(
			"chan %d got GapSigRev but collision = 0, collidingHTLC = nil, commitment.CollidingHashPreimage = %t, commitment.CollidingHashDelta = %t, commitment.CollidingPreimages = %t, commitment.CollidingPreimageDelta = %t, delta = %d",
			q.Idx(),
			q.ChanState.Commitment.CollidingHashPreimage,
			q.ChanState.Commitment.CollidingHashDelta,
			q.ChanState.Commitment.CollidingPreimages,
			q.ChanState.Commitment.CollidingPreimageDelta,
			q.ChanState.Commitment.Delta)
	}

	// stash for justice tx
	prevAmt := q.ChanState.Commitment.MyAmt - int64(q.ChanState.Commitment.Collision) // myAmt before collision

	q.ChanState.Commitment.MyAmt += int64(q.ChanState.Commitment.Delta) // delta should be negative
	q.ChanState.Commitment.Delta = q.ChanState.Commitment.Collision     // now delta is positive
	q.ChanState.Commitment.Collision = 0

	if q.ChanState.Commitment.InProgHTLC != nil {
		if !q.ChanState.Commitment.InProgHTLC.Incoming {
			q.ChanState.Commitment.MyAmt -= q.ChanState.Commitment.InProgHTLC.Amt
		}
	}

	if q.ChanState.Commitment.CollidingHTLC != nil {
		if !q.ChanState.Commitment.CollidingHTLC.Incoming {
			q.ChanState.Commitment.MyAmt -= q.ChanState.Commitment.CollidingHTLC.Amt
		}
	}

	for _, h := range q.ChanState.Commitment.HTLCs {
		if h.Clearing && !h.Cleared && (h.Incoming != (h.R == [16]byte{})) {
			q.ChanState.Commitment.MyAmt += h.Amt
		}
	}

	// verify elkrem and save it in ram
	err = q.AdvanceElkrem(&msg.Elk, msg.N2ElkPoint)
	if err != nil {
		nd.FailChannel(q)
		return fmt.Errorf("GapSigRevHandler err %s", err.Error())
		// ! non-recoverable error, need to close the channel here.
	}

	// go up to n+2 elkpoint for the sig verification
	stashElkPoint := q.ChanState.Commitment.ElkPoint
	q.ChanState.Commitment.ElkPoint = q.ChanState.Commitment.NextElkPoint

	// state is already incremented from DeltaSigHandler, increment again for n+2
	// (note that we've moved n here.)
	q.ChanState.Commitment.StateIdx++
	q.ChanState.LastUpdate = uint64(time.Now().UnixNano() / 1000)

	// verify the sig

	// TODO: More sigs here that before
	err = q.VerifySigs(msg.Signature, msg.HTLCSigs)
	if err != nil {
		nd.FailChannel(q)
		return fmt.Errorf("GapSigRevHandler err %s", err.Error())
	}
	// go back to sequential elkpoints
	q.ChanState.Commitment.ElkPoint = stashElkPoint

	if !bytes.Equal(msg.N2HTLCBase[:], q.ChanState.Commitment.N2HTLCBase[:]) {
		q.ChanState.Commitment.NextHTLCBase = q.ChanState.Commitment.N2HTLCBase
		q.ChanState.Commitment.N2HTLCBase = msg.N2HTLCBase
	}

	// If we were colliding, advance HTLCBase here.
	if q.ChanState.Commitment.CollidingHTLC != nil {
		var kg portxo.KeyGen
		kg.Depth = 5
		kg.Step[0] = 44 | 1<<31
		kg.Step[1] = q.Coin() | 1<<31
		kg.Step[2] = UseHTLCBase
		kg.Step[3] = q.ChanState.Commitment.HTLCIdx + 3 | 1<<31
		kg.Step[4] = q.Idx() | 1<<31

		q.ChanState.Commitment.MyNextHTLCBase = q.ChanState.Commitment.MyN2HTLCBase
		q.ChanState.Commitment.MyN2HTLCBase, err = nd.GetUsePub(kg, UseHTLCBase)
		if err != nil {
			nd.FailChannel(q)
			return err
		}
	}

	err = nd.SaveQchanState(q)
	if err != nil {
		nd.FailChannel(q)
		return fmt.Errorf("GapSigRevHandler err %s", err.Error())
	}
	err = nd.SendREV(q)
	if err != nil {
		nd.FailChannel(q)
		return fmt.Errorf("GapSigRevHandler err %s", err.Error())
	}

	// for justice, have to create signature for n-2.  Remember the n-2 amount

	q.ChanState.Commitment.StateIdx -= 2
	q.ChanState.Commitment.MyAmt = prevAmt

	err = nd.BuildJusticeSig(q)
	if err != nil {
		logging.Infof("GapSigRevHandler BuildJusticeSig err %s", err.Error())
	}

	return nil
}

// SIGREVHandler takes in a SIGREV and responds with a REV (if everything goes OK)
// Leaves the channel in a clear / rest state.
func (nd *LitNode) SigRevHandler(msg lnutil.SigRevMsg, qc *Qchan) error {
	logging.Infof("Got SigRev: %v", msg)

	// load qchan & state from DB
	err := nd.ReloadQchanState(qc)
	if err != nil {
		nd.FailChannel(qc)
		return fmt.Errorf("SIGREVHandler err %s", err.Error())
	}

	// check if we're supposed to get a SigRev now. Delta should be negative
	if qc.ChanState.Commitment.Delta > 0 {
		nd.FailChannel(qc)
		return fmt.Errorf("SIGREVHandler err: chan %d got SigRev, expect Rev. delta %d",
			qc.Idx(), qc.ChanState.Commitment.Delta)
	}

	var clearing bool
	for _, h := range qc.ChanState.Commitment.HTLCs {
		if h.Clearing {
			clearing = true
			break
		}
	}

	if qc.ChanState.Commitment.Delta == 0 && qc.ChanState.Commitment.InProgHTLC == nil && !clearing {
		// re-send last rev; they probably didn't get it
		err = nd.SendREV(qc)
		if err != nil {
			nd.FailChannel(qc)
		}
		return err
	}

	if qc.ChanState.Commitment.Collision != 0 || qc.ChanState.Commitment.CollidingHTLC != nil {
		nd.FailChannel(qc)
		return fmt.Errorf("chan %d got SigRev, expect GapSigRev delta %d col %d",
			qc.Idx(), qc.ChanState.Commitment.Delta, qc.ChanState.Commitment.Collision)
	}

	// stash previous amount here for watchtower sig creation
	prevAmt := qc.ChanState.Commitment.MyAmt

	qc.ChanState.Commitment.StateIdx++
	qc.ChanState.Commitment.MyAmt += int64(qc.ChanState.Commitment.Delta)
	qc.ChanState.Commitment.Delta = 0

	if qc.ChanState.Commitment.InProgHTLC != nil {
		if !qc.ChanState.Commitment.InProgHTLC.Incoming {
			qc.ChanState.Commitment.MyAmt -= qc.ChanState.Commitment.InProgHTLC.Amt
		}
	}

	if qc.ChanState.Commitment.CollidingHTLC != nil {
		if !qc.ChanState.Commitment.CollidingHTLC.Incoming {
			qc.ChanState.Commitment.MyAmt -= qc.ChanState.Commitment.CollidingHTLC.Amt
		}
	}

	for _, h := range qc.ChanState.Commitment.HTLCs {
		if h.Clearing && !h.Cleared {
			/*
				Incoming:
					Timeout:
						They get money
					Success:
						We get money
				!Incoming:
					Timeout:
						We get money
					Success:
						They get money
			*/

			if (h.Incoming && h.R != [16]byte{}) || (!h.Incoming && h.R == [16]byte{}) {
				qc.ChanState.Commitment.MyAmt += h.Amt
			}
		}
	}

	// first verify sig.
	// (if elkrem ingest fails later, at least we close out with a bit more money)

	// TODO: more sigs here than before
	curElk := qc.ChanState.Commitment.ElkPoint
	qc.ChanState.Commitment.ElkPoint = qc.ChanState.Commitment.NextElkPoint
	err = qc.VerifySigs(msg.Signature, msg.HTLCSigs)
	if err != nil {
		nd.FailChannel(qc)
		return fmt.Errorf("SIGREVHandler err %s", err.Error())
	}
	qc.ChanState.Commitment.ElkPoint = curElk

	// verify elkrem and save it in ram
	err = qc.AdvanceElkrem(&msg.Elk, msg.N2ElkPoint)
	if err != nil {
		nd.FailChannel(qc)
		return fmt.Errorf("SIGREVHandler err %s", err.Error())
		// ! non-recoverable error, need to close the channel here.
	}
	// if the elkrem failed but sig didn't... we should update the DB to reflect
	// that and try to close with the incremented amount, why not.
	// TODO Implement that later though.

	if qc.ChanState.Commitment.InProgHTLC != nil || qc.ChanState.Commitment.CollidingHashDelta {
		var kg portxo.KeyGen
		kg.Depth = 5
		kg.Step[0] = 44 | 1<<31
		kg.Step[1] = qc.Coin() | 1<<31
		kg.Step[2] = UseHTLCBase
		kg.Step[3] = qc.ChanState.Commitment.HTLCIdx + 2 | 1<<31
		kg.Step[4] = qc.Idx() | 1<<31

		qc.ChanState.Commitment.MyNextHTLCBase = qc.ChanState.Commitment.MyN2HTLCBase
		qc.ChanState.Commitment.MyN2HTLCBase, err = nd.GetUsePub(kg,
			UseHTLCBase)

		if err != nil {
			nd.FailChannel(qc)
			return err
		}
	}

	if qc.ChanState.Commitment.InProgHTLC != nil {
		qc.ChanState.Commitment.HTLCs = append(qc.ChanState.Commitment.HTLCs, *qc.ChanState.Commitment.InProgHTLC)
		qc.ChanState.Commitment.InProgHTLC = nil
		qc.ChanState.Commitment.NextHTLCBase = qc.ChanState.Commitment.N2HTLCBase
		qc.ChanState.Commitment.N2HTLCBase = msg.N2HTLCBase

		qc.ChanState.Commitment.HTLCIdx++
	}

	for idx, h := range qc.ChanState.Commitment.HTLCs {
		if h.Clearing && !h.Cleared {
			qc.ChanState.Commitment.HTLCs[idx].Cleared = true
		}
	}

	// all verified; Save finished state to DB, puller is pretty much done.
	err = nd.SaveQchanState(qc)
	if err != nil {
		nd.FailChannel(qc)
		return fmt.Errorf("SIGREVHandler err %s", err.Error())
	}

	logging.Infof("SIGREV OK, state %d, will send REV\n", qc.ChanState.Commitment.StateIdx)
	err = nd.SendREV(qc)
	if err != nil {
		nd.FailChannel(qc)
		return fmt.Errorf("SIGREVHandler err %s", err.Error())
	}

	/*
		Re-enable this if you want to print out the break TX for old states.
		You can use this to debug justice. Don't enable in production since these
		things can screw someone up if someone else maliciously grabs their log file

		err = nd.PrintBreakTxForDebugging(qc)
		if err != nil {
			return fmt.Errorf("SIGREVHandler err %s", err.Error())
		}
	*/

	// now that we've saved & sent everything, before ending the function, we
	// go BACK to create a txid/sig pair for watchtower.  This feels like a kindof
	// weird way to do it.  Maybe there's a better way.

	qc.ChanState.Commitment.StateIdx--
	qc.ChanState.Commitment.MyAmt = prevAmt

	err = nd.BuildJusticeSig(qc)
	if err != nil {
		logging.Infof("SigRevHandler BuildJusticeSig err %s", err.Error())
	}

	// done updating channel, no new messages expected.  Set clear to send
	qc.ClearToSend <- true

	return nil
}

// SendREV sends a REV message based on channel info
func (nd *LitNode) SendREV(q *Qchan) error {
	// revoke previous already built state
	elk, err := q.ChanState.ElkSnd.AtIndex(q.ChanState.Commitment.StateIdx - 1)
	if err != nil {
		return err
	}
	// send commitment elkrem point for next round of messages
	n2ElkPoint, err := q.N2ElkPointForThem()
	if err != nil {
		return err
	}

	outMsg := lnutil.NewRevMsg(q.Peer(), q.ChanState.Txo.Op, *elk, n2ElkPoint, q.ChanState.Commitment.MyN2HTLCBase)

	logging.Infof("Sending Rev: %v", outMsg)

	nd.tmpSendLitMsg(outMsg)

	return err
}

// REVHandler takes in a REV and clears the state's prev HAKD.  This is the
// final message in the state update process and there is no response.
// Leaves the channel in a clear / rest state.
func (nd *LitNode) RevHandler(msg lnutil.RevMsg, qc *Qchan) error {
	logging.Infof("Got Rev: %v", msg)

	// load qchan & state from DB
	err := nd.ReloadQchanState(qc)
	if err != nil {
		nd.FailChannel(qc)
		return fmt.Errorf("REVHandler err %s", err.Error())
	}

	var clearing bool
	for _, h := range qc.ChanState.Commitment.HTLCs {
		if h.Clearing {
			clearing = true
			break
		}
	}

	// check if there's nothing for them to revoke
	if qc.ChanState.Commitment.Delta == 0 && qc.ChanState.Commitment.InProgHTLC == nil && !clearing {
		return fmt.Errorf("got REV, expected deltaSig, ignoring.")
	}
	// maybe this is an unexpected rev, asking us for a rev repeat
	if qc.ChanState.Commitment.Delta < 0 {
		logging.Infof("got Rev, expected SigRev.  Re-sending last REV.\n")
		return nd.SendREV(qc)
	}

	// verify elkrem
	err = qc.AdvanceElkrem(&msg.Elk, msg.N2ElkPoint)
	if err != nil {
		nd.FailChannel(qc)
		logging.Errorf(" ! non-recoverable error, need to close the channel here.\n")
		return fmt.Errorf("REVHandler err %s", err.Error())
	}
	prevAmt := qc.ChanState.Commitment.MyAmt - int64(qc.ChanState.Commitment.Delta)
	qc.ChanState.Commitment.Delta = 0
	qc.ChanState.LastUpdate = uint64(time.Now().UnixNano() / 1000)

	if !bytes.Equal(msg.N2HTLCBase[:], qc.ChanState.Commitment.N2HTLCBase[:]) {
		qc.ChanState.Commitment.NextHTLCBase = qc.ChanState.Commitment.N2HTLCBase
		qc.ChanState.Commitment.N2HTLCBase = msg.N2HTLCBase
	}
	// Clear collision state for HashSig-DeltaSig
	qc.ChanState.Commitment.CollidingHashDelta = false
	// Clear collision state for HashSig-PreimageSig
	qc.ChanState.Commitment.CollidingHashPreimage = false
	qc.ChanState.Commitment.CollidingPreimages = false
	qc.ChanState.Commitment.CollidingPreimageDelta = false

	if qc.ChanState.Commitment.InProgHTLC != nil {
		qc.ChanState.Commitment.HTLCs = append(qc.ChanState.Commitment.HTLCs, *qc.ChanState.Commitment.InProgHTLC)
		qc.ChanState.Commitment.InProgHTLC = nil
		qc.ChanState.Commitment.HTLCIdx++
	}

	if qc.ChanState.Commitment.CollidingHTLC != nil {
		qc.ChanState.Commitment.HTLCs = append(qc.ChanState.Commitment.HTLCs, *qc.ChanState.Commitment.CollidingHTLC)
		qc.ChanState.Commitment.CollidingHTLC = nil
		qc.ChanState.Commitment.HTLCIdx++
	}

	for idx, h := range qc.ChanState.Commitment.HTLCs {
		if h.Clearing && !h.Cleared {
			qc.ChanState.Commitment.HTLCs[idx].Cleared = true

			nd.MultihopMutex.Lock()
			defer nd.MultihopMutex.Unlock()
			for i, mu := range nd.InProgMultihop {
				if bytes.Equal(mu.HHash[:], h.RHash[:]) && !mu.Succeeded {
					nd.InProgMultihop[i].Succeeded = true
					nd.InProgMultihop[i].PreImage = h.R
					err = nd.SaveMultihopPayment(nd.InProgMultihop[i])
					if err != nil {
						return err
					}
				}
			}
		}
	}

	// save to DB (new elkrem & point, delta zeroed)
	err = nd.SaveQchanState(qc)
	if err != nil {
		nd.FailChannel(qc)
		return fmt.Errorf("REVHandler err %s", err.Error())
	}

	/*
		Re-enable this if you want to print out the break TX for old states.
		You can use this to debug justice. Don't enable in production since these
		things can screw someone up if someone else maliciously grabs their log file

		err = nd.PrintBreakTxForDebugging(qc)
		if err != nil {
			return fmt.Errorf("SIGREVHandler err %s", err.Error())
		}
	*/

	// after saving cleared updated state, go back to previous state and build
	// the justice signature
	qc.ChanState.Commitment.StateIdx--      // back one state
	qc.ChanState.Commitment.MyAmt = prevAmt // use stashed previous state amount
	err = nd.BuildJusticeSig(qc)
	if err != nil {
		logging.Errorf("RevHandler BuildJusticeSig err %s", err.Error())
	}

	// got rev, assert clear to send
	qc.ClearToSend <- true

	logging.Infof("REV OK, state %d all clear.\n", qc.ChanState.Commitment.StateIdx)
	return nil
}

// FailChannel sets the fail flag on the channel and attempts to save it
func (nd *LitNode) FailChannel(q *Qchan) {
	nd.ReloadQchanState(q)
	q.ChanState.Commitment.Failed = true
	nd.SaveQchanState(q)
}
