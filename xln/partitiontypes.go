package xln

type partpeerbal struct {
	Pubkey  []byte
	Balance uint64
}

func (*partpeerbal) TypeName() string {
	return "peerbal"
}

func (part *partpeerbal) Clone() PartitionData {
	npk := make([]byte, len(part.Pubkey))
	copy(npk, part.Pubkey)
	return &partpeerbal{
		Pubkey:  npk,
		Balance: part.Balance,
	}
}
