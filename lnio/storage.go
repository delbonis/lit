package lnio

// LitStorage is an abstract wrapper layer around an arbitrary database.
type LitStorage interface {
	Open(string) error
	Close() error
	GetWalletDB(uint32) LitWalletStorage
	GetPeerDB() LitPeerStorage
	GetChannelDB() LitChannelStorage
}

// LitWalletStorage is storage for wallet data.
type LitWalletStorage interface {
	GetCoinType() uint32

	GetAddresses() ([][]byte, error)
	CreateNewAddress() ([]byte, error)

	GetUtxos() ([]Utxo, error)

	GetSyncHeight() (int32, error)

	AddWatchOutpoint(TxOut) error
	RemoveWatchOutput(TxOut) error

	// TODO More
}
