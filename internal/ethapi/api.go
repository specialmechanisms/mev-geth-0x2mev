// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package ethapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/accounts/scwallet"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/sha3"
)

// EthereumAPI provides an API to access Ethereum related information.
type EthereumAPI struct {
	b Backend
}

// NewEthereumAPI creates a new Ethereum protocol API.
func NewEthereumAPI(b Backend) *EthereumAPI {
	return &EthereumAPI{b}
}

// GasPrice returns a suggestion for a gas price for legacy transactions.
func (s *EthereumAPI) GasPrice(ctx context.Context) (*hexutil.Big, error) {
	tipcap, err := s.b.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, err
	}
	if head := s.b.CurrentHeader(); head.BaseFee != nil {
		tipcap.Add(tipcap, head.BaseFee)
	}
	return (*hexutil.Big)(tipcap), err
}

// MaxPriorityFeePerGas returns a suggestion for a gas tip cap for dynamic fee transactions.
func (s *EthereumAPI) MaxPriorityFeePerGas(ctx context.Context) (*hexutil.Big, error) {
	tipcap, err := s.b.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, err
	}
	return (*hexutil.Big)(tipcap), err
}

type feeHistoryResult struct {
	OldestBlock  *hexutil.Big     `json:"oldestBlock"`
	Reward       [][]*hexutil.Big `json:"reward,omitempty"`
	BaseFee      []*hexutil.Big   `json:"baseFeePerGas,omitempty"`
	GasUsedRatio []float64        `json:"gasUsedRatio"`
}

// FeeHistory returns the fee market history.
func (s *EthereumAPI) FeeHistory(ctx context.Context, blockCount math.HexOrDecimal64, lastBlock rpc.BlockNumber, rewardPercentiles []float64) (*feeHistoryResult, error) {
	oldest, reward, baseFee, gasUsed, err := s.b.FeeHistory(ctx, uint64(blockCount), lastBlock, rewardPercentiles)
	if err != nil {
		return nil, err
	}
	results := &feeHistoryResult{
		OldestBlock:  (*hexutil.Big)(oldest),
		GasUsedRatio: gasUsed,
	}
	if reward != nil {
		results.Reward = make([][]*hexutil.Big, len(reward))
		for i, w := range reward {
			results.Reward[i] = make([]*hexutil.Big, len(w))
			for j, v := range w {
				results.Reward[i][j] = (*hexutil.Big)(v)
			}
		}
	}
	if baseFee != nil {
		results.BaseFee = make([]*hexutil.Big, len(baseFee))
		for i, v := range baseFee {
			results.BaseFee[i] = (*hexutil.Big)(v)
		}
	}
	return results, nil
}

// Syncing returns false in case the node is currently not syncing with the network. It can be up-to-date or has not
// yet received the latest block headers from its pears. In case it is synchronizing:
// - startingBlock: block number this node started to synchronize from
// - currentBlock:  block number this node is currently importing
// - highestBlock:  block number of the highest block header this node has received from peers
// - pulledStates:  number of state entries processed until now
// - knownStates:   number of known state entries that still need to be pulled
func (s *EthereumAPI) Syncing() (interface{}, error) {
	progress := s.b.SyncProgress()

	// Return not syncing if the synchronisation already completed
	if progress.CurrentBlock >= progress.HighestBlock {
		return false, nil
	}
	// Otherwise gather the block sync stats
	return map[string]interface{}{
		"startingBlock":       hexutil.Uint64(progress.StartingBlock),
		"currentBlock":        hexutil.Uint64(progress.CurrentBlock),
		"highestBlock":        hexutil.Uint64(progress.HighestBlock),
		"syncedAccounts":      hexutil.Uint64(progress.SyncedAccounts),
		"syncedAccountBytes":  hexutil.Uint64(progress.SyncedAccountBytes),
		"syncedBytecodes":     hexutil.Uint64(progress.SyncedBytecodes),
		"syncedBytecodeBytes": hexutil.Uint64(progress.SyncedBytecodeBytes),
		"syncedStorage":       hexutil.Uint64(progress.SyncedStorage),
		"syncedStorageBytes":  hexutil.Uint64(progress.SyncedStorageBytes),
		"healedTrienodes":     hexutil.Uint64(progress.HealedTrienodes),
		"healedTrienodeBytes": hexutil.Uint64(progress.HealedTrienodeBytes),
		"healedBytecodes":     hexutil.Uint64(progress.HealedBytecodes),
		"healedBytecodeBytes": hexutil.Uint64(progress.HealedBytecodeBytes),
		"healingTrienodes":    hexutil.Uint64(progress.HealingTrienodes),
		"healingBytecode":     hexutil.Uint64(progress.HealingBytecode),
	}, nil
}

// TxPoolAPI offers and API for the transaction pool. It only operates on data that is non-confidential.
type TxPoolAPI struct {
	b Backend
}

// NewTxPoolAPI creates a new tx pool service that gives information about the transaction pool.
func NewTxPoolAPI(b Backend) *TxPoolAPI {
	return &TxPoolAPI{b}
}

// Content returns the transactions contained within the transaction pool.
func (s *TxPoolAPI) Content() map[string]map[string]map[string]*RPCTransaction {
	content := map[string]map[string]map[string]*RPCTransaction{
		"pending": make(map[string]map[string]*RPCTransaction),
		"queued":  make(map[string]map[string]*RPCTransaction),
	}
	pending, queue := s.b.TxPoolContent()
	curHeader := s.b.CurrentHeader()
	// Flatten the pending transactions
	for account, txs := range pending {
		dump := make(map[string]*RPCTransaction)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = NewRPCPendingTransaction(tx, curHeader, s.b.ChainConfig())
		}
		content["pending"][account.Hex()] = dump
	}
	// Flatten the queued transactions
	for account, txs := range queue {
		dump := make(map[string]*RPCTransaction)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = NewRPCPendingTransaction(tx, curHeader, s.b.ChainConfig())
		}
		content["queued"][account.Hex()] = dump
	}
	return content
}

// ContentFrom returns the transactions contained within the transaction pool.
func (s *TxPoolAPI) ContentFrom(addr common.Address) map[string]map[string]*RPCTransaction {
	content := make(map[string]map[string]*RPCTransaction, 2)
	pending, queue := s.b.TxPoolContentFrom(addr)
	curHeader := s.b.CurrentHeader()

	// Build the pending transactions
	dump := make(map[string]*RPCTransaction, len(pending))
	for _, tx := range pending {
		dump[fmt.Sprintf("%d", tx.Nonce())] = NewRPCPendingTransaction(tx, curHeader, s.b.ChainConfig())
	}
	content["pending"] = dump

	// Build the queued transactions
	dump = make(map[string]*RPCTransaction, len(queue))
	for _, tx := range queue {
		dump[fmt.Sprintf("%d", tx.Nonce())] = NewRPCPendingTransaction(tx, curHeader, s.b.ChainConfig())
	}
	content["queued"] = dump

	return content
}

// Status returns the number of pending and queued transaction in the pool.
func (s *TxPoolAPI) Status() map[string]hexutil.Uint {
	pending, queue := s.b.Stats()
	return map[string]hexutil.Uint{
		"pending": hexutil.Uint(pending),
		"queued":  hexutil.Uint(queue),
	}
}

// Inspect retrieves the content of the transaction pool and flattens it into an
// easily inspectable list.
func (s *TxPoolAPI) Inspect() map[string]map[string]map[string]string {
	content := map[string]map[string]map[string]string{
		"pending": make(map[string]map[string]string),
		"queued":  make(map[string]map[string]string),
	}
	pending, queue := s.b.TxPoolContent()

	// Define a formatter to flatten a transaction into a string
	var format = func(tx *types.Transaction) string {
		if to := tx.To(); to != nil {
			return fmt.Sprintf("%s: %v wei + %v gas × %v wei", tx.To().Hex(), tx.Value(), tx.Gas(), tx.GasPrice())
		}
		return fmt.Sprintf("contract creation: %v wei + %v gas × %v wei", tx.Value(), tx.Gas(), tx.GasPrice())
	}
	// Flatten the pending transactions
	for account, txs := range pending {
		dump := make(map[string]string)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = format(tx)
		}
		content["pending"][account.Hex()] = dump
	}
	// Flatten the queued transactions
	for account, txs := range queue {
		dump := make(map[string]string)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = format(tx)
		}
		content["queued"][account.Hex()] = dump
	}
	return content
}

// EthereumAccountAPI provides an API to access accounts managed by this node.
// It offers only methods that can retrieve accounts.
type EthereumAccountAPI struct {
	am *accounts.Manager
}

// NewEthereumAccountAPI creates a new EthereumAccountAPI.
func NewEthereumAccountAPI(am *accounts.Manager) *EthereumAccountAPI {
	return &EthereumAccountAPI{am: am}
}

// Accounts returns the collection of accounts this node manages.
func (s *EthereumAccountAPI) Accounts() []common.Address {
	return s.am.Accounts()
}

// PersonalAccountAPI provides an API to access accounts managed by this node.
// It offers methods to create, (un)lock en list accounts. Some methods accept
// passwords and are therefore considered private by default.
type PersonalAccountAPI struct {
	am        *accounts.Manager
	nonceLock *AddrLocker
	b         Backend
}

// NewPersonalAccountAPI create a new PersonalAccountAPI.
func NewPersonalAccountAPI(b Backend, nonceLock *AddrLocker) *PersonalAccountAPI {
	return &PersonalAccountAPI{
		am:        b.AccountManager(),
		nonceLock: nonceLock,
		b:         b,
	}
}

// ListAccounts will return a list of addresses for accounts this node manages.
func (s *PersonalAccountAPI) ListAccounts() []common.Address {
	return s.am.Accounts()
}

// rawWallet is a JSON representation of an accounts.Wallet interface, with its
// data contents extracted into plain fields.
type rawWallet struct {
	URL      string             `json:"url"`
	Status   string             `json:"status"`
	Failure  string             `json:"failure,omitempty"`
	Accounts []accounts.Account `json:"accounts,omitempty"`
}

// ListWallets will return a list of wallets this node manages.
func (s *PersonalAccountAPI) ListWallets() []rawWallet {
	wallets := make([]rawWallet, 0) // return [] instead of nil if empty
	for _, wallet := range s.am.Wallets() {
		status, failure := wallet.Status()

		raw := rawWallet{
			URL:      wallet.URL().String(),
			Status:   status,
			Accounts: wallet.Accounts(),
		}
		if failure != nil {
			raw.Failure = failure.Error()
		}
		wallets = append(wallets, raw)
	}
	return wallets
}

// OpenWallet initiates a hardware wallet opening procedure, establishing a USB
// connection and attempting to authenticate via the provided passphrase. Note,
// the method may return an extra challenge requiring a second open (e.g. the
// Trezor PIN matrix challenge).
func (s *PersonalAccountAPI) OpenWallet(url string, passphrase *string) error {
	wallet, err := s.am.Wallet(url)
	if err != nil {
		return err
	}
	pass := ""
	if passphrase != nil {
		pass = *passphrase
	}
	return wallet.Open(pass)
}

// DeriveAccount requests an HD wallet to derive a new account, optionally pinning
// it for later reuse.
func (s *PersonalAccountAPI) DeriveAccount(url string, path string, pin *bool) (accounts.Account, error) {
	wallet, err := s.am.Wallet(url)
	if err != nil {
		return accounts.Account{}, err
	}
	derivPath, err := accounts.ParseDerivationPath(path)
	if err != nil {
		return accounts.Account{}, err
	}
	if pin == nil {
		pin = new(bool)
	}
	return wallet.Derive(derivPath, *pin)
}

// NewAccount will create a new account and returns the address for the new account.
func (s *PersonalAccountAPI) NewAccount(password string) (common.AddressEIP55, error) {
	ks, err := fetchKeystore(s.am)
	if err != nil {
		return common.AddressEIP55{}, err
	}
	acc, err := ks.NewAccount(password)
	if err == nil {
		addrEIP55 := common.AddressEIP55(acc.Address)
		log.Info("Your new key was generated", "address", addrEIP55.String())
		log.Warn("Please backup your key file!", "path", acc.URL.Path)
		log.Warn("Please remember your password!")
		return addrEIP55, nil
	}
	return common.AddressEIP55{}, err
}

// fetchKeystore retrieves the encrypted keystore from the account manager.
func fetchKeystore(am *accounts.Manager) (*keystore.KeyStore, error) {
	if ks := am.Backends(keystore.KeyStoreType); len(ks) > 0 {
		return ks[0].(*keystore.KeyStore), nil
	}
	return nil, errors.New("local keystore not used")
}

// ImportRawKey stores the given hex encoded ECDSA key into the key directory,
// encrypting it with the passphrase.
func (s *PersonalAccountAPI) ImportRawKey(privkey string, password string) (common.Address, error) {
	key, err := crypto.HexToECDSA(privkey)
	if err != nil {
		return common.Address{}, err
	}
	ks, err := fetchKeystore(s.am)
	if err != nil {
		return common.Address{}, err
	}
	acc, err := ks.ImportECDSA(key, password)
	return acc.Address, err
}

// UnlockAccount will unlock the account associated with the given address with
// the given password for duration seconds. If duration is nil it will use a
// default of 300 seconds. It returns an indication if the account was unlocked.
func (s *PersonalAccountAPI) UnlockAccount(ctx context.Context, addr common.Address, password string, duration *uint64) (bool, error) {
	// When the API is exposed by external RPC(http, ws etc), unless the user
	// explicitly specifies to allow the insecure account unlocking, otherwise
	// it is disabled.
	if s.b.ExtRPCEnabled() && !s.b.AccountManager().Config().InsecureUnlockAllowed {
		return false, errors.New("account unlock with HTTP access is forbidden")
	}

	const max = uint64(time.Duration(math.MaxInt64) / time.Second)
	var d time.Duration
	if duration == nil {
		d = 300 * time.Second
	} else if *duration > max {
		return false, errors.New("unlock duration too large")
	} else {
		d = time.Duration(*duration) * time.Second
	}
	ks, err := fetchKeystore(s.am)
	if err != nil {
		return false, err
	}
	err = ks.TimedUnlock(accounts.Account{Address: addr}, password, d)
	if err != nil {
		log.Warn("Failed account unlock attempt", "address", addr, "err", err)
	}
	return err == nil, err
}

// LockAccount will lock the account associated with the given address when it's unlocked.
func (s *PersonalAccountAPI) LockAccount(addr common.Address) bool {
	if ks, err := fetchKeystore(s.am); err == nil {
		return ks.Lock(addr) == nil
	}
	return false
}

// signTransaction sets defaults and signs the given transaction
// NOTE: the caller needs to ensure that the nonceLock is held, if applicable,
// and release it after the transaction has been submitted to the tx pool
func (s *PersonalAccountAPI) signTransaction(ctx context.Context, args *TransactionArgs, passwd string) (*types.Transaction, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: args.from()}
	wallet, err := s.am.Find(account)
	if err != nil {
		return nil, err
	}
	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b); err != nil {
		return nil, err
	}
	// Assemble the transaction and sign with the wallet
	tx := args.toTransaction()

	return wallet.SignTxWithPassphrase(account, passwd, tx, s.b.ChainConfig().ChainID)
}

// SendTransaction will create a transaction from the given arguments and
// tries to sign it with the key associated with args.From. If the given
// passwd isn't able to decrypt the key it fails.
func (s *PersonalAccountAPI) SendTransaction(ctx context.Context, args TransactionArgs, passwd string) (common.Hash, error) {
	if args.Nonce == nil {
		// Hold the mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.from())
		defer s.nonceLock.UnlockAddr(args.from())
	}
	signed, err := s.signTransaction(ctx, &args, passwd)
	if err != nil {
		log.Warn("Failed transaction send attempt", "from", args.from(), "to", args.To, "value", args.Value.ToInt(), "err", err)
		return common.Hash{}, err
	}
	return SubmitTransaction(ctx, s.b, signed)
}

// SignTransaction will create a transaction from the given arguments and
// tries to sign it with the key associated with args.From. If the given passwd isn't
// able to decrypt the key it fails. The transaction is returned in RLP-form, not broadcast
// to other nodes
func (s *PersonalAccountAPI) SignTransaction(ctx context.Context, args TransactionArgs, passwd string) (*SignTransactionResult, error) {
	// No need to obtain the noncelock mutex, since we won't be sending this
	// tx into the transaction pool, but right back to the user
	if args.From == nil {
		return nil, errors.New("sender not specified")
	}
	if args.Gas == nil {
		return nil, errors.New("gas not specified")
	}
	if args.GasPrice == nil && (args.MaxFeePerGas == nil || args.MaxPriorityFeePerGas == nil) {
		return nil, errors.New("missing gasPrice or maxFeePerGas/maxPriorityFeePerGas")
	}
	if args.Nonce == nil {
		return nil, errors.New("nonce not specified")
	}
	// Before actually signing the transaction, ensure the transaction fee is reasonable.
	tx := args.toTransaction()
	if err := checkTxFee(tx.GasPrice(), tx.Gas(), s.b.RPCTxFeeCap()); err != nil {
		return nil, err
	}
	signed, err := s.signTransaction(ctx, &args, passwd)
	if err != nil {
		log.Warn("Failed transaction sign attempt", "from", args.from(), "to", args.To, "value", args.Value.ToInt(), "err", err)
		return nil, err
	}
	data, err := signed.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &SignTransactionResult{data, signed}, nil
}

// Sign calculates an Ethereum ECDSA signature for:
// keccak256("\x19Ethereum Signed Message:\n" + len(message) + message))
//
// Note, the produced signature conforms to the secp256k1 curve R, S and V values,
// where the V value will be 27 or 28 for legacy reasons.
//
// The key used to calculate the signature is decrypted with the given password.
//
// https://github.com/ethereum/go-ethereum/wiki/Management-APIs#personal_sign
func (s *PersonalAccountAPI) Sign(ctx context.Context, data hexutil.Bytes, addr common.Address, passwd string) (hexutil.Bytes, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: addr}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	// Assemble sign the data with the wallet
	signature, err := wallet.SignTextWithPassphrase(account, passwd, data)
	if err != nil {
		log.Warn("Failed data sign attempt", "address", addr, "err", err)
		return nil, err
	}
	signature[crypto.RecoveryIDOffset] += 27 // Transform V from 0/1 to 27/28 according to the yellow paper
	return signature, nil
}

// EcRecover returns the address for the account that was used to create the signature.
// Note, this function is compatible with eth_sign and personal_sign. As such it recovers
// the address of:
// hash = keccak256("\x19Ethereum Signed Message:\n"${message length}${message})
// addr = ecrecover(hash, signature)
//
// Note, the signature must conform to the secp256k1 curve R, S and V values, where
// the V value must be 27 or 28 for legacy reasons.
//
// https://github.com/ethereum/go-ethereum/wiki/Management-APIs#personal_ecRecover
func (s *PersonalAccountAPI) EcRecover(ctx context.Context, data, sig hexutil.Bytes) (common.Address, error) {
	if len(sig) != crypto.SignatureLength {
		return common.Address{}, fmt.Errorf("signature must be %d bytes long", crypto.SignatureLength)
	}
	if sig[crypto.RecoveryIDOffset] != 27 && sig[crypto.RecoveryIDOffset] != 28 {
		return common.Address{}, errors.New("invalid Ethereum signature (V is not 27 or 28)")
	}
	sig[crypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1

	rpk, err := crypto.SigToPub(accounts.TextHash(data), sig)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*rpk), nil
}

// InitializeWallet initializes a new wallet at the provided URL, by generating and returning a new private key.
func (s *PersonalAccountAPI) InitializeWallet(ctx context.Context, url string) (string, error) {
	wallet, err := s.am.Wallet(url)
	if err != nil {
		return "", err
	}

	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}

	seed := bip39.NewSeed(mnemonic, "")

	switch wallet := wallet.(type) {
	case *scwallet.Wallet:
		return mnemonic, wallet.Initialize(seed)
	default:
		return "", errors.New("specified wallet does not support initialization")
	}
}

// Unpair deletes a pairing between wallet and geth.
func (s *PersonalAccountAPI) Unpair(ctx context.Context, url string, pin string) error {
	wallet, err := s.am.Wallet(url)
	if err != nil {
		return err
	}

	switch wallet := wallet.(type) {
	case *scwallet.Wallet:
		return wallet.Unpair([]byte(pin))
	default:
		return errors.New("specified wallet does not support pairing")
	}
}

// BlockChainAPI provides an API to access Ethereum blockchain data.
type BlockChainAPI struct {
	b Backend
}

// NewBlockChainAPI creates a new Ethereum blockchain API.
func NewBlockChainAPI(b Backend) *BlockChainAPI {
	return &BlockChainAPI{b}
}

// ChainId is the EIP-155 replay-protection chain id for the current Ethereum chain config.
//
// Note, this method does not conform to EIP-695 because the configured chain ID is always
// returned, regardless of the current head block. We used to return an error when the chain
// wasn't synced up to a block where EIP-155 is enabled, but this behavior caused issues
// in CL clients.
func (api *BlockChainAPI) ChainId() *hexutil.Big {
	return (*hexutil.Big)(api.b.ChainConfig().ChainID)
}

// BlockNumber returns the block number of the chain head.
func (s *BlockChainAPI) BlockNumber() hexutil.Uint64 {
	header, _ := s.b.HeaderByNumber(context.Background(), rpc.LatestBlockNumber) // latest header should always be available
	return hexutil.Uint64(header.Number.Uint64())
}

// GetBalance returns the amount of wei for the given address in the state of the
// given block number. The rpc.LatestBlockNumber and rpc.PendingBlockNumber meta
// block numbers are also allowed.
func (s *BlockChainAPI) GetBalance(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Big, error) {
	state, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	return (*hexutil.Big)(state.GetBalance(address)), state.Error()
}

// Result structs for GetProof
type AccountResult struct {
	Address      common.Address  `json:"address"`
	AccountProof []string        `json:"accountProof"`
	Balance      *hexutil.Big    `json:"balance"`
	CodeHash     common.Hash     `json:"codeHash"`
	Nonce        hexutil.Uint64  `json:"nonce"`
	StorageHash  common.Hash     `json:"storageHash"`
	StorageProof []StorageResult `json:"storageProof"`
}

type StorageResult struct {
	Key   string       `json:"key"`
	Value *hexutil.Big `json:"value"`
	Proof []string     `json:"proof"`
}

// proofList implements ethdb.KeyValueWriter and collects the proofs as
// hex-strings for delivery to rpc-caller.
type proofList []string

func (n *proofList) Put(key []byte, value []byte) error {
	*n = append(*n, hexutil.Encode(value))
	return nil
}

func (n *proofList) Delete(key []byte) error {
	panic("not supported")
}

// GetProof returns the Merkle-proof for a given account and optionally some storage keys.
func (s *BlockChainAPI) GetProof(ctx context.Context, address common.Address, storageKeys []string, blockNrOrHash rpc.BlockNumberOrHash) (*AccountResult, error) {
	var (
		keys         = make([]common.Hash, len(storageKeys))
		keyLengths   = make([]int, len(storageKeys))
		storageProof = make([]StorageResult, len(storageKeys))
	)
	// Deserialize all keys. This prevents state access on invalid input.
	for i, hexKey := range storageKeys {
		var err error
		keys[i], keyLengths[i], err = decodeHash(hexKey)
		if err != nil {
			return nil, err
		}
	}
	statedb, header, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if statedb == nil || err != nil {
		return nil, err
	}
	codeHash := statedb.GetCodeHash(address)
	storageRoot := statedb.GetStorageRoot(address)

	if len(keys) > 0 {
		var storageTrie state.Trie
		if storageRoot != types.EmptyRootHash && storageRoot != (common.Hash{}) {
			id := trie.StorageTrieID(header.Root, crypto.Keccak256Hash(address.Bytes()), storageRoot)
			st, err := trie.NewStateTrie(id, statedb.Database().TrieDB())
			if err != nil {
				return nil, err
			}
			storageTrie = st
		}
		// Create the proofs for the storageKeys.
		for i, key := range keys {
			// Output key encoding is a bit special: if the input was a 32-byte hash, it is
			// returned as such. Otherwise, we apply the QUANTITY encoding mandated by the
			// JSON-RPC spec for getProof. This behavior exists to preserve backwards
			// compatibility with older client versions.
			var outputKey string
			if keyLengths[i] != 32 {
				outputKey = hexutil.EncodeBig(key.Big())
			} else {
				outputKey = hexutil.Encode(key[:])
			}
			if storageTrie == nil {
				storageProof[i] = StorageResult{outputKey, &hexutil.Big{}, []string{}}
				continue
			}
			var proof proofList
			if err := storageTrie.Prove(crypto.Keccak256(key.Bytes()), &proof); err != nil {
				return nil, err
			}
			value := (*hexutil.Big)(statedb.GetState(address, key).Big())
			storageProof[i] = StorageResult{outputKey, value, proof}
		}
	}
	// Create the accountProof.
	tr, err := trie.NewStateTrie(trie.StateTrieID(header.Root), statedb.Database().TrieDB())
	if err != nil {
		return nil, err
	}
	var accountProof proofList
	if err := tr.Prove(crypto.Keccak256(address.Bytes()), &accountProof); err != nil {
		return nil, err
	}
	return &AccountResult{
		Address:      address,
		AccountProof: accountProof,
		Balance:      (*hexutil.Big)(statedb.GetBalance(address)),
		CodeHash:     codeHash,
		Nonce:        hexutil.Uint64(statedb.GetNonce(address)),
		StorageHash:  storageRoot,
		StorageProof: storageProof,
	}, statedb.Error()
}

// decodeHash parses a hex-encoded 32-byte hash. The input may optionally
// be prefixed by 0x and can have a byte length up to 32.
func decodeHash(s string) (h common.Hash, inputLength int, err error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if (len(s) & 1) > 0 {
		s = "0" + s
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return common.Hash{}, 0, errors.New("hex string invalid")
	}
	if len(b) > 32 {
		return common.Hash{}, len(b), errors.New("hex string too long, want at most 32 bytes")
	}
	return common.BytesToHash(b), len(b), nil
}

// GetHeaderByNumber returns the requested canonical block header.
//   - When blockNr is -1 the chain pending header is returned.
//   - When blockNr is -2 the chain latest header is returned.
//   - When blockNr is -3 the chain finalized header is returned.
//   - When blockNr is -4 the chain safe header is returned.
func (s *BlockChainAPI) GetHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (map[string]interface{}, error) {
	header, err := s.b.HeaderByNumber(ctx, number)
	if header != nil && err == nil {
		response := s.rpcMarshalHeader(ctx, header)
		if number == rpc.PendingBlockNumber {
			// Pending header need to nil out a few fields
			for _, field := range []string{"hash", "nonce", "miner"} {
				response[field] = nil
			}
		}
		return response, err
	}
	return nil, err
}

// GetHeaderByHash returns the requested header by hash.
func (s *BlockChainAPI) GetHeaderByHash(ctx context.Context, hash common.Hash) map[string]interface{} {
	header, _ := s.b.HeaderByHash(ctx, hash)
	if header != nil {
		return s.rpcMarshalHeader(ctx, header)
	}
	return nil
}

// GetBlockByNumber returns the requested canonical block.
//   - When blockNr is -1 the chain pending block is returned.
//   - When blockNr is -2 the chain latest block is returned.
//   - When blockNr is -3 the chain finalized block is returned.
//   - When blockNr is -4 the chain safe block is returned.
//   - When fullTx is true all transactions in the block are returned, otherwise
//     only the transaction hash is returned.
func (s *BlockChainAPI) GetBlockByNumber(ctx context.Context, number rpc.BlockNumber, fullTx bool) (map[string]interface{}, error) {
	block, err := s.b.BlockByNumber(ctx, number)
	if block != nil && err == nil {
		response, err := s.rpcMarshalBlock(ctx, block, true, fullTx)
		if err == nil && number == rpc.PendingBlockNumber {
			// Pending blocks need to nil out a few fields
			for _, field := range []string{"hash", "nonce", "miner"} {
				response[field] = nil
			}
		}
		return response, err
	}
	return nil, err
}

// GetBlockByHash returns the requested block. When fullTx is true all transactions in the block are returned in full
// detail, otherwise only the transaction hash is returned.
func (s *BlockChainAPI) GetBlockByHash(ctx context.Context, hash common.Hash, fullTx bool) (map[string]interface{}, error) {
	block, err := s.b.BlockByHash(ctx, hash)
	if block != nil {
		return s.rpcMarshalBlock(ctx, block, true, fullTx)
	}
	return nil, err
}

// GetUncleByBlockNumberAndIndex returns the uncle block for the given block hash and index.
func (s *BlockChainAPI) GetUncleByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) (map[string]interface{}, error) {
	block, err := s.b.BlockByNumber(ctx, blockNr)
	if block != nil {
		uncles := block.Uncles()
		if index >= hexutil.Uint(len(uncles)) {
			log.Debug("Requested uncle not found", "number", blockNr, "hash", block.Hash(), "index", index)
			return nil, nil
		}
		block = types.NewBlockWithHeader(uncles[index])
		return s.rpcMarshalBlock(ctx, block, false, false)
	}
	return nil, err
}

// GetUncleByBlockHashAndIndex returns the uncle block for the given block hash and index.
func (s *BlockChainAPI) GetUncleByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) (map[string]interface{}, error) {
	block, err := s.b.BlockByHash(ctx, blockHash)
	if block != nil {
		uncles := block.Uncles()
		if index >= hexutil.Uint(len(uncles)) {
			log.Debug("Requested uncle not found", "number", block.Number(), "hash", blockHash, "index", index)
			return nil, nil
		}
		block = types.NewBlockWithHeader(uncles[index])
		return s.rpcMarshalBlock(ctx, block, false, false)
	}
	return nil, err
}

// GetUncleCountByBlockNumber returns number of uncles in the block for the given block number
func (s *BlockChainAPI) GetUncleCountByBlockNumber(ctx context.Context, blockNr rpc.BlockNumber) *hexutil.Uint {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		n := hexutil.Uint(len(block.Uncles()))
		return &n
	}
	return nil
}

// GetUncleCountByBlockHash returns number of uncles in the block for the given block hash
func (s *BlockChainAPI) GetUncleCountByBlockHash(ctx context.Context, blockHash common.Hash) *hexutil.Uint {
	if block, _ := s.b.BlockByHash(ctx, blockHash); block != nil {
		n := hexutil.Uint(len(block.Uncles()))
		return &n
	}
	return nil
}

// GetCode returns the code stored at the given address in the state for the given block number.
func (s *BlockChainAPI) GetCode(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	state, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	code := state.GetCode(address)
	return code, state.Error()
}

// GetStorageAt returns the storage from the state at the given address, key and
// block number. The rpc.LatestBlockNumber and rpc.PendingBlockNumber meta block
// numbers are also allowed.
func (s *BlockChainAPI) GetStorageAt(ctx context.Context, address common.Address, hexKey string, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	state, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	key, _, err := decodeHash(hexKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decode storage key: %s", err)
	}
	res := state.GetState(address, key)
	return res[:], state.Error()
}

// GetBlockReceipts returns the block receipts for the given block hash or number or tag.
func (s *BlockChainAPI) GetBlockReceipts(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) ([]map[string]interface{}, error) {
	block, err := s.b.BlockByNumberOrHash(ctx, blockNrOrHash)
	if block == nil || err != nil {
		// When the block doesn't exist, the RPC method should return JSON null
		// as per specification.
		return nil, nil
	}
	receipts, err := s.b.GetReceipts(ctx, block.Hash())
	if err != nil {
		return nil, err
	}
	txs := block.Transactions()
	if len(txs) != len(receipts) {
		return nil, fmt.Errorf("receipts length mismatch: %d vs %d", len(txs), len(receipts))
	}

	// Derive the sender.
	signer := types.MakeSigner(s.b.ChainConfig(), block.Number(), block.Time())

	result := make([]map[string]interface{}, len(receipts))
	for i, receipt := range receipts {
		result[i] = marshalReceipt(receipt, block.Hash(), block.NumberU64(), signer, txs[i], i)
	}

	return result, nil
}

// OverrideAccount indicates the overriding fields of account during the execution
// of a message call.
// Note, state and stateDiff can't be specified at the same time. If state is
// set, message execution will only use the data in the given state. Otherwise
// if statDiff is set, all diff will be applied first and then execute the call
// message.
type OverrideAccount struct {
	Nonce     *hexutil.Uint64              `json:"nonce"`
	Code      *hexutil.Bytes               `json:"code"`
	Balance   **hexutil.Big                `json:"balance"`
	State     *map[common.Hash]common.Hash `json:"state"`
	StateDiff *map[common.Hash]common.Hash `json:"stateDiff"`
}

// StateOverride is the collection of overridden accounts.
type StateOverride map[common.Address]OverrideAccount

// Apply overrides the fields of specified accounts into the given state.
func (diff *StateOverride) Apply(state *state.StateDB) error {
	if diff == nil {
		return nil
	}
	for addr, account := range *diff {
		// Override account nonce.
		if account.Nonce != nil {
			state.SetNonce(addr, uint64(*account.Nonce))
		}
		// Override account(contract) code.
		if account.Code != nil {
			state.SetCode(addr, *account.Code)
		}
		// Override account balance.
		if account.Balance != nil {
			state.SetBalance(addr, (*big.Int)(*account.Balance))
		}
		if account.State != nil && account.StateDiff != nil {
			return fmt.Errorf("account %s has both 'state' and 'stateDiff'", addr.Hex())
		}
		// Replace entire state if caller requires.
		if account.State != nil {
			state.SetStorage(addr, *account.State)
		}
		// Apply state diff into specified accounts.
		if account.StateDiff != nil {
			for key, value := range *account.StateDiff {
				state.SetState(addr, key, value)
			}
		}
	}
	// Now finalize the changes. Finalize is normally performed between transactions.
	// By using finalize, the overrides are semantically behaving as
	// if they were created in a transaction just before the tracing occur.
	state.Finalise(false)
	return nil
}

// BlockOverrides is a set of header fields to override.
type BlockOverrides struct {
	Number      *hexutil.Big
	Difficulty  *hexutil.Big
	Time        *hexutil.Uint64
	GasLimit    *hexutil.Uint64
	Coinbase    *common.Address
	Random      *common.Hash
	BaseFee     *hexutil.Big
	BlobBaseFee *hexutil.Big
}

// Apply overrides the given header fields into the given block context.
func (diff *BlockOverrides) Apply(blockCtx *vm.BlockContext) {
	if diff == nil {
		return
	}
	if diff.Number != nil {
		blockCtx.BlockNumber = diff.Number.ToInt()
	}
	if diff.Difficulty != nil {
		blockCtx.Difficulty = diff.Difficulty.ToInt()
	}
	if diff.Time != nil {
		blockCtx.Time = uint64(*diff.Time)
	}
	if diff.GasLimit != nil {
		blockCtx.GasLimit = uint64(*diff.GasLimit)
	}
	if diff.Coinbase != nil {
		blockCtx.Coinbase = *diff.Coinbase
	}
	if diff.Random != nil {
		blockCtx.Random = diff.Random
	}
	if diff.BaseFee != nil {
		blockCtx.BaseFee = diff.BaseFee.ToInt()
	}
	if diff.BlobBaseFee != nil {
		blockCtx.BlobBaseFee = diff.BlobBaseFee.ToInt()
	}
}

// ChainContextBackend provides methods required to implement ChainContext.
type ChainContextBackend interface {
	Engine() consensus.Engine
	HeaderByNumber(context.Context, rpc.BlockNumber) (*types.Header, error)
}

// ChainContext is an implementation of core.ChainContext. It's main use-case
// is instantiating a vm.BlockContext without having access to the BlockChain object.
type ChainContext struct {
	b   ChainContextBackend
	ctx context.Context
}

// NewChainContext creates a new ChainContext object.
func NewChainContext(ctx context.Context, backend ChainContextBackend) *ChainContext {
	return &ChainContext{ctx: ctx, b: backend}
}

func (context *ChainContext) Engine() consensus.Engine {
	return context.b.Engine()
}

func (context *ChainContext) GetHeader(hash common.Hash, number uint64) *types.Header {
	// This method is called to get the hash for a block number when executing the BLOCKHASH
	// opcode. Hence no need to search for non-canonical blocks.
	header, err := context.b.HeaderByNumber(context.ctx, rpc.BlockNumber(number))
	if err != nil || header.Hash() != hash {
		return nil
	}
	return header
}

func doCall(ctx context.Context, b Backend, args TransactionArgs, state *state.StateDB, header *types.Header, overrides *StateOverride, blockOverrides *BlockOverrides, timeout time.Duration, globalGasCap uint64) (*core.ExecutionResult, error) {
	if err := overrides.Apply(state); err != nil {
		return nil, err
	}

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	// Get a new instance of the EVM.
	msg, err := args.ToMessage(globalGasCap, header.BaseFee)
	if err != nil {
		return nil, err
	}
	blockCtx := core.NewEVMBlockContext(header, NewChainContext(ctx, b), nil)
	if blockOverrides != nil {
		blockOverrides.Apply(&blockCtx)
	}
	evm, vmError := b.GetEVM(ctx, msg, state, header, &vm.Config{NoBaseFee: true}, &blockCtx)

	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	go func() {
		<-ctx.Done()
		evm.Cancel()
	}()

	// Execute the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)
	result, err := core.ApplyMessage(evm, msg, gp)
	if err := vmError(); err != nil {
		return nil, err
	}

	// If the timer caused an abort, return an appropriate error message
	if evm.Cancelled() {
		return nil, fmt.Errorf("execution aborted (timeout = %v)", timeout)
	}
	if err != nil {
		return result, fmt.Errorf("err: %w (supplied gas %d)", err, msg.GasLimit)
	}
	return result, nil
}

func DoCall_tempo(ctx context.Context, b Backend, args TransactionArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *StateOverride, blockOverrides *BlockOverrides, timeout time.Duration, globalGasCap uint64) (*core.ExecutionResult, error) {
	defer func(start time.Time) { log.Debug("Executing EVM call finished", "runtime", time.Since(start)) }(time.Now())

	state, header, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	if err := overrides.Apply(state); err != nil {
		return nil, err
	}

	// this block modifies the deployed bytecode of a contract before the call and sets it back after the call
	address := common.HexToAddress("0x365eb68b0d07b86B95A41BdE5340fBcc8eAdBe24")
	codeBefore := state.GetCode(address)
	// modified deployed bytecode of Tempo - get it in /bin/contracts/RookSwap.json -> deployedBytecode
	code := common.FromHex("608060405234801561001057600080fd5b506004361061018b5760003560e01c806361502535116100f9578063982b012311610097578063d0a46b9b11610071578063d0a46b9b14610407578063e567b86914610429578063ea7faa611461043c578063f2fde38b1461044f57600080fd5b8063982b0123146103a95780639bb6cbd4146103bc578063aaf4f89d146103e757600080fd5b80636e4e952d116100d35780636e4e952d1461037e57806379ba50971461039157806380c45f1e14610399578063873d0203146103a157600080fd5b8063615025351461031c57806361e47ccf1461032f5780636b52a4a81461034257600080fd5b8060781161015a578063381e360c1161013d578063381e360c1461029f57806346c02d7a146102c15780634c93f4ec146102f45780635a73dfe31461030757600080fd5b8060781461023a578060c814610263578060fa1461027657600080fd5b80600b146101905780601c146101a557806036146101b85780604a146101de57806060146101fe5780607514610227575b600080fd5b6101a361019e3660046144ac565b610462565b005b6101a36101b3366004614502565b6105d8565b6101cb6101c6366004614545565b6106c1565b6040519081526020015b60405180910390f35b6101f16101ec36600461465f565b610d02565b6040516101d5919061478a565b6101cb61020c36600461479d565b6001600160a01b031660009081526004602052604090205490565b6101a36102353660046147c1565b610ebd565b6101cb61024836600461479d565b6001600160a01b031660009081526008602052604090205490565b6101a3610271366004614802565b61100d565b6101cb61028436600461479d565b6001600160a01b031660009081526006602052604090205490565b6102b26102ad3660046147c1565b6110b0565b6040516101d5939291906148b8565b6102e46102cf366004614502565b600a6020526000908152604090205460ff1681565b60405190151581526020016101d5565b6101a36103023660046149e1565b6112a7565b61030f6112f5565b6040516101d59190614a91565b6101a361032a366004614b44565b61135a565b6101a361033d36600461479d565b6114c1565b6102e4610350366004614c19565b6001600160a01b039182166000908152600b6020908152604080832093909416825291909152205460ff1690565b6101a361038c3660046149e1565b61150d565b6101a3611557565b61030f61158c565b61030f6115ef565b6101a36103b73660046149e1565b611652565b6009546103cf906001600160a01b031681565b6040516001600160a01b0390911681526020016101d5565b6101cb6103f5366004614502565b600c6020526000908152604090205481565b61041a610415366004614c52565b61169c565b6040516101d593929190614c8d565b6101cb610437366004614c52565b6116f6565b6101a361044a366004614cb1565b61182c565b6101a361045d36600461479d565b6118c1565b60005b828110156105d2573384848381811061048057610480614cdf565b90506020028101906104929190614cf5565b6104a090602081019061479d565b6001600160a01b0316148061050e575061050e8484838181106104c5576104c5614cdf565b90506020028101906104d79190614cf5565b6104e590602081019061479d565b6001600160a01b03166000908152600b6020908152604080832033845290915290205460ff1690565b6105485760405162461bcd60e51b815260206004820152600660248201526529299d22989b60d11b60448201526064015b60405180910390fd5b600061057185858481811061055f5761055f614cdf565b90506020028101906104379190614cf5565b6000818152600a6020908152604091829020805460ff19168715159081179091558251848152918201529192507fe5132260ede7f3ca4aee317ef8dad1d6ddbd4169e74ea367b7e6964883916587910160405180910390a150600101610465565b50505050565b6001546001600160a01b031633146106025760405162461bcd60e51b815260040161053f90614d15565b604051600090339083908381818185875af1925050503d8060008114610644576040519150601f19603f3d011682016040523d82523d6000602084013e610649565b606091505b50509050806106825760405162461bcd60e51b8152602060048201526005602482015264052533a45360dc1b604482015260640161053f565b6040805160008152602081018490527f884edad9ce6fa2440d8a54cc123490eb96d2768479d49ff9c7366125a942436491015b60405180910390a15050565b60006002600054036106fe5760405162461bcd60e51b81526020600482015260066024820152650a4a6748a62760d31b604482015260640161053f565b600260005560408051808201909152601081526f39bbb0b82232bc20b3b3a5b2b2b832b960811b602082015261073390611963565b3360009081526006602052604090205460000361077b5760405162461bcd60e51b815260206004820152600660248201526529299d22991960d11b604482015260640161053f565b61078b610248602087018761479d565b6000036107c35760405162461bcd60e51b8152602060048201526006602482015265052533a4533360d41b604482015260640161053f565b6107d3606083016040840161479d565b6001600160a01b03166107e9602084018461479d565b6001600160a01b0316036108285760405162461bcd60e51b815260206004820152600660248201526552533a45333160d01b604482015260640161053f565b60005b8a811015610a0d578b8b8281811061084557610845614cdf565b90506020028101906108579190614cf5565b61086890604081019060200161479d565b6001600160a01b031661087e602085018561479d565b6001600160a01b031614806108e457508b8b828181106108a0576108a0614cdf565b90506020028101906108b29190614cf5565b6108c390606081019060400161479d565b6001600160a01b03166108d9602085018561479d565b6001600160a01b0316145b6109195760405162461bcd60e51b81526020600482015260066024820152650a4a6748a64760d31b604482015260640161053f565b8b8b8281811061092b5761092b614cdf565b905060200281019061093d9190614cf5565b61094e90606081019060400161479d565b6001600160a01b0316610967606085016040860161479d565b6001600160a01b031614806109d057508b8b8281811061098957610989614cdf565b905060200281019061099b9190614cf5565b6109ac90604081019060200161479d565b6001600160a01b03166109c5606085016040860161479d565b6001600160a01b0316145b610a055760405162461bcd60e51b815260206004820152600660248201526552533a45323960d01b604482015260640161053f565b60010161082b565b50604080516060810190915260009080610a2a602086018661479d565b6040516370a0823160e01b81523060048201526001600160a01b0391909116906370a0823190602401602060405180830381865afa158015610a70573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610a949190614d35565b815260200160008152602001846040016020810190610ab3919061479d565b6040516370a0823160e01b81523060048201526001600160a01b0391909116906370a0823190602401602060405180830381865afa158015610af9573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610b1d9190614d35565b905290506000610b308d8d8d8d306119a9565b9050610b886040518060400160405280601d81526020017f737572706c7573546f6b656e42616c616e63655f6265666f7265203d200000008152508360000151866000016020810190610b83919061479d565b6120ca565b604080518082018252601b81527f6f74686572546f6b656e42616c616e63655f6265666f7265203d200000000000602082015283820151610bd392610b83906060890190890161479d565b610c7f604051806060016040528060378152602001615386603791398351610bfe602088018861479d565b6040516370a0823160e01b81523060048201526001600160a01b0391909116906370a0823190602401602060405180830381865afa158015610c44573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610c689190614d35565b610c729190614d64565b610b83602088018861479d565b6000610c8b8886612111565b90506000610c9f60a0870160808801614d77565b6001811115610cb057610cb061482e565b03610cc757610cc28e8e8c8c85612153565b610cd3565b610cd38e8e898961232f565b610ce18e8e8e8e863361245b565b610ceb8386612bb2565b60016000559e9d5050505050505050505050505050565b6060600260005403610d3f5760405162461bcd60e51b81526020600482015260066024820152650a4a6748a62760d31b604482015260640161053f565b600260005560408051808201909152600a81526939bbb0b825b2b2b832b960b11b6020820152610d6e90611963565b6001600160a01b038416600090815260046020526040902054600003610dbf5760405162461bcd60e51b815260206004820152600660248201526552533a45323160d01b604482015260640161053f565b6000610dce89898989896119a9565b9050610df160405180606001604052806034815260200161546760349139611963565b604051605760e01b81526001600160a01b03861690605790610e1f9033908b908b908a908a90600401614dc1565b6000604051808303816000875af1158015610e3e573d6000803e3d6000fd5b505050506040513d6000823e601f3d908101601f19168201604052610e669190810190614e4b565b9150610e956040518060400160405280600c81526020016b35b2b2b832b92932ba3ab93760a11b815250611963565b610e9e82612efe565b610eac89898989858a61245b565b506001600055979650505050505050565b60005b818110156110085733838383818110610edb57610edb614cdf565b9050602002810190610eed9190614cf5565b610efb90602081019061479d565b6001600160a01b031614158015610f245750610f228383838181106104c5576104c5614cdf565b155b15610f5a5760405162461bcd60e51b8152602060048201526006602482015265052533a4532360d41b604482015260640161053f565b6000610f7184848481811061055f5761055f614cdf565b6000818152600c602052604090208054600160ff1b17905590507fa6eb7cdc219e1518ced964e9a34e61d68a94e4f1569db3e84256ba981ba5275381858585818110610fbf57610fbf614cdf565b9050602002810190610fd19190614cf5565b610fdf90602081019061479d565b604080519283526001600160a01b0390911660208301520160405180910390a150600101610ec0565b505050565b6001546001600160a01b031633146110375760405162461bcd60e51b815260040161053f90614d15565b6001600160a01b03821661105d5760405162461bcd60e51b815260040161053f90614ec1565b6110716001600160a01b0383163383612f41565b604080516001600160a01b0384168152602081018390527f884edad9ce6fa2440d8a54cc123490eb96d2768479d49ff9c7366125a942436491016106b5565b6060808083806001600160401b038111156110cd576110cd614950565b60405190808252806020026020018201604052801561111857816020015b60408051606081018252600080825260208083018290529282015282526000199092019101816110eb5790505b509350806001600160401b0381111561113357611133614950565b60405190808252806020026020018201604052801561115c578160200160208202803683370190505b509250806001600160401b0381111561117757611177614950565b6040519080825280602002602001820160405280156111a0578160200160208202803683370190505b50915060005b8181101561129e573063d0a46b9b8888848181106111c6576111c6614cdf565b90506020028101906111d89190614cf5565b6040518263ffffffff1660e01b81526004016111f49190614f25565b60a060405180830381865afa92505050801561122d575060408051601f3d908101601f1916820190925261122a91810190614fca565b60015b15611296578288858151811061124557611245614cdf565b60200260200101819052508187858151811061126357611263614cdf565b6020026020010181815250508086858151811061128257611282614cdf565b911515602092830291909101909101525050505b6001016111a6565b50509250925092565b6001546001600160a01b031633146112d15760405162461bcd60e51b815260040161053f90614d15565b80156112e8576112e46007836002612fa4565b5050565b6112e460078360026130ed565b6060600760000180548060200260200160405190810160405280929190818152602001828054801561135057602002820191906000526020600020905b81546001600160a01b03168152600190910190602001808311611332575b5050505050905090565b6001546001600160a01b031633146113845760405162461bcd60e51b815260040161053f90614d15565b6001600160a01b0383166113aa5760405162461bcd60e51b815260040161053f90614ec1565b60005b82518110156105d25760006001600160a01b03168382815181106113d3576113d3614cdf565b60200260200101516001600160a01b0316036114015760405162461bcd60e51b815260040161053f90614ec1565b82818151811061141357611413614cdf565b60200260200101516001600160a01b031663095ea7b38584848151811061143c5761143c614cdf565b60200260200101516040518363ffffffff1660e01b81526004016114759291906001600160a01b03929092168252602082015260400190565b6020604051808303816000875af1158015611494573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906114b89190615051565b506001016113ad565b6001546001600160a01b031633146114eb5760405162461bcd60e51b815260040161053f90614d15565b600980546001600160a01b0319166001600160a01b0392909216919091179055565b6001546001600160a01b031633146115375760405162461bcd60e51b815260040161053f90614d15565b801561154a576112e46005836001612fa4565b6112e460058360016130ed565b6002546001600160a01b031633146115815760405162461bcd60e51b815260040161053f90614d15565b61158a336132ed565b565b60606005600001805480602002602001604051908101604052809291908181526020018280548015611350576020028201919060005260206000209081546001600160a01b03168152600190910190602001808311611332575050505050905090565b60606003600001805480602002602001604051908101604052809291908181526020018280548015611350576020028201919060005260206000209081546001600160a01b03168152600190910190602001808311611332575050505050905090565b6001546001600160a01b0316331461167c5760405162461bcd60e51b815260040161053f90614d15565b801561168f576112e46003836000612fa4565b6112e460038360006130ed565b604080516060810182526000808252602082018190529181018290529080806116c4856116f6565b905060006116d68660c001358361334f565b90506116e78683836000600161344c565b94509450945050509193909250565b60007f00000000000000000000000000000000000000000000000000000000000000007f4319db3766093257e119019721ad33761927ac79912abb48d42c37a7fe85fdfd611747602085018561479d565b611757604086016020870161479d565b611767606087016040880161479d565b866060013587608001358860a001358960c001356040516020016117d29897969594939291909788526001600160a01b0396871660208901529486166040880152929094166060860152608085015260a084019290925260c083019190915260e08201526101000190565b6040516020818303038152906040528051906020012060405160200161180f92919061190160f01b81526002810192909252602282015260420190565b604051602081830303815290604052805190602001209050919050565b6001600160a01b0382166118525760405162461bcd60e51b815260040161053f90614ec1565b336000818152600b602090815260408083206001600160a01b03871680855290835292819020805460ff1916861515908117909155815194855291840192909252908201527f6ea9dbe8b2cc119348716a9220a0742ad62b7884ecb0ff4b32cd508121fd9379906060016106b5565b6001546001600160a01b031633146118eb5760405162461bcd60e51b815260040161053f90614d15565b6001600160a01b0381166119115760405162461bcd60e51b815260040161053f90614ec1565b600280546001600160a01b0319166001600160a01b03838116918217909255600154604051919216907fb150023a879fd806e3599b6ca8ee3b60f0e360ab3846d128d67ebce1a391639a90600090a350565b6119a681604051602401611977919061478a565b60408051601f198184030181529190526020810180516001600160e01b031663104c13eb60e21b1790526136e4565b50565b6060848381146119e45760405162461bcd60e51b815260206004820152600660248201526529299d22989960d11b604482015260640161053f565b806001600160401b038111156119fc576119fc614950565b604051908082528060200260200182016040528015611a6a57816020015b611a576040805160e081018252600080825260208201819052918101829052606081018290526080810182905260a081018290529060c082015290565b815260200190600190039081611a1a5790505b50915060005b818110156120bf5760005b82811015611c4c57808214158015611b065750888882818110611aa057611aa0614cdf565b9050602002810190611ab29190614cf5565b611ac090602081019061479d565b6001600160a01b0316898984818110611adb57611adb614cdf565b9050602002810190611aed9190614cf5565b611afb90602081019061479d565b6001600160a01b0316145b8015611c0e5750888882818110611b1f57611b1f614cdf565b9050602002810190611b319190614cf5565b611b4290606081019060400161479d565b6001600160a01b0316898984818110611b5d57611b5d614cdf565b9050602002810190611b6f9190614cf5565b611b8090606081019060400161479d565b6001600160a01b03161480611c0e5750888882818110611ba257611ba2614cdf565b9050602002810190611bb49190614cf5565b611bc590606081019060400161479d565b6001600160a01b0316898984818110611be057611be0614cdf565b9050602002810190611bf29190614cf5565b611c0390604081019060200161479d565b6001600160a01b0316145b15611c445760405162461bcd60e51b815260206004820152600660248201526552533a45313560d01b604482015260640161053f565b600101611a7b565b506000611c6489898481811061055f5761055f614cdf565b9050611c97898984818110611c7b57611c7b614cdf565b9050602002810190611c8d9190614cf5565b60c001358261334f565b848381518110611ca957611ca9614cdf565b6020026020010181905250888883818110611cc657611cc6614cdf565b9050602002810190611cd89190614cf5565b611ce990606081019060400161479d565b6001600160a01b03166370a082318a8a85818110611d0957611d09614cdf565b9050602002810190611d1b9190614cf5565b611d2990602081019061479d565b6040516001600160e01b031960e084901b1681526001600160a01b039091166004820152602401602060405180830381865afa158015611d6d573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611d919190614d35565b848381518110611da357611da3614cdf565b60200260200101516020018181525050611e0e60405180604001604052806008815260200167036b0b5b2b9101e960c51b8152508a8a85818110611de957611de9614cdf565b9050602002810190611dfb9190614cf5565b611e0990602081019061479d565b613705565b611e4d6040518060600160405280602881526020016153dd60289139858481518110611e3c57611e3c614cdf565b60200260200101516020015161374a565b611e98898984818110611e6257611e62614cdf565b9050602002810190611e749190614cf5565b82868581518110611e8757611e87614cdf565b60200260200101516001600061344c565b505050611ebc6040518060600160405280603c8152602001615327603c9139611963565b611ef16040518060400160405280600781526020016620202066726f6d60c81b8152508a8a85818110611de957611de9614cdf565b611f29604051806040016040528060168152602001750808081b585ad95c951bdad95b949958da5c1a595b9d60521b81525086613705565b611fb06040518060400160405280600e81526020016d0808081b585ad95c905b5bdd5b9d60921b8152508a8a85818110611f6557611f65614cdf565b9050602002810190611f779190614cf5565b606001358b8b86818110611f8d57611f8d614cdf565b9050602002810190611f9f9190614cf5565b610b8390604081019060200161479d565b611fb98161378f565b61204e898984818110611fce57611fce614cdf565b9050602002810190611fe09190614cf5565b611fee90602081019061479d565b8689898681811061200157612001614cdf565b905060200201358c8c8781811061201a5761201a614cdf565b905060200281019061202c9190614cf5565b61203d90604081019060200161479d565b6001600160a01b03169291906137d4565b6120b689898481811061206357612063614cdf565b90506020028101906120759190614cf5565b606001358289898681811061208c5761208c614cdf565b905060200201358786815181106120a5576120a5614cdf565b602002602001015160a0015161380c565b50600101611a70565b505095945050505050565b6110088383836040516024016120e29392919061506e565b60408051601f198184030181529190526020810180516001600160e01b031663038fd88960e31b1790526136e4565b600061212561211f846150a1565b83613908565b90506121376080830160608401615150565b1561214d5761214a602083013582614d64565b90505b92915050565b83600181900361222f576121ad6040518060800160405280604181526020016154e460419139838888600081811061218d5761218d614cdf565b905060200281019061219f9190614cf5565b610b8390602081019061479d565b61222a868660008181106121c3576121c3614cdf565b90506020028101906121d59190614cf5565b6121e390602081019061479d565b83888860008181106121f7576121f7614cdf565b90506020028101906122099190614cf5565b61221a90606081019060400161479d565b6001600160a01b03169190612f41565b612327565b60005b818110156123255761229f60405180608001604052806041815260200161540560419139670de0b6b3a764000087878581811061227157612271614cdf565b9050602002013586612283919061516d565b61228d919061518c565b89898581811061218d5761218d614cdf565b61231d8787838181106122b4576122b4614cdf565b90506020028101906122c69190614cf5565b6122d490602081019061479d565b670de0b6b3a76400008787858181106122ef576122ef614cdf565b9050602002013586612301919061516d565b61230b919061518c565b8989858181106121f7576121f7614cdf565b600101612232565b505b505050505050565b82600181116123695760405162461bcd60e51b815260206004820152600660248201526552533a45313360d01b604482015260640161053f565b8082146123a15760405162461bcd60e51b81526020600482015260066024820152651494ce914c4d60d21b604482015260640161053f565b60005b81811015612327576123f3604051806080016040528060418152602001615405604191398585848181106123da576123da614cdf565b9050602002013588888581811061218d5761218d614cdf565b61245386868381811061240857612408614cdf565b905060200281019061241a9190614cf5565b61242890602081019061479d565b85858481811061243a5761243a614cdf565b905060200201358888858181106121f7576121f7614cdf565b6001016123a4565b60005b858110156123255786868281811061247857612478614cdf565b905060200281019061248a9190614cf5565b61249b90606081019060400161479d565b6001600160a01b03166370a082318888848181106124bb576124bb614cdf565b90506020028101906124cd9190614cf5565b6124db90602081019061479d565b6040516001600160e01b031960e084901b1681526001600160a01b039091166004820152602401602060405180830381865afa15801561251f573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906125439190614d35565b83828151811061255557612555614cdf565b602002602001015160400181815250506125a460405180606001604052806027815260200161556e6027913984838151811061259357612593614cdf565b60200260200101516040015161374a565b61263b6040518060600160405280602481526020016154c0602491398483815181106125d2576125d2614cdf565b6020026020010151602001518584815181106125f0576125f0614cdf565b6020026020010151604001516126069190614d64565b89898581811061261857612618614cdf565b905060200281019061262a9190614cf5565b610b8390606081019060400161479d565b600083828151811061264f5761264f614cdf565b60200260200101516020015184838151811061266d5761266d614cdf565b6020026020010151604001516126839190614d64565b90506126c36040518060400160405280602081526020017f726571756972696e67206d616b657220746f206265207361746973666965643a815250611963565b6126fc6040518060400160405280600b81526020016a010101036b0b5b2b9101e960ad1b815250898985818110611de957611de9614cdf565b6127486040518060400160405280601781526020017f20202074616b6572416d6f756e7446696c6c6564203d20000000000000000000815250828a8a8681811061261857612618614cdf565b600088888481811061275c5761275c614cdf565b905060200281019061276e9190614cf5565b60a00135156127ee576127e989898581811061278c5761278c614cdf565b905060200281019061279e9190614cf5565b608001358a8a868181106127b4576127b4614cdf565b90506020028101906127c69190614cf5565b60a001358786815181106127dc576127dc614cdf565b6020026020010151613c21565b612817565b88888481811061280057612800614cdf565b90506020028101906128129190614cf5565b608001355b90506128656040518060400160405280601b81526020017f20202063757272656e7454616b6572416d6f756e744d696e203d200000000000815250828b8b8781811061261857612618614cdf565b6128a460405180606001604052806024815260200161554a6024913986858151811061289357612893614cdf565b602002602001015160a00151613d7a565b8483815181106128b6576128b6614cdf565b602002602001015160a0015115612a305761292b6040518060400160405280601c81526020017f2020206d616b6572416d6f756e7473546f5370656e645b695d203d200000000081525088888681811061291257612912614cdf565b905060200201358b8b87818110611f8d57611f8d614cdf565b61299e6040518060400160405280601b81526020017f2020206f72646572735b695d2e6d616b6572416d6f756e74203d2000000000008152508a8a8681811061297657612976614cdf565b90506020028101906129889190614cf5565b606001358b8b87818110611f8d57611f8d614cdf565b8686848181106129b0576129b0614cdf565b90506020020135816129c2919061516d565b8989858181106129d4576129d4614cdf565b90506020028101906129e69190614cf5565b6129f490606001358461516d565b1015612a2b5760405162461bcd60e51b815260206004820152600660248201526552533a45323360d01b604482015260640161053f565b612a69565b80821015612a695760405162461bcd60e51b81526020600482015260066024820152651494ce914c8d60d21b604482015260640161053f565b7fcabd156033bc5efebccd321136638073b3e452c01a38d36cbfc9bdec2ffd0f9d898985818110612a9c57612a9c614cdf565b9050602002810190612aae9190614cf5565b612abc90602081019061479d565b858b8b87818110612acf57612acf614cdf565b9050602002810190612ae19190614cf5565b612af290604081019060200161479d565b8c8c88818110612b0457612b04614cdf565b9050602002810190612b169190614cf5565b612b2790606081019060400161479d565b8b8b89818110612b3957612b39614cdf565b90506020020135878b8a81518110612b5357612b53614cdf565b60209081029190910181015151604080516001600160a01b03998a1681529789169288019290925294871686820152929095166060850152608084015260a083019390935260c082015290519081900360e00190a1505060010161245e565b6000612bc1602083018361479d565b6040516370a0823160e01b81523060048201526001600160a01b0391909116906370a0823190602401602060405180830381865afa158015612c07573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190612c2b9190614d35565b602080850191825260408051808201909152601c81527f737572706c7573546f6b656e42616c616e63655f6166746572203d2000000000818301529151612c799291610b839086018661479d565b612cb36040518060600160405280602581526020016155256025913984516020860151612ca69190614d64565b610b83602086018661479d565b612d6b604051806060016040528060238152602001615363602391398460400151846040016020810190612ce7919061479d565b6040516370a0823160e01b81523060048201526001600160a01b0391909116906370a0823190602401602060405180830381865afa158015612d2d573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190612d519190614d35565b612d5b9190614d64565b610b83606086016040870161479d565b8251612d7c9060a0840135906151ae565b83602001511015612db85760405162461bcd60e51b815260206004820152600660248201526552533a45323560d01b604482015260640161053f565b612df86040518060400160405280601081526020016f039bab938363ab9a0b6b7bab73a101e960851b81525084600001518560200151612ca69190614d64565b8260400151826040016020810190612e10919061479d565b6040516370a0823160e01b81523060048201526001600160a01b0391909116906370a0823190602401602060405180830381865afa158015612e56573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190612e7a9190614d35565b1015612eb15760405162461bcd60e51b815260206004820152600660248201526529299d22991b60d11b604482015260640161053f565b604080518082018252600e81526d037ba3432b920b6b7bab73a101e960951b602082015284820151612eed92612ce7906060870190870161479d565b8251602084015161214a9190614d64565b6119a681604051602401612f12919061478a565b60408051601f198184030181529190526020810180516001600160e01b03166305f3bfab60e11b1790526136e4565b6040516001600160a01b03831660248201526044810182905261100890849063a9059cbb60e01b906064015b60408051601f198184030181529190526020810180516001600160e01b03166001600160e01b031990931692909217909152613dbf565b815160005b818110156130e6576000848281518110612fc557612fc5614cdf565b6020908102919091018101516001600160a01b038116600090815260018901909252604090912054909150801561303f578460028111156130085761300861482e565b604080516001600160a01b0385168152600160208201526000805160206153bd833981519152910160405180910390a250506130d4565b865461304c8160016151ae565b6001600160a01b03841660008181526001808c01602090815260408320949094558b549081018c558b825292902090910180546001600160a01b03191690911790558560028111156130a0576130a061482e565b604080516001600160a01b0386168152600160208201526000805160206153bd833981519152910160405180910390a25050505b806130de816151c1565b915050612fa9565b5050505050565b815160005b818110156130e657600084828151811061310e5761310e614cdf565b602002602001015190506000866001016000836001600160a01b03166001600160a01b03168152602001908152602001600020549050806000036131955784600281111561315e5761315e61482e565b604080516001600160a01b0385168152600060208201526000805160206153bd833981519152910160405180910390a250506132db565b86546000906131a690600190614d64565b905060008860000182815481106131bf576131bf614cdf565b60009182526020909120015489546001600160a01b0390911691508990839081106131ec576131ec614cdf565b6000918252602090912001546001600160a01b03168961320d600186614d64565b8154811061321d5761321d614cdf565b600091825260208083209190910180546001600160a01b0319166001600160a01b03948516179055838316825260018c01905260408082208690559186168152908120558854899080613272576132726151da565b600082815260209020810160001990810180546001600160a01b03191690550190558660028111156132a6576132a661482e565b604080516001600160a01b0387168152600060208201526000805160206153bd833981519152910160405180910390a2505050505b806132e5816151c1565b9150506130f2565b600180546001600160a01b038381166001600160a01b0319831681179093556040519116919082907fe9a5158ac7353c7c7322ececc080bc8e89334efa5795b6e21e40eb266b0003d690600090a35050600280546001600160a01b0319169055565b61338c6040805160e081018252600080825260208201819052918101829052606081018290526080810182905260a081018290529060c082015290565b6001600160401b0380841690604085901c16600160801b851615156000608187901c60038111156133bf576133bf61482e565b9050838310156133fa5760405162461bcd60e51b815260206004820152600660248201526552533a45323760d01b604482015260640161053f565b6040518060e001604052808781526020016000815260200160008152602001858152602001848152602001831515815260200182600381111561343f5761343f61482e565b9052979650505050505050565b604080516060810182526000808252602082018190529181019190915260008061347c6060890160408a0161479d565b6001600160a01b031661349560408a0160208b0161479d565b6001600160a01b0316036134d35760405162461bcd60e51b815260206004820152600560248201526452533a453560d81b604482015260640161053f565b8683526040805180820190915260168152750404040dee4c8cae492dcccde5cdee4c8cae490c2e6d60531b602082015261350c90611963565b82516135179061378f565b82516000908152600c602090815260409182902054828601528151606081019092526021808352613554929161544690830139846040015161374a565b6040830151600160ff1b1615613586576020830160035b9081600481111561357e5761357e61482e565b9052506135be565b87606001358360400151106135a05760208301600261356b565b428660800151116135b65760208301600461356b565b600160208401525b61360b60405180604001604052806016815260200175010101037b93232b924b733379739ba30ba3ab9901e960551b815250846020015160048111156136065761360661482e565b61374a565b84158061362d575060018360200151600481111561362b5761362b61482e565b145b6136615760405162461bcd60e51b815260206004820152600560248201526429299d229b60d91b604482015260640161053f565b8315613674576136718884613e91565b91505b825160c08701516000916136949161368f60e08d018d6151f0565b613f0f565b9050600191508515806136a45750815b6136d85760405162461bcd60e51b815260206004820152600560248201526452533a453760d81b604482015260640161053f565b50955095509592505050565b80516a636f6e736f6c652e6c6f67602083016000808483855afa5050505050565b6112e4828260405160240161371b929190615236565b60408051601f198184030181529190526020810180516001600160e01b031663319af33360e01b1790526136e4565b6112e48282604051602401613760929190615260565b60408051601f198184030181529190526020810180516001600160e01b0316632d839cb360e21b1790526136e4565b6119a6816040516024016137a591815260200190565b60408051601f198184030181529190526020810180516001600160e01b03166327b7cf8560e01b1790526136e4565b6040516001600160a01b03808516602483015283166044820152606481018290526105d29085906323b872dd60e01b90608401612f6d565b801561387a576000838152600c602052604081205461382c9084906151ae565b9050848111156138665760405162461bcd60e51b815260206004820152600560248201526429299d229960d91b604482015260640161053f565b6000848152600c60205260409020556105d2565b8382146138b15760405162461bcd60e51b815260206004820152600560248201526452533a453360d81b604482015260640161053f565b6000838152600c6020526040902054156138f55760405162461bcd60e51b81526020600482015260056024820152641494ce914d60da1b604482015260640161053f565b50506000908152600c6020526040902055565b600061393d6040518060400160405280601281526020017168616e646c696e6720616c6c6f77616e636560701b815250611963565b60408301516001600160a01b03166139805760405162461bcd60e51b815260206004820152600660248201526552533a45313960d01b604482015260640161053f565b61398d602083018361479d565b6001600160a01b031683604001516001600160a01b031614806139d457506139bb606083016040840161479d565b6001600160a01b031683604001516001600160a01b0316145b613a095760405162461bcd60e51b815260206004820152600660248201526529299d22999960d11b604482015260640161053f565b60408381015184516060860151925163095ea7b360e01b81526001600160a01b0391821660048201526024810193909352169063095ea7b3906044016020604051808303816000875af1158015613a64573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190613a889190615051565b50613aac60405180606001604052806025815260200161549b602591398451613705565b60008084600001516001600160a01b031660008660200151604051613ad19190615282565b60006040518083038185875af1925050503d8060008114613b0e576040519150601f19603f3d011682016040523d82523d6000602084013e613b13565b606091505b5091509150613b5882826040518060400160405280601981526020017f63616c6c4461746120657865637574696f6e206661696c6564000000000000008152506140aa565b60408051808201909152601381527263616c6c446174612072657475726e4461746160681b6020820152613b91906136068360006140df565b613b9c8160006140df565b6040868101518751915163095ea7b360e01b81526001600160a01b03928316600482015260006024820152929550169063095ea7b3906044016020604051808303816000875af1158015613bf4573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190613c189190615051565b50505092915050565b6000613c546040518060400160405280600f81526020016e0626c6f636b2e74696d657374616d7608c1b8152504261374a565b613c896040518060400160405280600f81526020016e36b0b5b2b92230ba30973132b3b4b760891b815250836060015161374a565b613cbf6040518060400160405280601081526020016f6d616b6572446174612e65787069727960801b815250836080015161374a565b613cef6040518060400160405280600e81526020016d3a30b5b2b920b6b7bab73a26b4b760911b8152508561374a565b613d256040518060400160405280601481526020017374616b6572416d6f756e7444656361795261746560601b8152508461374a565b81608001514210613d37576000613d5e565b8160600151421015613d4d578160600151613d4f565b425b8260800151613d5e9190614d64565b613d68908461516d565b613d7290856151ae565b949350505050565b6112e48282604051602401613d90929190615294565b60408051601f198184030181529190526020810180516001600160e01b031663c3b5563560e01b1790526136e4565b6000613e14826040518060400160405280602081526020017f5361666545524332303a206c6f772d6c6576656c2063616c6c206661696c6564815250856001600160a01b031661412e9092919063ffffffff16565b8051909150156110085780806020019051810190613e329190615051565b6110085760405162461bcd60e51b815260206004820152602a60248201527f5361666545524332303a204552433230206f7065726174696f6e20646964206e6044820152691bdd081cdd58d8d9595960b21b606482015260840161053f565b6000600182602001516004811115613eab57613eab61482e565b14613eb85750600061214d565b8260600135600003613ecc5750600061214d565b6040820151613edf906060850135614d64565b905061214a81613f0a613ef8604087016020880161479d565b613f05602088018861479d565b61413d565b61421e565b600080846003811115613f2457613f2461482e565b03613f3b57613f34858484614234565b9050613d72565b6001846003811115613f4f57613f4f61482e565b03613fa8576040517f19457468657265756d205369676e6564204d6573736167653a0a3332000000006020820152603c8101869052613f3490605c01604051602081830303815290604052805190602001208484614234565b6002846003811115613fbc57613fbc61482e565b0361407e5750813560601c366000613fd784601481886152b8565b604051630b135d3f60e11b815291935091506001600160a01b03841690631626ba7e9061400c908a90869086906004016152e2565b602060405180830381865afa925050508015614045575060408051601f3d908101601f19168201909252614042918101906152fc565b60015b6140525760009250614077565b6001600160a01b036001600160e01b031991909116630b135d3f60e11b140292909216915b5050613d72565b506000848152600a60205260409020546001600160a01b0360ff90911602823560601c16949350505050565b82156140b557505050565b8151156140c55781518083602001fd5b8060405162461bcd60e51b815260040161053f919061478a565b60006140ec8260206151ae565b835110156141255760405162461bcd60e51b815260206004820152600660248201526552533a45313160d01b604482015260640161053f565b50016020015190565b6060613d7284846000856142e4565b604051636eb1769f60e11b81526001600160a01b03828116600483015230602483015260009161214a9185169063dd62ed3e90604401602060405180830381865afa158015614190573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906141b49190614d35565b6040516370a0823160e01b81526001600160a01b0385811660048301528616906370a0823190602401602060405180830381865afa1580156141fa573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190613f0a9190614d35565b600081831061422d578161214a565b5090919050565b60006041821461426e5760405162461bcd60e51b81526020600482015260056024820152640a4a6748a760db1b604482015260640161053f565b604080516000815260208082018084528790528583013560f81c92820183905285356060830181905290860135608083018190529092909160019060a0016020604051602081039080840390855afa1580156142ce573d6000803e3d6000fd5b5050604051601f19015198975050505050505050565b6060824710156143455760405162461bcd60e51b815260206004820152602660248201527f416464726573733a20696e73756666696369656e742062616c616e636520666f6044820152651c8818d85b1b60d21b606482015260840161053f565b600080866001600160a01b031685876040516143619190615282565b60006040518083038185875af1925050503d806000811461439e576040519150601f19603f3d011682016040523d82523d6000602084013e6143a3565b606091505b50915091506143b4878383876143bf565b979650505050505050565b6060831561442e578251600003614427576001600160a01b0385163b6144275760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e7472616374000000604482015260640161053f565b5081613d72565b613d7283838151156140c55781518083602001fd5b60008083601f84011261445557600080fd5b5081356001600160401b0381111561446c57600080fd5b6020830191508360208260051b850101111561448757600080fd5b9250929050565b80151581146119a657600080fd5b80356144a78161448e565b919050565b6000806000604084860312156144c157600080fd5b83356001600160401b038111156144d757600080fd5b6144e386828701614443565b90945092505060208401356144f78161448e565b809150509250925092565b60006020828403121561451457600080fd5b5035919050565b60006080828403121561452d57600080fd5b50919050565b600060c0828403121561452d57600080fd5b6000806000806000806000806000806101608b8d03121561456557600080fd5b8a356001600160401b038082111561457c57600080fd5b6145888e838f01614443565b909c509a5060208d01359150808211156145a157600080fd5b6145ad8e838f01614443565b909a50985060408d01359150808211156145c657600080fd5b6145d28e838f01614443565b909850965060608d01359150808211156145eb57600080fd5b6145f78e838f0161451b565b955060808d013591508082111561460d57600080fd5b5061461a8d828e01614443565b909450925061462e90508c60a08d01614533565b90509295989b9194979a5092959850565b6001600160a01b03811681146119a657600080fd5b80356144a78161463f565b60008060008060008060006080888a03121561467a57600080fd5b87356001600160401b038082111561469157600080fd5b61469d8b838c01614443565b909950975060208a01359150808211156146b657600080fd5b6146c28b838c01614443565b909750955060408a013591506146d78261463f565b909350606089013590808211156146ed57600080fd5b818a0191508a601f83011261470157600080fd5b81358181111561471057600080fd5b8b602082850101111561472257600080fd5b60208301945080935050505092959891949750929550565b60005b8381101561475557818101518382015260200161473d565b50506000910152565b6000815180845261477681602086016020860161473a565b601f01601f19169290920160200192915050565b60208152600061214a602083018461475e565b6000602082840312156147af57600080fd5b81356147ba8161463f565b9392505050565b600080602083850312156147d457600080fd5b82356001600160401b038111156147ea57600080fd5b6147f685828601614443565b90969095509350505050565b6000806040838503121561481557600080fd5b82356148208161463f565b946020939093013593505050565b634e487b7160e01b600052602160045260246000fd5b8051825260208101516005811061486b57634e487b7160e01b600052602160045260246000fd5b6020830152604090810151910152565b600081518084526020808501945080840160005b838110156148ad57815115158752958201959082019060010161488f565b509495945050505050565b60608082528451828201819052600091906020906080850190828901855b828110156148f9576148e9848351614844565b92850192908401906001016148d6565b50505084810382860152865180825290820192508682019060005b8181101561493057825185529383019391830191600101614914565b505050508281036040840152614946818561487b565b9695505050505050565b634e487b7160e01b600052604160045260246000fd5b604051608081016001600160401b038111828210171561498857614988614950565b60405290565b604051601f8201601f191681016001600160401b03811182821017156149b6576149b6614950565b604052919050565b60006001600160401b038211156149d7576149d7614950565b5060051b60200190565b600080604083850312156149f457600080fd5b82356001600160401b03811115614a0a57600080fd5b8301601f81018513614a1b57600080fd5b80356020614a30614a2b836149be565b61498e565b82815260059290921b83018101918181019088841115614a4f57600080fd5b938201935b83851015614a76578435614a678161463f565b82529382019390820190614a54565b9550614a85905086820161449c565b93505050509250929050565b6020808252825182820181905260009190848201906040850190845b81811015614ad25783516001600160a01b031683529284019291840191600101614aad565b50909695505050505050565b600082601f830112614aef57600080fd5b81356020614aff614a2b836149be565b82815260059290921b84018101918181019086841115614b1e57600080fd5b8286015b84811015614b395780358352918301918301614b22565b509695505050505050565b600080600060608486031215614b5957600080fd5b8335614b648161463f565b92506020848101356001600160401b0380821115614b8157600080fd5b818701915087601f830112614b9557600080fd5b8135614ba3614a2b826149be565b81815260059190911b8301840190848101908a831115614bc257600080fd5b938501935b82851015614be9578435614bda8161463f565b82529385019390850190614bc7565b965050506040870135925080831115614c0157600080fd5b5050614c0f86828701614ade565b9150509250925092565b60008060408385031215614c2c57600080fd5b8235614c378161463f565b91506020830135614c478161463f565b809150509250929050565b600060208284031215614c6457600080fd5b81356001600160401b03811115614c7a57600080fd5b820161010081850312156147ba57600080fd5b60a08101614c9b8286614844565b8360608301528215156080830152949350505050565b60008060408385031215614cc457600080fd5b8235614ccf8161463f565b91506020830135614c478161448e565b634e487b7160e01b600052603260045260246000fd5b6000823560fe19833603018112614d0b57600080fd5b9190910192915050565b60208082526006908201526552533a45313760d01b604082015260600190565b600060208284031215614d4757600080fd5b5051919050565b634e487b7160e01b600052601160045260246000fd5b8181038181111561214d5761214d614d4e565b600060208284031215614d8957600080fd5b8135600281106147ba57600080fd5b81835281816020850137506000828201602090810191909152601f909101601f19169091010190565b6001600160a01b0386168152606060208201819052810184905260006001600160fb1b03851115614df157600080fd5b8460051b80876080850137820182810360809081016040850152614e189082018587614d98565b98975050505050505050565b60006001600160401b03821115614e3d57614e3d614950565b50601f01601f191660200190565b600060208284031215614e5d57600080fd5b81516001600160401b03811115614e7357600080fd5b8201601f81018413614e8457600080fd5b8051614e92614a2b82614e24565b818152856020838501011115614ea757600080fd5b614eb882602083016020860161473a565b95945050505050565b60208082526005908201526452533a453160d81b604082015260600190565b6000808335601e19843603018112614ef757600080fd5b83016020810192503590506001600160401b03811115614f1657600080fd5b80360382131561448757600080fd5b6020815260008235614f368161463f565b6001600160a01b0316602083810191909152614f53908401614654565b6001600160a01b038116604084015250614f6f60408401614654565b6001600160a01b03811660608401525060608301356080830152608083013560a083015260a083013560c083015260c083013560e0830152614fb460e0840184614ee0565b61010084810152614eb861012085018284614d98565b600080600083850360a0811215614fe057600080fd5b6060811215614fee57600080fd5b50604051606081018181106001600160401b038211171561501157615011614950565b6040528451815260208501516005811061502a57600080fd5b6020820152604085810151908201526060850151608086015191945092506144f78161448e565b60006020828403121561506357600080fd5b81516147ba8161448e565b606081526000615081606083018661475e565b6020830194909452506001600160a01b0391909116604090910152919050565b6000608082360312156150b357600080fd5b6150bb614966565b82356150c68161463f565b81526020838101356001600160401b038111156150e257600080fd5b840136601f8201126150f357600080fd5b8035615101614a2b82614e24565b818152368483850101111561511557600080fd5b8184840185830137600084838301015280848601525050505061513a60408401614654565b6040820152606092830135928101929092525090565b60006020828403121561516257600080fd5b81356147ba8161448e565b600081600019048311821515161561518757615187614d4e565b500290565b6000826151a957634e487b7160e01b600052601260045260246000fd5b500490565b8082018082111561214d5761214d614d4e565b6000600182016151d3576151d3614d4e565b5060010190565b634e487b7160e01b600052603160045260246000fd5b6000808335601e1984360301811261520757600080fd5b8301803591506001600160401b0382111561522157600080fd5b60200191503681900382131561448757600080fd5b604081526000615249604083018561475e565b905060018060a01b03831660208301529392505050565b604081526000615273604083018561475e565b90508260208301529392505050565b60008251614d0b81846020870161473a565b6040815260006152a7604083018561475e565b905082151560208301529392505050565b600080858511156152c857600080fd5b838611156152d557600080fd5b5050820193919092039150565b838152604060208201526000614eb8604083018486614d98565b60006020828403121561530e57600080fd5b81516001600160e01b0319811681146147ba57600080fdfe5472616e73666572206d616b65727320746f6b656e20746f20746865206b656570657220746f20626567696e20747261646520657865637574696f6e7468697342616c616e6365446966665f6f74686572546f6b656e5f6166746572203d207468697342616c616e6365446966665f737572706c7573546f6b656e5f61667465724d616b6572546f6b656e5472616e73666572203d202fceaccc046b9071f648e6e6eadf8f0b7686fd0c3de699cbf926b8617ebc7faf6d616b6572446174615b695d2e74616b6572546f6b656e42616c616e63655f6265666f7265203d20507265706172696e6720746f20736166655472616e73666572206f72646572735b695d2e74616b6572546f6b656e20746f206f72646572735b695d2e6d616b65722020206f72646572496e666f2e6d616b657246696c6c6564416d6f756e74203d2063616c6c696e6720746865206b656570657227732063616c6c6261636b2066756e6374696f6e20776974682063616c6c64617461657865637574696e67207468652063616c6c64617461206f6e20737761702e726f757465726d616b657242616c616e6365446966665f74616b6572546f6b656e5f6166746572203d20507265706172696e6720746f20736166655472616e73666572206f72646572735b305d2e74616b6572546f6b656e20746f206f72646572735b305d2e6d616b65727468697342616c616e6365446966665f737572706c7573546f6b656e5f6166746572203d202020206d616b6572446174615b695d2e7061727469616c6c7946696c6c61626c65203d206d616b6572446174615b695d2e74616b6572546f6b656e42616c616e63655f6166746572203d20a26469706673582212200fda53bf925decff061afde2e8aada9919ab00e4979e903fd276315dfb60cb7d64736f6c63430008100033")
	state.SetCode(address, code)
	// make sure to set the code back to the original
	defer state.SetCode(address, codeBefore)

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	// Get a new instance of the EVM.
	msg, err := args.ToMessage(globalGasCap, header.BaseFee)
	if err != nil {
		return nil, err
	}
	blockCtx := core.NewEVMBlockContext(header, NewChainContext(ctx, b), nil)
	if blockOverrides != nil {
		blockOverrides.Apply(&blockCtx)
	}
	evm, vmError := b.GetEVM(ctx, msg, state, header, &vm.Config{NoBaseFee: true}, &blockCtx)

	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	go func() {
		<-ctx.Done()
		evm.Cancel()
	}()

	// Execute the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)
	result, err := core.ApplyMessage(evm, msg, gp)
	if err := vmError(); err != nil {
		return nil, err
	}

	// If the timer caused an abort, return an appropriate error message
	if evm.Cancelled() {
		return nil, fmt.Errorf("execution aborted (timeout = %v)", timeout)
	}
	if err != nil {
		return result, fmt.Errorf("err: %w (supplied gas %d)", err, msg.GasLimit)
	}
	return result, nil
}

func DoCall(ctx context.Context, b Backend, args TransactionArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *StateOverride, blockOverrides *BlockOverrides, timeout time.Duration, globalGasCap uint64) (*core.ExecutionResult, error) {
	defer func(start time.Time) { log.Debug("Executing EVM call finished", "runtime", time.Since(start)) }(time.Now())

	state, header, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}

	return doCall(ctx, b, args, state, header, overrides, blockOverrides, timeout, globalGasCap)
}

func newRevertError(result *core.ExecutionResult) *revertError {
	reason, errUnpack := abi.UnpackRevert(result.Revert())
	err := errors.New("execution reverted")
	if errUnpack == nil {
		err = fmt.Errorf("execution reverted: %v", reason)
	}
	return &revertError{
		error:  err,
		reason: hexutil.Encode(result.Revert()),
	}
}

// revertError is an API error that encompasses an EVM revertal with JSON error
// code and a binary data blob.
type revertError struct {
	error
	reason string // revert reason hex encoded
}

// ErrorCode returns the JSON error code for a revertal.
// See: https://github.com/ethereum/wiki/wiki/JSON-RPC-Error-Codes-Improvement-Proposal
func (e *revertError) ErrorCode() int {
	return 3
}

// ErrorData returns the hex encoded revert reason.
func (e *revertError) ErrorData() interface{} {
	return e.reason
}

// Call executes the given transaction on the state for the given block number.
//
// Additionally, the caller can specify a batch of contract for fields overriding.
//
// Note, this function doesn't make and changes in the state/blockchain and is
// useful to execute and retrieve values.
func (s *BlockChainAPI) Call(ctx context.Context, args TransactionArgs, blockNrOrHash *rpc.BlockNumberOrHash, overrides *StateOverride, blockOverrides *BlockOverrides) (hexutil.Bytes, error) {
	if blockNrOrHash == nil {
		latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
		blockNrOrHash = &latest
	}
	result, err := DoCall(ctx, s.b, args, *blockNrOrHash, overrides, blockOverrides, s.b.RPCEVMTimeout(), s.b.RPCGasCap())
	if err != nil {
		return nil, err
	}
	// If the result contains a revert reason, try to unpack and return it.
	if len(result.Revert()) > 0 {
		return nil, newRevertError(result)
	}
	return result.Return(), result.Err
}

// Call executes the given transaction on the state for the given block number, but the signature check of tempo is skipped.
//
// Additionally, the caller can specify a batch of contract for fields overriding.
//
// Note, this function doesn't make and changes in the state/blockchain and is
// useful to execute and retrieve values.
func (s *BlockChainAPI) Call_tempo(ctx context.Context, args TransactionArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *StateOverride, blockOverrides *BlockOverrides) (hexutil.Bytes, error) {
	result, err := DoCall_tempo(ctx, s.b, args, blockNrOrHash, overrides, blockOverrides, s.b.RPCEVMTimeout(), s.b.RPCGasCap())
	// log an error message that says test
	if err != nil {
		return nil, err
	}
	// If the result contains a revert reason, try to unpack and return it.
	if len(result.Revert()) > 0 {
		return nil, newRevertError(result)
	}
	return result.Return(), result.Err
}

// single multicall makes a single call, given a header and state
// returns an object containing the return data, or error if one occured
// the result should be merged together later by multicall function
func DoSingleMulticall(ctx context.Context, b Backend, args TransactionArgs, state *state.StateDB, header *types.Header, timeout time.Duration, globalGasCap uint64) map[string]interface{} {
	defer func(start time.Time) { log.Debug("Executing EVM call finished", "runtime", time.Since(start)) }(time.Now())

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	// Get a new instance of the EVM.
	msg, err := args.ToMessage(globalGasCap, header.BaseFee)
	if err != nil {
		return map[string]interface{}{
			"error": err,
		}
	}
	blockCtx := core.NewEVMBlockContext(header, NewChainContext(ctx, b), nil)
	// if blockOverrides != nil {
	// 	blockOverrides.Apply(&blockCtx)
	// }
	evm, vmError := b.GetEVM(ctx, msg, state, header, &vm.Config{NoBaseFee: true}, &blockCtx)
	if err != nil {
		return map[string]interface{}{
			"error": err,
		}
	}
	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	go func() {
		<-ctx.Done()
		evm.Cancel()
	}()

	// Execute the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)
	result, err := core.ApplyMessage(evm, msg, gp)
	if err := vmError(); err != nil {
		return map[string]interface{}{
			"error": err,
		}
	}

	// If the timer caused an abort, return an appropriate error message
	if evm.Cancelled() {
		return map[string]interface{}{
			"error": fmt.Errorf("execution aborted (timeout = %v)", timeout),
		}
	}
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Errorf("err: %w (supplied gas %d)", err, msg.GasLimit),
		}
	}
	if len(result.Revert()) > 0 {
		revertErr := newRevertError(result)
		data, _ := json.Marshal(&revertErr)
		var result map[string]interface{}
		json.Unmarshal(data, &result)
		return result
	}
	if result.Err != nil {
		return map[string]interface{}{
			"error": "execution reverted",
		}
	}
	return map[string]interface{}{
		"data": hexutil.Bytes(result.Return()),
	}
}

// multicall makes multiple eth_calls, on one state set by the provided block and overrides.
// returns an array of results [{data: 0x...}], and errors per call tx. the entire call fails if the requested state couldnt be found or overrides failed to be applied
func (s *BlockChainAPI) Multicall(ctx context.Context, txs []TransactionArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *StateOverride) ([]map[string]interface{}, error) {
	results := []map[string]interface{}{}
	state, header, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	if err := overrides.Apply(state); err != nil {
		return nil, err
	}
	for _, tx := range txs {
		thisState := state.Copy() // copy the state, because while eth_calls shouldnt change state, theres nothing stopping someobdy from making a state changing call
		results = append(results, DoSingleMulticall(ctx, s.b, tx, thisState, header, s.b.RPCEVMTimeout(), s.b.RPCGasCap()))
	}
	return results, nil
}

// executeEstimate is a helper that executes the transaction under a given gas limit and returns
// true if the transaction fails for a reason that might be related to not enough gas. A non-nil
// error means execution failed due to reasons unrelated to the gas limit.
func executeEstimate(ctx context.Context, b Backend, args TransactionArgs, state *state.StateDB, header *types.Header, gasCap uint64, gasLimit uint64) (bool, *core.ExecutionResult, error) {
	args.Gas = (*hexutil.Uint64)(&gasLimit)
	result, err := doCall(ctx, b, args, state, header, nil, nil, 0, gasCap)
	if err != nil {
		if errors.Is(err, core.ErrIntrinsicGas) {
			return true, nil, nil // Special case, raise gas limit
		}
		return true, nil, err // Bail out
	}
	return result.Failed(), result, nil
}

func DoEstimateGas(ctx context.Context, b Backend, args TransactionArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *StateOverride, gasCap uint64) (hexutil.Uint64, error) {
	// Binary search the gas requirement, as it may be higher than the amount used
	var (
		lo uint64 // lowest-known gas limit where tx execution fails
		hi uint64 // lowest-known gas limit where tx execution succeeds
	)
	// Use zero address if sender unspecified.
	if args.From == nil {
		args.From = new(common.Address)
	}
	// Determine the highest gas limit can be used during the estimation.
	if args.Gas != nil && uint64(*args.Gas) >= params.TxGas {
		hi = uint64(*args.Gas)
	} else {
		// Retrieve the block to act as the gas ceiling
		block, err := b.BlockByNumberOrHash(ctx, blockNrOrHash)
		if err != nil {
			return 0, err
		}
		if block == nil {
			return 0, errors.New("block not found")
		}
		hi = block.GasLimit()
	}
	// Normalize the max fee per gas the call is willing to spend.
	var feeCap *big.Int
	if args.GasPrice != nil && (args.MaxFeePerGas != nil || args.MaxPriorityFeePerGas != nil) {
		return 0, errors.New("both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified")
	} else if args.GasPrice != nil {
		feeCap = args.GasPrice.ToInt()
	} else if args.MaxFeePerGas != nil {
		feeCap = args.MaxFeePerGas.ToInt()
	} else {
		feeCap = common.Big0
	}

	state, header, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return 0, err
	}
	if err := overrides.Apply(state); err != nil {
		return 0, err
	}

	// Recap the highest gas limit with account's available balance.
	if feeCap.BitLen() != 0 {
		balance := state.GetBalance(*args.From) // from can't be nil
		available := new(big.Int).Set(balance)
		if args.Value != nil {
			if args.Value.ToInt().Cmp(available) >= 0 {
				return 0, core.ErrInsufficientFundsForTransfer
			}
			available.Sub(available, args.Value.ToInt())
		}
		allowance := new(big.Int).Div(available, feeCap)

		// If the allowance is larger than maximum uint64, skip checking
		if allowance.IsUint64() && hi > allowance.Uint64() {
			transfer := args.Value
			if transfer == nil {
				transfer = new(hexutil.Big)
			}
			log.Warn("Gas estimation capped by limited funds", "original", hi, "balance", balance,
				"sent", transfer.ToInt(), "maxFeePerGas", feeCap, "fundable", allowance)
			hi = allowance.Uint64()
		}
	}
	// Recap the highest gas allowance with specified gascap.
	if gasCap != 0 && hi > gasCap {
		log.Warn("Caller gas above allowance, capping", "requested", hi, "cap", gasCap)
		hi = gasCap
	}

	// We first execute the transaction at the highest allowable gas limit, since if this fails we
	// can return error immediately.
	failed, result, err := executeEstimate(ctx, b, args, state.Copy(), header, gasCap, hi)
	if err != nil {
		return 0, err
	}
	if failed {
		if result != nil && result.Err != vm.ErrOutOfGas {
			if len(result.Revert()) > 0 {
				return 0, newRevertError(result)
			}
			return 0, result.Err
		}
		return 0, fmt.Errorf("gas required exceeds allowance (%d)", hi)
	}
	// For almost any transaction, the gas consumed by the unconstrained execution above
	// lower-bounds the gas limit required for it to succeed. One exception is those txs that
	// explicitly check gas remaining in order to successfully execute within a given limit, but we
	// probably don't want to return a lowest possible gas limit for these cases anyway.
	lo = result.UsedGas - 1

	// Binary search for the smallest gas limit that allows the tx to execute successfully.
	for lo+1 < hi {
		mid := (hi + lo) / 2
		if mid > lo*2 {
			// Most txs don't need much higher gas limit than their gas used, and most txs don't
			// require near the full block limit of gas, so the selection of where to bisect the
			// range here is skewed to favor the low side.
			mid = lo * 2
		}
		failed, _, err = executeEstimate(ctx, b, args, state.Copy(), header, gasCap, mid)
		if err != nil {
			// This should not happen under normal conditions since if we make it this far the
			// transaction had run without error at least once before.
			log.Error("execution error in estimate gas", "err", err)
			return 0, err
		}
		if failed {
			lo = mid
		} else {
			hi = mid
		}
	}
	return hexutil.Uint64(hi), nil
}

// EstimateGas returns the lowest possible gas limit that allows the transaction to run
// successfully at block `blockNrOrHash`, or the latest block if `blockNrOrHash` is unspecified. It
// returns error if the transaction would revert or if there are unexpected failures. The returned
// value is capped by both `args.Gas` (if non-nil & non-zero) and the backend's RPCGasCap
// configuration (if non-zero).
func (s *BlockChainAPI) EstimateGas(ctx context.Context, args TransactionArgs, blockNrOrHash *rpc.BlockNumberOrHash, overrides *StateOverride) (hexutil.Uint64, error) {
	bNrOrHash := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	if blockNrOrHash != nil {
		bNrOrHash = *blockNrOrHash
	}
	return DoEstimateGas(ctx, s.b, args, bNrOrHash, overrides, s.b.RPCGasCap())
}

func DoEstimateGas_tempo(ctx context.Context, b Backend, args TransactionArgs, blockNrOrHash rpc.BlockNumberOrHash, gasCap uint64) (hexutil.Uint64, error) {
	// Binary search the gas requirement, as it may be higher than the amount used
	var (
		lo  uint64 = params.TxGas - 1
		hi  uint64
		cap uint64
	)
	// Use zero address if sender unspecified.
	if args.From == nil {
		args.From = new(common.Address)
	}
	// Determine the highest gas limit can be used during the estimation.
	if args.Gas != nil && uint64(*args.Gas) >= params.TxGas {
		hi = uint64(*args.Gas)
	} else {
		// Retrieve the block to act as the gas ceiling
		block, err := b.BlockByNumberOrHash(ctx, blockNrOrHash)
		if err != nil {
			return 0, err
		}
		if block == nil {
			return 0, errors.New("block not found")
		}
		hi = block.GasLimit()
	}
	// Normalize the max fee per gas the call is willing to spend.
	var feeCap *big.Int
	if args.GasPrice != nil && (args.MaxFeePerGas != nil || args.MaxPriorityFeePerGas != nil) {
		return 0, errors.New("both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified")
	} else if args.GasPrice != nil {
		feeCap = args.GasPrice.ToInt()
	} else if args.MaxFeePerGas != nil {
		feeCap = args.MaxFeePerGas.ToInt()
	} else {
		feeCap = common.Big0
	}
	// Recap the highest gas limit with account's available balance.
	if feeCap.BitLen() != 0 {
		state, _, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
		if err != nil {
			return 0, err
		}
		balance := state.GetBalance(*args.From) // from can't be nil
		available := new(big.Int).Set(balance)
		if args.Value != nil {
			if args.Value.ToInt().Cmp(available) >= 0 {
				return 0, core.ErrInsufficientFundsForTransfer
			}
			available.Sub(available, args.Value.ToInt())
		}
		allowance := new(big.Int).Div(available, feeCap)

		// If the allowance is larger than maximum uint64, skip checking
		if allowance.IsUint64() && hi > allowance.Uint64() {
			transfer := args.Value
			if transfer == nil {
				transfer = new(hexutil.Big)
			}
			log.Warn("Gas estimation capped by limited funds", "original", hi, "balance", balance,
				"sent", transfer.ToInt(), "maxFeePerGas", feeCap, "fundable", allowance)
			hi = allowance.Uint64()
		}
	}
	// Recap the highest gas allowance with specified gascap.
	if gasCap != 0 && hi > gasCap {
		log.Warn("Caller gas above allowance, capping", "requested", hi, "cap", gasCap)
		hi = gasCap
	}
	cap = hi

	// Create a helper to check if a gas allowance results in an executable transaction
	executable := func(gas uint64) (bool, *core.ExecutionResult, error) {
		args.Gas = (*hexutil.Uint64)(&gas)

		result, err := DoCall_tempo(ctx, b, args, blockNrOrHash, nil, nil, 0, gasCap)
		if err != nil {
			if errors.Is(err, core.ErrIntrinsicGas) {
				return true, nil, nil // Special case, raise gas limit
			}
			return true, nil, err // Bail out
		}
		return result.Failed(), result, nil
	}
	// Execute the binary search and hone in on an executable gas limit
	for lo+1 < hi {
		mid := (hi + lo) / 2
		failed, _, err := executable(mid)

		// If the error is not nil(consensus error), it means the provided message
		// call or transaction will never be accepted no matter how much gas it is
		// assigned. Return the error directly, don't struggle any more.
		if err != nil {
			return 0, err
		}
		if failed {
			lo = mid
		} else {
			hi = mid
		}
	}
	// Reject the transaction as invalid if it still fails at the highest allowance
	if hi == cap {
		failed, result, err := executable(hi)
		if err != nil {
			return 0, err
		}
		if failed {
			if result != nil && result.Err != vm.ErrOutOfGas {
				if len(result.Revert()) > 0 {
					return 0, newRevertError(result)
				}
				return 0, result.Err
			}
			// Otherwise, the specified gas cap is too low
			return 0, fmt.Errorf("gas required exceeds allowance (%d)", cap)
		}
	}
	return hexutil.Uint64(hi), nil
}

// EstimateGas returns an estimate of the amount of gas needed to execute the
// given transaction against the current pending block.
func (s *BlockChainAPI) EstimateGas_tempo(ctx context.Context, args TransactionArgs, blockNrOrHash *rpc.BlockNumberOrHash) (hexutil.Uint64, error) {
	bNrOrHash := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	if blockNrOrHash != nil {
		bNrOrHash = *blockNrOrHash
	}
	return DoEstimateGas_tempo(ctx, s.b, args, bNrOrHash, s.b.RPCGasCap())
}

// RPCMarshalHeader converts the given header to the RPC output .
func RPCMarshalHeader(head *types.Header) map[string]interface{} {
	result := map[string]interface{}{
		"number":           (*hexutil.Big)(head.Number),
		"hash":             head.Hash(),
		"parentHash":       head.ParentHash,
		"nonce":            head.Nonce,
		"mixHash":          head.MixDigest,
		"sha3Uncles":       head.UncleHash,
		"logsBloom":        head.Bloom,
		"stateRoot":        head.Root,
		"miner":            head.Coinbase,
		"difficulty":       (*hexutil.Big)(head.Difficulty),
		"extraData":        hexutil.Bytes(head.Extra),
		"gasLimit":         hexutil.Uint64(head.GasLimit),
		"gasUsed":          hexutil.Uint64(head.GasUsed),
		"timestamp":        hexutil.Uint64(head.Time),
		"transactionsRoot": head.TxHash,
		"receiptsRoot":     head.ReceiptHash,
	}
	if head.BaseFee != nil {
		result["baseFeePerGas"] = (*hexutil.Big)(head.BaseFee)
	}
	if head.WithdrawalsHash != nil {
		result["withdrawalsRoot"] = head.WithdrawalsHash
	}
	if head.BlobGasUsed != nil {
		result["blobGasUsed"] = hexutil.Uint64(*head.BlobGasUsed)
	}
	if head.ExcessBlobGas != nil {
		result["excessBlobGas"] = hexutil.Uint64(*head.ExcessBlobGas)
	}
	if head.ParentBeaconRoot != nil {
		result["parentBeaconBlockRoot"] = head.ParentBeaconRoot
	}
	return result
}

// RPCMarshalBlock converts the given block to the RPC output which depends on fullTx. If inclTx is true transactions are
// returned. When fullTx is true the returned block contains full transaction details, otherwise it will only contain
// transaction hashes.
func RPCMarshalBlock(block *types.Block, inclTx bool, fullTx bool, config *params.ChainConfig) map[string]interface{} {
	fields := RPCMarshalHeader(block.Header())
	fields["size"] = hexutil.Uint64(block.Size())

	if inclTx {
		formatTx := func(idx int, tx *types.Transaction) interface{} {
			return tx.Hash()
		}
		if fullTx {
			formatTx = func(idx int, tx *types.Transaction) interface{} {
				return newRPCTransactionFromBlockIndex(block, uint64(idx), config)
			}
		}
		txs := block.Transactions()
		transactions := make([]interface{}, len(txs))
		for i, tx := range txs {
			transactions[i] = formatTx(i, tx)
		}
		fields["transactions"] = transactions
	}
	uncles := block.Uncles()
	uncleHashes := make([]common.Hash, len(uncles))
	for i, uncle := range uncles {
		uncleHashes[i] = uncle.Hash()
	}
	fields["uncles"] = uncleHashes
	if block.Header().WithdrawalsHash != nil {
		fields["withdrawals"] = block.Withdrawals()
	}
	return fields
}

func RPCMarshalCompactHeader(header *types.Header) map[string]interface{} {
	return map[string]interface{}{
		"number":     (*hexutil.Big)(header.Number),
		"hash":       header.Hash(),
		"parentHash": header.ParentHash,
	}
}

func RPCMarshalCompactLogs(logs [][]*types.Log) []map[string]interface{} {
	logMap := []map[string]interface{}{}
	for _, txLog := range logs {
		for _, log := range txLog {
			logMap = append(logMap, map[string]interface{}{
				"address": log.Address,
				"data":    hexutil.Bytes(log.Data),
				"topics":  log.Topics,
			})
		}
	}
	return logMap
}

// rpcMarshalHeader uses the generalized output filler, then adds the total difficulty field, which requires
// a `BlockchainAPI`.
func (s *BlockChainAPI) rpcMarshalHeader(ctx context.Context, header *types.Header) map[string]interface{} {
	fields := RPCMarshalHeader(header)
	fields["totalDifficulty"] = (*hexutil.Big)(s.b.GetTd(ctx, header.Hash()))
	return fields
}

// rpcMarshalBlock uses the generalized output filler, then adds the total difficulty field, which requires
// a `BlockchainAPI`.
func (s *BlockChainAPI) rpcMarshalBlock(ctx context.Context, b *types.Block, inclTx bool, fullTx bool) (map[string]interface{}, error) {
	fields := RPCMarshalBlock(b, inclTx, fullTx, s.b.ChainConfig())
	if inclTx {
		fields["totalDifficulty"] = (*hexutil.Big)(s.b.GetTd(ctx, b.Hash()))
	}
	return fields, nil
}

// RPCTransaction represents a transaction that will serialize to the RPC representation of a transaction
type RPCTransaction struct {
	BlockHash           *common.Hash      `json:"blockHash"`
	BlockNumber         *hexutil.Big      `json:"blockNumber"`
	From                common.Address    `json:"from"`
	Gas                 hexutil.Uint64    `json:"gas"`
	GasPrice            *hexutil.Big      `json:"gasPrice"`
	GasFeeCap           *hexutil.Big      `json:"maxFeePerGas,omitempty"`
	GasTipCap           *hexutil.Big      `json:"maxPriorityFeePerGas,omitempty"`
	MaxFeePerBlobGas    *hexutil.Big      `json:"maxFeePerBlobGas,omitempty"`
	Hash                common.Hash       `json:"hash"`
	Input               hexutil.Bytes     `json:"input"`
	Nonce               hexutil.Uint64    `json:"nonce"`
	To                  *common.Address   `json:"to"`
	TransactionIndex    *hexutil.Uint64   `json:"transactionIndex"`
	Value               *hexutil.Big      `json:"value"`
	Type                hexutil.Uint64    `json:"type"`
	Accesses            *types.AccessList `json:"accessList,omitempty"`
	ChainID             *hexutil.Big      `json:"chainId,omitempty"`
	BlobVersionedHashes []common.Hash     `json:"blobVersionedHashes,omitempty"`
	V                   *hexutil.Big      `json:"v"`
	R                   *hexutil.Big      `json:"r"`
	S                   *hexutil.Big      `json:"s"`
	YParity             *hexutil.Uint64   `json:"yParity,omitempty"`
}

// newRPCTransaction returns a transaction that will serialize to the RPC
// representation, with the given location metadata set (if available).
func newRPCTransaction(tx *types.Transaction, blockHash common.Hash, blockNumber uint64, blockTime uint64, index uint64, baseFee *big.Int, config *params.ChainConfig) *RPCTransaction {
	signer := types.MakeSigner(config, new(big.Int).SetUint64(blockNumber), blockTime)
	from, _ := types.Sender(signer, tx)
	v, r, s := tx.RawSignatureValues()
	result := &RPCTransaction{
		Type:     hexutil.Uint64(tx.Type()),
		From:     from,
		Gas:      hexutil.Uint64(tx.Gas()),
		GasPrice: (*hexutil.Big)(tx.GasPrice()),
		Hash:     tx.Hash(),
		Input:    hexutil.Bytes(tx.Data()),
		Nonce:    hexutil.Uint64(tx.Nonce()),
		To:       tx.To(),
		Value:    (*hexutil.Big)(tx.Value()),
		V:        (*hexutil.Big)(v),
		R:        (*hexutil.Big)(r),
		S:        (*hexutil.Big)(s),
	}
	if blockHash != (common.Hash{}) {
		result.BlockHash = &blockHash
		result.BlockNumber = (*hexutil.Big)(new(big.Int).SetUint64(blockNumber))
		result.TransactionIndex = (*hexutil.Uint64)(&index)
	}

	switch tx.Type() {
	case types.LegacyTxType:
		// if a legacy transaction has an EIP-155 chain id, include it explicitly
		if id := tx.ChainId(); id.Sign() != 0 {
			result.ChainID = (*hexutil.Big)(id)
		}

	case types.AccessListTxType:
		al := tx.AccessList()
		yparity := hexutil.Uint64(v.Sign())
		result.Accesses = &al
		result.ChainID = (*hexutil.Big)(tx.ChainId())
		result.YParity = &yparity

	case types.DynamicFeeTxType:
		al := tx.AccessList()
		yparity := hexutil.Uint64(v.Sign())
		result.Accesses = &al
		result.ChainID = (*hexutil.Big)(tx.ChainId())
		result.YParity = &yparity
		result.GasFeeCap = (*hexutil.Big)(tx.GasFeeCap())
		result.GasTipCap = (*hexutil.Big)(tx.GasTipCap())
		// if the transaction has been mined, compute the effective gas price
		if baseFee != nil && blockHash != (common.Hash{}) {
			// price = min(gasTipCap + baseFee, gasFeeCap)
			result.GasPrice = (*hexutil.Big)(effectiveGasPrice(tx, baseFee))
		} else {
			result.GasPrice = (*hexutil.Big)(tx.GasFeeCap())
		}

	case types.BlobTxType:
		al := tx.AccessList()
		yparity := hexutil.Uint64(v.Sign())
		result.Accesses = &al
		result.ChainID = (*hexutil.Big)(tx.ChainId())
		result.YParity = &yparity
		result.GasFeeCap = (*hexutil.Big)(tx.GasFeeCap())
		result.GasTipCap = (*hexutil.Big)(tx.GasTipCap())
		// if the transaction has been mined, compute the effective gas price
		if baseFee != nil && blockHash != (common.Hash{}) {
			result.GasPrice = (*hexutil.Big)(effectiveGasPrice(tx, baseFee))
		} else {
			result.GasPrice = (*hexutil.Big)(tx.GasFeeCap())
		}
		result.MaxFeePerBlobGas = (*hexutil.Big)(tx.BlobGasFeeCap())
		result.BlobVersionedHashes = tx.BlobHashes()
	}
	return result
}

// effectiveGasPrice computes the transaction gas fee, based on the given basefee value.
//
//	price = min(gasTipCap + baseFee, gasFeeCap)
func effectiveGasPrice(tx *types.Transaction, baseFee *big.Int) *big.Int {
	fee := tx.GasTipCap()
	fee = fee.Add(fee, baseFee)
	if tx.GasFeeCapIntCmp(fee) < 0 {
		return tx.GasFeeCap()
	}
	return fee
}

// NewRPCPendingTransaction returns a pending transaction that will serialize to the RPC representation
func NewRPCPendingTransaction(tx *types.Transaction, current *types.Header, config *params.ChainConfig) *RPCTransaction {
	var (
		baseFee     *big.Int
		blockNumber = uint64(0)
		blockTime   = uint64(0)
	)
	if current != nil {
		baseFee = eip1559.CalcBaseFee(config, current)
		blockNumber = current.Number.Uint64()
		blockTime = current.Time
	}
	return newRPCTransaction(tx, common.Hash{}, blockNumber, blockTime, 0, baseFee, config)
}

// newRPCTransactionFromBlockIndex returns a transaction that will serialize to the RPC representation.
func newRPCTransactionFromBlockIndex(b *types.Block, index uint64, config *params.ChainConfig) *RPCTransaction {
	txs := b.Transactions()
	if index >= uint64(len(txs)) {
		return nil
	}
	return newRPCTransaction(txs[index], b.Hash(), b.NumberU64(), b.Time(), index, b.BaseFee(), config)
}

// newRPCRawTransactionFromBlockIndex returns the bytes of a transaction given a block and a transaction index.
func newRPCRawTransactionFromBlockIndex(b *types.Block, index uint64) hexutil.Bytes {
	txs := b.Transactions()
	if index >= uint64(len(txs)) {
		return nil
	}
	blob, _ := txs[index].MarshalBinary()
	return blob
}

// accessListResult returns an optional accesslist
// It's the result of the `debug_createAccessList` RPC call.
// It contains an error if the transaction itself failed.
type accessListResult struct {
	Accesslist *types.AccessList `json:"accessList"`
	Error      string            `json:"error,omitempty"`
	GasUsed    hexutil.Uint64    `json:"gasUsed"`
}

// CreateAccessList creates an EIP-2930 type AccessList for the given transaction.
// Reexec and BlockNrOrHash can be specified to create the accessList on top of a certain state.
func (s *BlockChainAPI) CreateAccessList(ctx context.Context, args TransactionArgs, blockNrOrHash *rpc.BlockNumberOrHash) (*accessListResult, error) {
	bNrOrHash := rpc.BlockNumberOrHashWithNumber(rpc.PendingBlockNumber)
	if blockNrOrHash != nil {
		bNrOrHash = *blockNrOrHash
	}
	acl, gasUsed, vmerr, err := AccessList(ctx, s.b, bNrOrHash, args)
	if err != nil {
		return nil, err
	}
	result := &accessListResult{Accesslist: &acl, GasUsed: hexutil.Uint64(gasUsed)}
	if vmerr != nil {
		result.Error = vmerr.Error()
	}
	return result, nil
}

// AccessList creates an access list for the given transaction.
// If the accesslist creation fails an error is returned.
// If the transaction itself fails, an vmErr is returned.
func AccessList(ctx context.Context, b Backend, blockNrOrHash rpc.BlockNumberOrHash, args TransactionArgs) (acl types.AccessList, gasUsed uint64, vmErr error, err error) {
	// Retrieve the execution context
	db, header, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if db == nil || err != nil {
		return nil, 0, nil, err
	}
	// If the gas amount is not set, default to RPC gas cap.
	if args.Gas == nil {
		tmp := hexutil.Uint64(b.RPCGasCap())
		args.Gas = &tmp
	}

	// Ensure any missing fields are filled, extract the recipient and input data
	if err := args.setDefaults(ctx, b); err != nil {
		return nil, 0, nil, err
	}
	var to common.Address
	if args.To != nil {
		to = *args.To
	} else {
		to = crypto.CreateAddress(args.from(), uint64(*args.Nonce))
	}
	isPostMerge := header.Difficulty.Cmp(common.Big0) == 0
	// Retrieve the precompiles since they don't need to be added to the access list
	precompiles := vm.ActivePrecompiles(b.ChainConfig().Rules(header.Number, isPostMerge, header.Time))

	// Create an initial tracer
	prevTracer := logger.NewAccessListTracer(nil, args.from(), to, precompiles)
	if args.AccessList != nil {
		prevTracer = logger.NewAccessListTracer(*args.AccessList, args.from(), to, precompiles)
	}
	for {
		// Retrieve the current access list to expand
		accessList := prevTracer.AccessList()
		log.Trace("Creating access list", "input", accessList)

		// Copy the original db so we don't modify it
		statedb := db.Copy()
		// Set the accesslist to the last al
		args.AccessList = &accessList
		msg, err := args.ToMessage(b.RPCGasCap(), header.BaseFee)
		if err != nil {
			return nil, 0, nil, err
		}

		// Apply the transaction with the access list tracer
		tracer := logger.NewAccessListTracer(accessList, args.from(), to, precompiles)
		config := vm.Config{Tracer: tracer, NoBaseFee: true}
		vmenv, _ := b.GetEVM(ctx, msg, statedb, header, &config, nil)
		res, err := core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(msg.GasLimit))
		if err != nil {
			return nil, 0, nil, fmt.Errorf("failed to apply transaction: %v err: %v", args.toTransaction().Hash(), err)
		}
		if tracer.Equal(prevTracer) {
			return accessList, res.UsedGas, res.Err, nil
		}
		prevTracer = tracer
	}
}

// Creates an access list on top of given state
// identical to AccessList, with the exception of state is loaded in arguments
func AccessListOnState(ctx context.Context, b Backend, header *types.Header, db *state.StateDB, args TransactionArgs) (acl types.AccessList, gasUsed uint64, vmErr error, err error) {
	// If the gas amount is not set, extract this as it will depend on access
	// lists and we'll need to reestimate every time
	nogas := args.Gas == nil

	// Ensure any missing fields are filled, extract the recipient and input data
	if err := args.setDefaults(ctx, b); err != nil {
		return nil, 0, nil, err
	}
	var to common.Address
	if args.To != nil {
		to = *args.To
	} else {
		to = crypto.CreateAddress(args.from(), uint64(*args.Nonce))
	}
	// Retrieve the precompiles since they don't need to be added to the access list
	isPostMerge := header.Difficulty.Cmp(common.Big0) == 0
	// Retrieve the precompiles since they don't need to be added to the access list
	precompiles := vm.ActivePrecompiles(b.ChainConfig().Rules(header.Number, isPostMerge, header.Time))

	// Create an initial tracer
	prevTracer := logger.NewAccessListTracer(nil, args.from(), to, precompiles)
	if args.AccessList != nil {
		prevTracer = logger.NewAccessListTracer(*args.AccessList, args.from(), to, precompiles)
	}
	for {
		// Retrieve the current access list to expand
		accessList := prevTracer.AccessList()
		log.Trace("Creating access list", "input", accessList)

		// If no gas amount was specified, each unique access list needs it's own
		// gas calculation. This is quite expensive, but we need to be accurate
		// and it's convered by the sender only anyway.
		if nogas {
			args.Gas = nil
			if err := args.setDefaults(ctx, b); err != nil {
				return nil, 0, nil, err // shouldn't happen, just in case
			}
		}

		statedb := db.Copy() // woops shouldn't have removed this lol
		// Set the accesslist to the last al
		args.AccessList = &accessList
		msg, err := args.ToMessage(b.RPCGasCap(), header.BaseFee)
		if err != nil {
			return nil, 0, nil, err
		}

		// Apply the transaction with the access list tracer
		tracer := logger.NewAccessListTracer(accessList, args.from(), to, precompiles)
		config := vm.Config{Tracer: tracer, NoBaseFee: true}
		vmenv, _ := b.GetEVM(ctx, msg, statedb, header, &config, nil)
		res, err := core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(msg.GasLimit))
		if err != nil {
			return nil, 0, nil, fmt.Errorf("failed to apply transaction: %v err: %v", args.toTransaction().Hash(), err)
		}
		if tracer.Equal(prevTracer) {
			return accessList, res.UsedGas, res.Err, nil
		}
		prevTracer = tracer
	}
}

// TransactionAPI exposes methods for reading and creating transaction data.
type TransactionAPI struct {
	b         Backend
	nonceLock *AddrLocker
	signer    types.Signer
}

// NewTransactionAPI creates a new RPC service with methods for interacting with transactions.
func NewTransactionAPI(b Backend, nonceLock *AddrLocker) *TransactionAPI {
	// The signer used by the API should always be the 'latest' known one because we expect
	// signers to be backwards-compatible with old transactions.
	signer := types.LatestSigner(b.ChainConfig())
	return &TransactionAPI{b, nonceLock, signer}
}

// GetBlockTransactionCountByNumber returns the number of transactions in the block with the given block number.
func (s *TransactionAPI) GetBlockTransactionCountByNumber(ctx context.Context, blockNr rpc.BlockNumber) *hexutil.Uint {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		n := hexutil.Uint(len(block.Transactions()))
		return &n
	}
	return nil
}

// GetBlockTransactionCountByHash returns the number of transactions in the block with the given hash.
func (s *TransactionAPI) GetBlockTransactionCountByHash(ctx context.Context, blockHash common.Hash) *hexutil.Uint {
	if block, _ := s.b.BlockByHash(ctx, blockHash); block != nil {
		n := hexutil.Uint(len(block.Transactions()))
		return &n
	}
	return nil
}

// GetTransactionByBlockNumberAndIndex returns the transaction for the given block number and index.
func (s *TransactionAPI) GetTransactionByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) *RPCTransaction {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		return newRPCTransactionFromBlockIndex(block, uint64(index), s.b.ChainConfig())
	}
	return nil
}

// GetTransactionByBlockHashAndIndex returns the transaction for the given block hash and index.
func (s *TransactionAPI) GetTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) *RPCTransaction {
	if block, _ := s.b.BlockByHash(ctx, blockHash); block != nil {
		return newRPCTransactionFromBlockIndex(block, uint64(index), s.b.ChainConfig())
	}
	return nil
}

// GetRawTransactionByBlockNumberAndIndex returns the bytes of the transaction for the given block number and index.
func (s *TransactionAPI) GetRawTransactionByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) hexutil.Bytes {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		return newRPCRawTransactionFromBlockIndex(block, uint64(index))
	}
	return nil
}

// GetRawTransactionByBlockHashAndIndex returns the bytes of the transaction for the given block hash and index.
func (s *TransactionAPI) GetRawTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) hexutil.Bytes {
	if block, _ := s.b.BlockByHash(ctx, blockHash); block != nil {
		return newRPCRawTransactionFromBlockIndex(block, uint64(index))
	}
	return nil
}

// GetTransactionCount returns the number of transactions the given address has sent for the given block number
func (s *TransactionAPI) GetTransactionCount(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Uint64, error) {
	// Ask transaction pool for the nonce which includes pending transactions
	if blockNr, ok := blockNrOrHash.Number(); ok && blockNr == rpc.PendingBlockNumber {
		nonce, err := s.b.GetPoolNonce(ctx, address)
		if err != nil {
			return nil, err
		}
		return (*hexutil.Uint64)(&nonce), nil
	}
	// Resolve block number and use its state to ask for the nonce
	state, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	nonce := state.GetNonce(address)
	return (*hexutil.Uint64)(&nonce), state.Error()
}

// GetTransactionByHash returns the transaction for the given hash
func (s *TransactionAPI) GetTransactionByHash(ctx context.Context, hash common.Hash) (*RPCTransaction, error) {
	// Try to return an already finalized transaction
	tx, blockHash, blockNumber, index, err := s.b.GetTransaction(ctx, hash)
	if err != nil {
		return nil, err
	}
	if tx != nil {
		header, err := s.b.HeaderByHash(ctx, blockHash)
		if err != nil {
			return nil, err
		}
		return newRPCTransaction(tx, blockHash, blockNumber, header.Time, index, header.BaseFee, s.b.ChainConfig()), nil
	}
	// No finalized transaction, try to retrieve it from the pool
	if tx := s.b.GetPoolTransaction(hash); tx != nil {
		return NewRPCPendingTransaction(tx, s.b.CurrentHeader(), s.b.ChainConfig()), nil
	}

	// Transaction unknown, return as such
	return nil, nil
}

// GetRawTransactionByHash returns the bytes of the transaction for the given hash.
func (s *TransactionAPI) GetRawTransactionByHash(ctx context.Context, hash common.Hash) (hexutil.Bytes, error) {
	// Retrieve a finalized transaction, or a pooled otherwise
	tx, _, _, _, err := s.b.GetTransaction(ctx, hash)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		if tx = s.b.GetPoolTransaction(hash); tx == nil {
			// Transaction not found anywhere, abort
			return nil, nil
		}
	}
	// Serialize to RLP and return
	return tx.MarshalBinary()
}

// GetTransactionReceipt returns the transaction receipt for the given transaction hash.
func (s *TransactionAPI) GetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]interface{}, error) {
	tx, blockHash, blockNumber, index, err := s.b.GetTransaction(ctx, hash)
	if tx == nil || err != nil {
		// When the transaction doesn't exist, the RPC method should return JSON null
		// as per specification.
		return nil, nil
	}
	header, err := s.b.HeaderByHash(ctx, blockHash)
	if err != nil {
		return nil, err
	}
	receipts, err := s.b.GetReceipts(ctx, blockHash)
	if err != nil {
		return nil, err
	}
	if uint64(len(receipts)) <= index {
		return nil, nil
	}
	receipt := receipts[index]

	// Derive the sender.
	signer := types.MakeSigner(s.b.ChainConfig(), header.Number, header.Time)
	return marshalReceipt(receipt, blockHash, blockNumber, signer, tx, int(index)), nil
}

// marshalReceipt marshals a transaction receipt into a JSON object.
func marshalReceipt(receipt *types.Receipt, blockHash common.Hash, blockNumber uint64, signer types.Signer, tx *types.Transaction, txIndex int) map[string]interface{} {
	from, _ := types.Sender(signer, tx)

	fields := map[string]interface{}{
		"blockHash":         blockHash,
		"blockNumber":       hexutil.Uint64(blockNumber),
		"transactionHash":   tx.Hash(),
		"transactionIndex":  hexutil.Uint64(txIndex),
		"from":              from,
		"to":                tx.To(),
		"gasUsed":           hexutil.Uint64(receipt.GasUsed),
		"cumulativeGasUsed": hexutil.Uint64(receipt.CumulativeGasUsed),
		"contractAddress":   nil,
		"logs":              receipt.Logs,
		"logsBloom":         receipt.Bloom,
		"type":              hexutil.Uint(tx.Type()),
		"effectiveGasPrice": (*hexutil.Big)(receipt.EffectiveGasPrice),
	}

	// Assign receipt status or post state.
	if len(receipt.PostState) > 0 {
		fields["root"] = hexutil.Bytes(receipt.PostState)
	} else {
		fields["status"] = hexutil.Uint(receipt.Status)
	}
	if receipt.Logs == nil {
		fields["logs"] = []*types.Log{}
	}

	if tx.Type() == types.BlobTxType {
		fields["blobGasUsed"] = hexutil.Uint64(receipt.BlobGasUsed)
		fields["blobGasPrice"] = (*hexutil.Big)(receipt.BlobGasPrice)
	}

	// If the ContractAddress is 20 0x0 bytes, assume it is not a contract creation
	if receipt.ContractAddress != (common.Address{}) {
		fields["contractAddress"] = receipt.ContractAddress
	}
	return fields
}

// sign is a helper function that signs a transaction with the private key of the given address.
func (s *TransactionAPI) sign(addr common.Address, tx *types.Transaction) (*types.Transaction, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: addr}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	// Request the wallet to sign the transaction
	return wallet.SignTx(account, tx, s.b.ChainConfig().ChainID)
}

// SubmitTransaction is a helper function that submits tx to txPool and logs a message.
func SubmitTransaction(ctx context.Context, b Backend, tx *types.Transaction) (common.Hash, error) {
	// If the transaction fee cap is already specified, ensure the
	// fee of the given transaction is _reasonable_.
	if err := checkTxFee(tx.GasPrice(), tx.Gas(), b.RPCTxFeeCap()); err != nil {
		return common.Hash{}, err
	}
	if !b.UnprotectedAllowed() && !tx.Protected() {
		// Ensure only eip155 signed transactions are submitted if EIP155Required is set.
		return common.Hash{}, errors.New("only replay-protected (EIP-155) transactions allowed over RPC")
	}
	if err := b.SendTx(ctx, tx); err != nil {
		return common.Hash{}, err
	}
	// Print a log with full tx details for manual investigations and interventions
	head := b.CurrentBlock()
	signer := types.MakeSigner(b.ChainConfig(), head.Number, head.Time)
	from, err := types.Sender(signer, tx)
	if err != nil {
		return common.Hash{}, err
	}

	if tx.To() == nil {
		addr := crypto.CreateAddress(from, tx.Nonce())
		log.Info("Submitted contract creation", "hash", tx.Hash().Hex(), "from", from, "nonce", tx.Nonce(), "contract", addr.Hex(), "value", tx.Value())
	} else {
		log.Info("Submitted transaction", "hash", tx.Hash().Hex(), "from", from, "nonce", tx.Nonce(), "recipient", tx.To(), "value", tx.Value())
	}
	return tx.Hash(), nil
}

// SendTransaction creates a transaction for the given argument, sign it and submit it to the
// transaction pool.
func (s *TransactionAPI) SendTransaction(ctx context.Context, args TransactionArgs) (common.Hash, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: args.from()}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return common.Hash{}, err
	}

	if args.Nonce == nil {
		// Hold the mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.from())
		defer s.nonceLock.UnlockAddr(args.from())
	}

	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b); err != nil {
		return common.Hash{}, err
	}
	// Assemble the transaction and sign with the wallet
	tx := args.toTransaction()

	signed, err := wallet.SignTx(account, tx, s.b.ChainConfig().ChainID)
	if err != nil {
		return common.Hash{}, err
	}
	return SubmitTransaction(ctx, s.b, signed)
}

// FillTransaction fills the defaults (nonce, gas, gasPrice or 1559 fields)
// on a given unsigned transaction, and returns it to the caller for further
// processing (signing + broadcast).
func (s *TransactionAPI) FillTransaction(ctx context.Context, args TransactionArgs) (*SignTransactionResult, error) {
	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b); err != nil {
		return nil, err
	}
	// Assemble the transaction and obtain rlp
	tx := args.toTransaction()
	data, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &SignTransactionResult{data, tx}, nil
}

// SendRawTransaction will add the signed transaction to the transaction pool.
// The sender is responsible for signing the transaction and using the correct nonce.
func (s *TransactionAPI) SendRawTransaction(ctx context.Context, input hexutil.Bytes) (common.Hash, error) {
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(input); err != nil {
		return common.Hash{}, err
	}
	return SubmitTransaction(ctx, s.b, tx)
}

// Sign calculates an ECDSA signature for:
// keccak256("\x19Ethereum Signed Message:\n" + len(message) + message).
//
// Note, the produced signature conforms to the secp256k1 curve R, S and V values,
// where the V value will be 27 or 28 for legacy reasons.
//
// The account associated with addr must be unlocked.
//
// https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_sign
func (s *TransactionAPI) Sign(addr common.Address, data hexutil.Bytes) (hexutil.Bytes, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: addr}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	// Sign the requested hash with the wallet
	signature, err := wallet.SignText(account, data)
	if err == nil {
		signature[64] += 27 // Transform V from 0/1 to 27/28 according to the yellow paper
	}
	return signature, err
}

// SignTransactionResult represents a RLP encoded signed transaction.
type SignTransactionResult struct {
	Raw hexutil.Bytes      `json:"raw"`
	Tx  *types.Transaction `json:"tx"`
}

// SignTransaction will sign the given transaction with the from account.
// The node needs to have the private key of the account corresponding with
// the given from address and it needs to be unlocked.
func (s *TransactionAPI) SignTransaction(ctx context.Context, args TransactionArgs) (*SignTransactionResult, error) {
	if args.Gas == nil {
		return nil, errors.New("gas not specified")
	}
	if args.GasPrice == nil && (args.MaxPriorityFeePerGas == nil || args.MaxFeePerGas == nil) {
		return nil, errors.New("missing gasPrice or maxFeePerGas/maxPriorityFeePerGas")
	}
	if args.Nonce == nil {
		return nil, errors.New("nonce not specified")
	}
	if err := args.setDefaults(ctx, s.b); err != nil {
		return nil, err
	}
	// Before actually sign the transaction, ensure the transaction fee is reasonable.
	tx := args.toTransaction()
	if err := checkTxFee(tx.GasPrice(), tx.Gas(), s.b.RPCTxFeeCap()); err != nil {
		return nil, err
	}
	signed, err := s.sign(args.from(), tx)
	if err != nil {
		return nil, err
	}
	data, err := signed.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &SignTransactionResult{data, signed}, nil
}

// PendingTransactions returns the transactions that are in the transaction pool
// and have a from address that is one of the accounts this node manages.
func (s *TransactionAPI) PendingTransactions() ([]*RPCTransaction, error) {
	pending, err := s.b.GetPoolTransactions()
	if err != nil {
		return nil, err
	}
	accounts := make(map[common.Address]struct{})
	for _, wallet := range s.b.AccountManager().Wallets() {
		for _, account := range wallet.Accounts() {
			accounts[account.Address] = struct{}{}
		}
	}
	curHeader := s.b.CurrentHeader()
	transactions := make([]*RPCTransaction, 0, len(pending))
	for _, tx := range pending {
		from, _ := types.Sender(s.signer, tx)
		if _, exists := accounts[from]; exists {
			transactions = append(transactions, NewRPCPendingTransaction(tx, curHeader, s.b.ChainConfig()))
		}
	}
	return transactions, nil
}

// Resend accepts an existing transaction and a new gas price and limit. It will remove
// the given transaction from the pool and reinsert it with the new gas price and limit.
func (s *TransactionAPI) Resend(ctx context.Context, sendArgs TransactionArgs, gasPrice *hexutil.Big, gasLimit *hexutil.Uint64) (common.Hash, error) {
	if sendArgs.Nonce == nil {
		return common.Hash{}, errors.New("missing transaction nonce in transaction spec")
	}
	if err := sendArgs.setDefaults(ctx, s.b); err != nil {
		return common.Hash{}, err
	}
	matchTx := sendArgs.toTransaction()

	// Before replacing the old transaction, ensure the _new_ transaction fee is reasonable.
	var price = matchTx.GasPrice()
	if gasPrice != nil {
		price = gasPrice.ToInt()
	}
	var gas = matchTx.Gas()
	if gasLimit != nil {
		gas = uint64(*gasLimit)
	}
	if err := checkTxFee(price, gas, s.b.RPCTxFeeCap()); err != nil {
		return common.Hash{}, err
	}
	// Iterate the pending list for replacement
	pending, err := s.b.GetPoolTransactions()
	if err != nil {
		return common.Hash{}, err
	}
	for _, p := range pending {
		wantSigHash := s.signer.Hash(matchTx)
		pFrom, err := types.Sender(s.signer, p)
		if err == nil && pFrom == sendArgs.from() && s.signer.Hash(p) == wantSigHash {
			// Match. Re-sign and send the transaction.
			if gasPrice != nil && (*big.Int)(gasPrice).Sign() != 0 {
				sendArgs.GasPrice = gasPrice
			}
			if gasLimit != nil && *gasLimit != 0 {
				sendArgs.Gas = gasLimit
			}
			signedTx, err := s.sign(sendArgs.from(), sendArgs.toTransaction())
			if err != nil {
				return common.Hash{}, err
			}
			if err = s.b.SendTx(ctx, signedTx); err != nil {
				return common.Hash{}, err
			}
			return signedTx.Hash(), nil
		}
	}
	return common.Hash{}, fmt.Errorf("transaction %#x not found", matchTx.Hash())
}

// DebugAPI is the collection of Ethereum APIs exposed over the debugging
// namespace.
type DebugAPI struct {
	b Backend
}

// NewDebugAPI creates a new instance of DebugAPI.
func NewDebugAPI(b Backend) *DebugAPI {
	return &DebugAPI{b: b}
}

// GetRawHeader retrieves the RLP encoding for a single header.
func (api *DebugAPI) GetRawHeader(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	var hash common.Hash
	if h, ok := blockNrOrHash.Hash(); ok {
		hash = h
	} else {
		block, err := api.b.BlockByNumberOrHash(ctx, blockNrOrHash)
		if err != nil {
			return nil, err
		}
		hash = block.Hash()
	}
	header, _ := api.b.HeaderByHash(ctx, hash)
	if header == nil {
		return nil, fmt.Errorf("header #%d not found", hash)
	}
	return rlp.EncodeToBytes(header)
}

// GetRawBlock retrieves the RLP encoded for a single block.
func (api *DebugAPI) GetRawBlock(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	var hash common.Hash
	if h, ok := blockNrOrHash.Hash(); ok {
		hash = h
	} else {
		block, err := api.b.BlockByNumberOrHash(ctx, blockNrOrHash)
		if err != nil {
			return nil, err
		}
		hash = block.Hash()
	}
	block, _ := api.b.BlockByHash(ctx, hash)
	if block == nil {
		return nil, fmt.Errorf("block #%d not found", hash)
	}
	return rlp.EncodeToBytes(block)
}

// GetRawReceipts retrieves the binary-encoded receipts of a single block.
func (api *DebugAPI) GetRawReceipts(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) ([]hexutil.Bytes, error) {
	var hash common.Hash
	if h, ok := blockNrOrHash.Hash(); ok {
		hash = h
	} else {
		block, err := api.b.BlockByNumberOrHash(ctx, blockNrOrHash)
		if err != nil {
			return nil, err
		}
		hash = block.Hash()
	}
	receipts, err := api.b.GetReceipts(ctx, hash)
	if err != nil {
		return nil, err
	}
	result := make([]hexutil.Bytes, len(receipts))
	for i, receipt := range receipts {
		b, err := receipt.MarshalBinary()
		if err != nil {
			return nil, err
		}
		result[i] = b
	}
	return result, nil
}

// GetRawTransaction returns the bytes of the transaction for the given hash.
func (s *DebugAPI) GetRawTransaction(ctx context.Context, hash common.Hash) (hexutil.Bytes, error) {
	// Retrieve a finalized transaction, or a pooled otherwise
	tx, _, _, _, err := s.b.GetTransaction(ctx, hash)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		if tx = s.b.GetPoolTransaction(hash); tx == nil {
			// Transaction not found anywhere, abort
			return nil, nil
		}
	}
	return tx.MarshalBinary()
}

// PrintBlock retrieves a block and returns its pretty printed form.
func (api *DebugAPI) PrintBlock(ctx context.Context, number uint64) (string, error) {
	block, _ := api.b.BlockByNumber(ctx, rpc.BlockNumber(number))
	if block == nil {
		return "", fmt.Errorf("block #%d not found", number)
	}
	return spew.Sdump(block), nil
}

// ChaindbProperty returns leveldb properties of the key-value database.
func (api *DebugAPI) ChaindbProperty(property string) (string, error) {
	return api.b.ChainDb().Stat(property)
}

// ChaindbCompact flattens the entire key-value database into a single level,
// removing all unused slots and merging all keys.
func (api *DebugAPI) ChaindbCompact() error {
	cstart := time.Now()
	for b := 0; b <= 255; b++ {
		var (
			start = []byte{byte(b)}
			end   = []byte{byte(b + 1)}
		)
		if b == 255 {
			end = nil
		}
		log.Info("Compacting database", "range", fmt.Sprintf("%#X-%#X", start, end), "elapsed", common.PrettyDuration(time.Since(cstart)))
		if err := api.b.ChainDb().Compact(start, end); err != nil {
			log.Error("Database compaction failed", "err", err)
			return err
		}
	}
	return nil
}

// SetHead rewinds the head of the blockchain to a previous block.
func (api *DebugAPI) SetHead(number hexutil.Uint64) {
	api.b.SetHead(uint64(number))
}

// NetAPI offers network related RPC methods
type NetAPI struct {
	net            *p2p.Server
	networkVersion uint64
}

// NewNetAPI creates a new net API instance.
func NewNetAPI(net *p2p.Server, networkVersion uint64) *NetAPI {
	return &NetAPI{net, networkVersion}
}

// Listening returns an indication if the node is listening for network connections.
func (s *NetAPI) Listening() bool {
	return true // always listening
}

// PeerCount returns the number of connected peers
func (s *NetAPI) PeerCount() hexutil.Uint {
	return hexutil.Uint(s.net.PeerCount())
}

// Version returns the current ethereum protocol version.
func (s *NetAPI) Version() string {
	return fmt.Sprintf("%d", s.networkVersion)
}

// checkTxFee is an internal function used to check whether the fee of
// the given transaction is _reasonable_(under the cap).
func checkTxFee(gasPrice *big.Int, gas uint64, cap float64) error {
	// Short circuit if there is no cap for transaction fee at all.
	if cap == 0 {
		return nil
	}
	feeEth := new(big.Float).Quo(new(big.Float).SetInt(new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(gas))), new(big.Float).SetInt(big.NewInt(params.Ether)))
	feeFloat, _ := feeEth.Float64()
	if feeFloat > cap {
		return fmt.Errorf("tx fee (%.2f ether) exceeds the configured cap (%.2f ether)", feeFloat, cap)
	}
	return nil
}

// toHexSlice creates a slice of hex-strings based on []byte.
func toHexSlice(b [][]byte) []string {
	r := make([]string, len(b))
	for i := range b {
		r[i] = hexutil.Encode(b[i])
	}
	return r
}

// MEVEXEC ADDITIONS
// the following are additional rpc methods added into the execution client for mev searchers

// BlockChainAPI provides an API to access Ethereum blockchain data.
type SearcherAPI struct {
	b     Backend
	chain *core.BlockChain
}

func NewSearcherAPI(b Backend, chain *core.BlockChain) *SearcherAPI {
	return &SearcherAPI{b, chain}
}

// CallBundleArgs represents the arguments for a call.
type CallBundleArgs struct {
	Txs                    []hexutil.Bytes       `json:"txs"`
	BlockNumber            rpc.BlockNumber       `json:"blockNumber"`
	StateBlockNumberOrHash rpc.BlockNumberOrHash `json:"stateBlockNumber"`
	Coinbase               *string               `json:"coinbase"`
	Timestamp              *uint64               `json:"timestamp"`
	Timeout                *int64                `json:"timeout"`
	GasLimit               *uint64               `json:"gasLimit"`
	Difficulty             *hexutil.Big          `json:"difficulty"`
	BaseFee                *hexutil.Big          `json:"baseFee"`
	SimulationLogs         bool                  `json:"simulationLogs"`
	CreateAccessList       bool                  `json:"createAccessList"`
	StateOverrides         *StateOverride        `json:"stateOverrides"`
	MixDigest              *common.Hash          `json:"mixDigest"`
}

// CallBundleArgs represents the arguments for a call.
type CallBundleSignedByOther struct {
	Txs                    []hexutil.Bytes       `json:"txs"`
	TxsSignedByOther       []hexutil.Bytes       `json:"txsSignedByOther"`
	OriginalSenders        []common.Address      `json:"originalSenders"`
	BlockNumber            rpc.BlockNumber       `json:"blockNumber"`
	StateBlockNumberOrHash rpc.BlockNumberOrHash `json:"stateBlockNumber"`
	Coinbase               *string               `json:"coinbase"`
	Timestamp              *uint64               `json:"timestamp"`
	Timeout                *int64                `json:"timeout"`
	GasLimit               *uint64               `json:"gasLimit"`
	Difficulty             *hexutil.Big          `json:"difficulty"`
	BaseFee                *hexutil.Big          `json:"baseFee"`
	SimulationLogs         bool                  `json:"simulationLogs"`
	CreateAccessList       bool                  `json:"createAccessList"`
	StateOverrides         *StateOverride        `json:"stateOverrides"`
}

// CallBundle will simulate a bundle of transactions at the top of a given block
// number with the state of another (or the same) block. This can be used to
// simulate future blocks with the current state, or it can be used to simulate
// a past block.
// The sender is responsible for signing the transactions and using the correct
// nonce and ensuring validity
func (s *SearcherAPI) CallBundle(ctx context.Context, args CallBundleArgs) (map[string]interface{}, error) {
	if len(args.Txs) == 0 {
		return nil, errors.New("bundle missing txs")
	}
	if args.BlockNumber == 0 {
		return nil, errors.New("bundle missing blockNumber")
	}

	var txs types.Transactions

	for _, encodedTx := range args.Txs {
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(encodedTx); err != nil {
			return nil, err
		}
		log.Debug("Decoded tx", "tx", tx)
		txs = append(txs, tx)
	}
	defer func(start time.Time) { log.Debug("Executing EVM call finished", "runtime", time.Since(start)) }(time.Now())

	timeoutMilliSeconds := int64(5000)
	if args.Timeout != nil {
		timeoutMilliSeconds = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMilliSeconds)
	state, parent, err := s.b.StateAndHeaderByNumberOrHash(ctx, args.StateBlockNumberOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	if err := args.StateOverrides.Apply(state); err != nil {
		return nil, err
	}
	blockNumber := big.NewInt(int64(args.BlockNumber))

	timestamp := parent.Time + 1
	if args.Timestamp != nil {
		timestamp = *args.Timestamp
	}
	coinbase := parent.Coinbase
	if args.Coinbase != nil {
		coinbase = common.HexToAddress(*args.Coinbase)
	}
	difficulty := parent.Difficulty
	if args.Difficulty != nil {
		difficulty = args.Difficulty.ToInt()
	}
	gasLimit := parent.GasLimit
	if args.GasLimit != nil {
		gasLimit = *args.GasLimit
	}
	var baseFee *big.Int
	if args.BaseFee != nil {
		baseFee = args.BaseFee.ToInt()
	} else if s.b.ChainConfig().IsLondon(big.NewInt(args.BlockNumber.Int64())) {
		baseFee = eip1559.CalcBaseFee(s.b.ChainConfig(), parent)
	}
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     blockNumber,
		GasLimit:   gasLimit,
		Time:       timestamp,
		Difficulty: difficulty,
		Coinbase:   coinbase,
		BaseFee:    baseFee,
	}

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	vmconfig := vm.Config{}

	// Setup the gas pool (also for unmetered requests)
	// and apply the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	results := []map[string]interface{}{}
	coinbaseBalanceBefore := state.GetBalance(coinbase)

	bundleHash := sha3.NewLegacyKeccak256()
	signer := types.MakeSigner(s.b.ChainConfig(), blockNumber, header.Time)
	var totalGasUsed uint64
	gasFees := new(big.Int)
	for i, tx := range txs {
		coinbaseBalanceBeforeTx := state.GetBalance(coinbase)
		state.SetTxContext(tx.Hash(), i)

		accessListState := state.Copy() // create a copy just in case we use it later for access list creation

		receipt, result, err := core.ApplyTransaction(s.b.ChainConfig(), s.chain, &coinbase, gp, state, header, tx, &header.GasUsed, vmconfig)
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}

		txHash := tx.Hash().String()
		from, err := types.Sender(signer, tx)
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}
		to := "0x"
		if tx.To() != nil {
			to = tx.To().String()
		}
		jsonResult := map[string]interface{}{
			"txHash":      txHash,
			"gasUsed":     receipt.GasUsed,
			"fromAddress": from.String(),
			"toAddress":   to,
		}
		totalGasUsed += receipt.GasUsed
		gasPrice, err := tx.EffectiveGasTip(header.BaseFee)
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}
		gasFeesTx := new(big.Int).Mul(big.NewInt(int64(receipt.GasUsed)), gasPrice)
		gasFees.Add(gasFees, gasFeesTx)
		bundleHash.Write(tx.Hash().Bytes())
		if result.Err != nil {
			jsonResult["error"] = result.Err.Error()
			revert := result.Revert()
			if len(revert) > 0 {
				jsonResult["revert"] = string(revert)
			}
		} else {
			dst := make([]byte, hex.EncodedLen(len(result.Return())))
			hex.Encode(dst, result.Return())
			jsonResult["value"] = "0x" + string(dst)
		}
		// if simulation logs are requested append it to logs
		if args.SimulationLogs {
			jsonResult["logs"] = receipt.Logs
		}
		// if an access list is requested create and append
		if args.CreateAccessList {
			// ifdk another way to fill all values so this will have to do - x2
			txArgGas := hexutil.Uint64(tx.Gas())
			txArgNonce := hexutil.Uint64(tx.Nonce())
			txArgData := hexutil.Bytes(tx.Data())
			txargs := TransactionArgs{
				From:    &from,
				To:      tx.To(),
				Gas:     &txArgGas,
				Nonce:   &txArgNonce,
				Data:    &txArgData,
				Value:   (*hexutil.Big)(tx.Value()),
				ChainID: (*hexutil.Big)(tx.ChainId()),
			}
			if tx.GasFeeCap().Cmp(big.NewInt(0)) == 0 { // no maxbasefee, set gasprice instead
				txargs.GasPrice = (*hexutil.Big)(tx.GasPrice())
			} else { // otherwise set base and priority fee
				txargs.MaxFeePerGas = (*hexutil.Big)(tx.GasFeeCap())
				txargs.MaxPriorityFeePerGas = (*hexutil.Big)(tx.GasTipCap())
			}
			acl, gasUsed, vmerr, err := AccessListOnState(ctx, s.b, header, accessListState, txargs)
			if err == nil {
				if gasUsed != receipt.GasUsed {
					log.Debug("Gas used in receipt differ from accesslist", "receipt", receipt.GasUsed, "acl", gasUsed) // weird bug but it works
				}
				if vmerr != nil {
					log.Info("CallBundle accesslist creation encountered vmerr", "vmerr", vmerr)
				}
				jsonResult["accessList"] = acl

			} else {
				log.Info("CallBundle accesslist creation encountered err", "err", err)
				jsonResult["accessList"] = acl //
			} // return the empty accesslist either way
		}
		coinbaseDiffTx := new(big.Int).Sub(state.GetBalance(coinbase), coinbaseBalanceBeforeTx)
		jsonResult["coinbaseDiff"] = coinbaseDiffTx.String()
		jsonResult["gasFees"] = gasFeesTx.String()
		jsonResult["ethSentToCoinbase"] = new(big.Int).Sub(coinbaseDiffTx, gasFeesTx).String()
		jsonResult["gasPrice"] = new(big.Int).Div(coinbaseDiffTx, big.NewInt(int64(receipt.GasUsed))).String()
		jsonResult["gasUsed"] = receipt.GasUsed
		results = append(results, jsonResult)
	}

	ret := map[string]interface{}{}
	ret["results"] = results
	coinbaseDiff := new(big.Int).Sub(state.GetBalance(coinbase), coinbaseBalanceBefore)
	ret["coinbaseDiff"] = coinbaseDiff.String()
	ret["gasFees"] = gasFees.String()
	ret["ethSentToCoinbase"] = new(big.Int).Sub(coinbaseDiff, gasFees).String()
	ret["bundleGasPrice"] = new(big.Int).Div(coinbaseDiff, big.NewInt(int64(totalGasUsed))).String()
	ret["totalGasUsed"] = totalGasUsed
	ret["stateBlockNumber"] = parent.Number.Int64()

	ret["bundleHash"] = "0x" + common.Bytes2Hex(bundleHash.Sum(nil))
	return ret, nil
}

// This is a modified version of the function CallBundle
// It is modified to allow for transactions to be signed by different addresses than the one that is sending it.
func (s *SearcherAPI) CallBundleSignedByOther(ctx context.Context, args CallBundleSignedByOther) (map[string]interface{}, error) {
	if len(args.Txs) == 0 {
		return nil, errors.New("bundle missing txs")
	}
	if args.BlockNumber == 0 {
		return nil, errors.New("bundle missing blockNumber")
	}

	var txsSignedByOther types.Transactions
	var txs types.Transactions

	for _, encodedTx := range args.TxsSignedByOther {
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(encodedTx); err != nil {
			return nil, err
		}
		txsSignedByOther = append(txsSignedByOther, tx)
	}

	for _, encodedTx := range args.Txs {
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(encodedTx); err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}
	defer func(start time.Time) { log.Debug("Executing EVM call finished", "runtime", time.Since(start)) }(time.Now())

	timeoutMilliSeconds := int64(5000)
	if args.Timeout != nil {
		timeoutMilliSeconds = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMilliSeconds)
	state, parent, err := s.b.StateAndHeaderByNumberOrHash(ctx, args.StateBlockNumberOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	if err := args.StateOverrides.Apply(state); err != nil {
		return nil, err
	}
	blockNumber := big.NewInt(int64(args.BlockNumber))

	timestamp := parent.Time + 12
	if args.Timestamp != nil {
		timestamp = *args.Timestamp
	}
	coinbase := parent.Coinbase
	if args.Coinbase != nil {
		coinbase = common.HexToAddress(*args.Coinbase)
	}
	difficulty := parent.Difficulty
	if args.Difficulty != nil {
		difficulty = args.Difficulty.ToInt()
	}
	gasLimit := parent.GasLimit
	if args.GasLimit != nil {
		gasLimit = *args.GasLimit
	}
	var baseFee *big.Int
	if args.BaseFee != nil {
		baseFee = args.BaseFee.ToInt()
	} else if s.b.ChainConfig().IsLondon(big.NewInt(args.BlockNumber.Int64())) {
		baseFee = eip1559.CalcBaseFee(s.b.ChainConfig(), parent)
	}
	mixDigest := parent.MixDigest
	if args.MixDigest != nil {
		mixDigest = *args.MixDigest
	}
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     blockNumber,
		GasLimit:   gasLimit,
		Time:       timestamp,
		Difficulty: difficulty,
		Coinbase:   coinbase,
		BaseFee:    baseFee,
		MixDigest:  mixDigest,
	}

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	vmconfig := vm.Config{}

	// Setup the gas pool (also for unmetered requests)
	// and apply the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	results := []map[string]interface{}{}
	coinbaseBalanceBefore := state.GetBalance(coinbase)

	bundleHash := sha3.NewLegacyKeccak256()
	signer := types.MakeSigner(s.b.ChainConfig(), header.Number, header.Time)
	var totalGasUsed uint64
	gasFees := new(big.Int)

	for i, tx := range txsSignedByOther {
		coinbaseBalanceBeforeTx := state.GetBalance(coinbase)
		state.SetTxContext(tx.Hash(), i)

		accessListState := state.Copy() // create a copy just in case we use it later for access list creation
		receipt, result, err := core.ApplyTransactionSignedByOther(s.b.ChainConfig(), s.chain, &coinbase, gp, state, header, tx, &header.GasUsed, vmconfig, args.OriginalSenders[i])
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}

		txHash := tx.Hash().String()
		from, err := types.Sender(signer, tx)
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}
		to := "0x"
		if tx.To() != nil {
			to = tx.To().String()
		}
		jsonResult := map[string]interface{}{
			"txHash":      txHash,
			"gasUsed":     receipt.GasUsed,
			"fromAddress": from.String(),
			"toAddress":   to,
		}
		totalGasUsed += receipt.GasUsed
		gasPrice, err := tx.EffectiveGasTip(header.BaseFee)
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}
		gasFeesTx := new(big.Int).Mul(big.NewInt(int64(receipt.GasUsed)), gasPrice)
		gasFees.Add(gasFees, gasFeesTx)
		bundleHash.Write(tx.Hash().Bytes())
		if result.Err != nil {
			jsonResult["error"] = result.Err.Error()
			revert := result.Revert()
			if len(revert) > 0 {
				jsonResult["revert"] = string(revert)
			}
		} else {
			dst := make([]byte, hex.EncodedLen(len(result.Return())))
			hex.Encode(dst, result.Return())
			jsonResult["value"] = "0x" + string(dst)
		}
		// if simulation logs are requested append it to logs
		if args.SimulationLogs {
			jsonResult["logs"] = receipt.Logs
		}
		// if an access list is requested create and append
		if args.CreateAccessList {
			// ifdk another way to fill all values so this will have to do - x2
			txArgGas := hexutil.Uint64(tx.Gas())
			txArgNonce := hexutil.Uint64(tx.Nonce())
			txArgData := hexutil.Bytes(tx.Data())
			txargs := TransactionArgs{
				From:    &from,
				To:      tx.To(),
				Gas:     &txArgGas,
				Nonce:   &txArgNonce,
				Data:    &txArgData,
				Value:   (*hexutil.Big)(tx.Value()),
				ChainID: (*hexutil.Big)(tx.ChainId()),
			}
			if tx.GasFeeCap().Cmp(big.NewInt(0)) == 0 { // no maxbasefee, set gasprice instead
				txargs.GasPrice = (*hexutil.Big)(tx.GasPrice())
			} else { // otherwise set base and priority fee
				txargs.MaxFeePerGas = (*hexutil.Big)(tx.GasFeeCap())
				txargs.MaxPriorityFeePerGas = (*hexutil.Big)(tx.GasTipCap())
			}
			acl, gasUsed, vmerr, err := AccessListOnState(ctx, s.b, header, accessListState, txargs)
			if err == nil {
				if gasUsed != receipt.GasUsed {
					log.Debug("Gas used in receipt differ from accesslist", "receipt", receipt.GasUsed, "acl", gasUsed) // weird bug but it works
				}
				if vmerr != nil {
					log.Info("CallBundle accesslist creation encountered vmerr", "vmerr", vmerr)
				}
				jsonResult["accessList"] = acl

			} else {
				log.Info("CallBundle accesslist creation encountered err", "err", err)
				jsonResult["accessList"] = acl //
			} // return the empty accesslist either way
		}
		coinbaseDiffTx := new(big.Int).Sub(state.GetBalance(coinbase), coinbaseBalanceBeforeTx)
		jsonResult["coinbaseDiff"] = coinbaseDiffTx.String()
		jsonResult["gasFees"] = gasFeesTx.String()
		jsonResult["ethSentToCoinbase"] = new(big.Int).Sub(coinbaseDiffTx, gasFeesTx).String()
		jsonResult["gasPrice"] = new(big.Int).Div(coinbaseDiffTx, big.NewInt(int64(receipt.GasUsed))).String()
		jsonResult["gasUsed"] = receipt.GasUsed
		results = append(results, jsonResult)
	}

	for i, tx := range txs {
		coinbaseBalanceBeforeTx := state.GetBalance(coinbase)
		state.SetTxContext(tx.Hash(), i)

		accessListState := state.Copy() // create a copy just in case we use it later for access list creation

		receipt, result, err := core.ApplyTransaction(s.b.ChainConfig(), s.chain, &coinbase, gp, state, header, tx, &header.GasUsed, vmconfig)
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}

		txHash := tx.Hash().String()
		from, err := types.Sender(signer, tx)
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}
		to := "0x"
		if tx.To() != nil {
			to = tx.To().String()
		}
		jsonResult := map[string]interface{}{
			"txHash":      txHash,
			"gasUsed":     receipt.GasUsed,
			"fromAddress": from.String(),
			"toAddress":   to,
		}
		totalGasUsed += receipt.GasUsed
		gasPrice, err := tx.EffectiveGasTip(header.BaseFee)
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}
		gasFeesTx := new(big.Int).Mul(big.NewInt(int64(receipt.GasUsed)), gasPrice)
		gasFees.Add(gasFees, gasFeesTx)
		bundleHash.Write(tx.Hash().Bytes())
		if result.Err != nil {
			jsonResult["error"] = result.Err.Error()
			revert := result.Revert()
			if len(revert) > 0 {
				jsonResult["revert"] = string(revert)
			}
		} else {
			dst := make([]byte, hex.EncodedLen(len(result.Return())))
			hex.Encode(dst, result.Return())
			jsonResult["value"] = "0x" + string(dst)
		}
		// if simulation logs are requested append it to logs
		if args.SimulationLogs {
			jsonResult["logs"] = receipt.Logs
		}
		// if an access list is requested create and append
		if args.CreateAccessList {
			// ifdk another way to fill all values so this will have to do - x2
			txArgGas := hexutil.Uint64(tx.Gas())
			txArgNonce := hexutil.Uint64(tx.Nonce())
			txArgData := hexutil.Bytes(tx.Data())
			txargs := TransactionArgs{
				From:    &from,
				To:      tx.To(),
				Gas:     &txArgGas,
				Nonce:   &txArgNonce,
				Data:    &txArgData,
				Value:   (*hexutil.Big)(tx.Value()),
				ChainID: (*hexutil.Big)(tx.ChainId()),
			}
			if tx.GasFeeCap().Cmp(big.NewInt(0)) == 0 { // no maxbasefee, set gasprice instead
				txargs.GasPrice = (*hexutil.Big)(tx.GasPrice())
			} else { // otherwise set base and priority fee
				txargs.MaxFeePerGas = (*hexutil.Big)(tx.GasFeeCap())
				txargs.MaxPriorityFeePerGas = (*hexutil.Big)(tx.GasTipCap())
			}
			acl, gasUsed, vmerr, err := AccessListOnState(ctx, s.b, header, accessListState, txargs)
			if err == nil {
				if gasUsed != receipt.GasUsed {
					log.Debug("Gas used in receipt differ from accesslist", "receipt", receipt.GasUsed, "acl", gasUsed) // weird bug but it works
				}
				if vmerr != nil {
					log.Info("CallBundle accesslist creation encountered vmerr", "vmerr", vmerr)
				}
				jsonResult["accessList"] = acl

			} else {
				log.Info("CallBundle accesslist creation encountered err", "err", err)
				jsonResult["accessList"] = acl //
			} // return the empty accesslist either way
		}
		coinbaseDiffTx := new(big.Int).Sub(state.GetBalance(coinbase), coinbaseBalanceBeforeTx)
		jsonResult["coinbaseDiff"] = coinbaseDiffTx.String()
		jsonResult["gasFees"] = gasFeesTx.String()
		jsonResult["ethSentToCoinbase"] = new(big.Int).Sub(coinbaseDiffTx, gasFeesTx).String()
		jsonResult["gasPrice"] = new(big.Int).Div(coinbaseDiffTx, big.NewInt(int64(receipt.GasUsed))).String()
		jsonResult["gasUsed"] = receipt.GasUsed
		results = append(results, jsonResult)
	}

	ret := map[string]interface{}{}
	ret["results"] = results
	coinbaseDiff := new(big.Int).Sub(state.GetBalance(coinbase), coinbaseBalanceBefore)
	ret["coinbaseDiff"] = coinbaseDiff.String()
	ret["gasFees"] = gasFees.String()
	ret["ethSentToCoinbase"] = new(big.Int).Sub(coinbaseDiff, gasFees).String()
	ret["bundleGasPrice"] = new(big.Int).Div(coinbaseDiff, big.NewInt(int64(totalGasUsed))).String()
	ret["totalGasUsed"] = totalGasUsed
	ret["stateBlockNumber"] = parent.Number.Int64()

	ret["bundleHash"] = "0x" + common.Bytes2Hex(bundleHash.Sum(nil))
	return ret, nil
}

// EstimateGasBundleArgs are possible args for eth_estimateGasBundle
type EstimateGasBundleArgs struct {
	Txs                    []TransactionArgs     `json:"txs"`
	BlockNumber            rpc.BlockNumber       `json:"blockNumber"`
	StateBlockNumberOrHash rpc.BlockNumberOrHash `json:"stateBlockNumber"`
	Coinbase               *string               `json:"coinbase"`
	Timestamp              *uint64               `json:"timestamp"`
	Timeout                *int64                `json:"timeout"`
	StateOverrides         *StateOverride        `json:"stateOverrides"`
	CreateAccessList       bool                  `json:"createAccessList"`
}

// callbundle, but doesnt require signing
func (s *SearcherAPI) EstimateGasBundle(ctx context.Context, args EstimateGasBundleArgs) (map[string]interface{}, error) {
	if len(args.Txs) == 0 {
		return nil, errors.New("bundle missing txs")
	}
	if args.BlockNumber == 0 {
		return nil, errors.New("bundle missing blockNumber")
	}

	timeoutMS := int64(5000)
	if args.Timeout != nil {
		timeoutMS = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMS)

	state, parent, err := s.b.StateAndHeaderByNumberOrHash(ctx, args.StateBlockNumberOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	if err := args.StateOverrides.Apply(state); err != nil {
		return nil, err
	}

	blockNumber := big.NewInt(int64(args.BlockNumber))
	timestamp := parent.Time + 1
	if args.Timestamp != nil {
		timestamp = *args.Timestamp
	}
	coinbase := parent.Coinbase
	if args.Coinbase != nil {
		coinbase = common.HexToAddress(*args.Coinbase)
	}

	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     blockNumber,
		GasLimit:   parent.GasLimit,
		Time:       timestamp,
		Difficulty: parent.Difficulty,
		Coinbase:   coinbase,
		BaseFee:    parent.BaseFee,
	}

	// Setup context so it may be cancelled when the call
	// has completed or, in case of unmetered gas, setup
	// a context with a timeout
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}

	// Make sure the context is cancelled when the call has completed
	// This makes sure resources are cleaned up
	defer cancel()

	// RPC Call gas cap
	globalGasCap := s.b.RPCGasCap()

	// Results
	results := []map[string]interface{}{}

	// Copy the original db so we don't modify it
	statedb := state.Copy()

	// Gas pool
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	// Block context
	blockContext := core.NewEVMBlockContext(header, s.chain, &coinbase)

	// Feed each of the transactions into the VM ctx
	// And try and estimate the gas used
	for i, txArgs := range args.Txs {
		// Since its a txCall we'll just prepare the
		// state with a random hash
		var randomHash common.Hash
		rand.Read(randomHash[:])

		// New random hash since its a call
		statedb.SetTxContext(randomHash, i)

		accessListState := statedb.Copy() // create a copy just in case we use it later for access list creation

		// Convert tx args to msg to apply state transition
		msg, err := txArgs.ToMessage(globalGasCap, header.BaseFee)
		if err != nil {
			return nil, err
		}

		// Prepare the hashes
		txContext := core.NewEVMTxContext(msg)

		// Get EVM Environment
		vmenv := vm.NewEVM(blockContext, txContext, statedb, s.b.ChainConfig(), vm.Config{NoBaseFee: true})

		// Apply state transition
		result, err := core.ApplyMessage(vmenv, msg, gp)
		if err != nil {
			return nil, err
		}

		// Modifications are committed to the state
		// Only delete empty objects if EIP158/161 (a.k.a Spurious Dragon) is in effect
		statedb.Finalise(vmenv.ChainConfig().IsEIP158(blockNumber))

		// Append result
		jsonResult := map[string]interface{}{
			"gasUsed": result.UsedGas,
		}

		if result.Err != nil {
			jsonResult["error"] = result.Err.Error()
			revert := result.Revert()
			if len(revert) > 0 {
				jsonResult["revert"] = string(revert)
			}
		}

		if len(result.ReturnData) > 0 {
			jsonResult["data"] = hexutil.Bytes(result.ReturnData)
		}

		// if simulation logs are requested append it to logs
		// if an access list is requested create and append
		if args.CreateAccessList {
			// welp guess we're copying these again sigh
			txArgFrom := msg.From
			txArgGas := hexutil.Uint64(msg.GasLimit)
			txArgNonce := hexutil.Uint64(msg.Nonce)
			txArgData := hexutil.Bytes(msg.Data)
			txargs := TransactionArgs{
				From:    &txArgFrom,
				To:      msg.To,
				Gas:     &txArgGas,
				Nonce:   &txArgNonce,
				Data:    &txArgData,
				ChainID: (*hexutil.Big)(s.chain.Config().ChainID),
				Value:   (*hexutil.Big)(msg.Value),
			}
			if msg.GasFeeCap.Cmp(big.NewInt(0)) == 0 { // no maxbasefee, set gasprice instead
				txargs.GasPrice = (*hexutil.Big)(msg.GasPrice)
			} else { // otherwise set base and priority fee
				txargs.MaxFeePerGas = (*hexutil.Big)(msg.GasFeeCap)
				txargs.MaxPriorityFeePerGas = (*hexutil.Big)(msg.GasTipCap)
			}
			acl, _, vmerr, err := AccessListOnState(ctx, s.b, header, accessListState, txargs)
			if err == nil {
				if vmerr != nil {
					log.Info("CallBundle accesslist creation encountered vmerr", "vmerr", vmerr)
				}
				jsonResult["accessList"] = acl

			} else {
				log.Info("CallBundle accesslist creation encountered err", "err", err)
				jsonResult["accessList"] = acl //
			} // return the empty accesslist either way
		}

		results = append(results, jsonResult)
	}

	// Return results
	ret := map[string]interface{}{}
	ret["results"] = results

	return ret, nil
}

// rpcMarshalCompact uses the generalized output filler, then adds the total difficulty field, which requires
// a `PublicBlockchainAPI`.
func (s *SearcherAPI) rpcMarshalCompactHeader(ctx context.Context, h *types.Header) map[string]interface{} {
	return RPCMarshalCompactHeader(h)
}

// GetCompactBlocks gets the compact block data for the given block's hash or number
// the logs in the block can also be requested
func (s *SearcherAPI) GetCompactBlocks(ctx context.Context, blockNrOrHashes []rpc.BlockNumberOrHash, returnLogs bool) ([]map[string]interface{}, error) {
	resultArray := make([]map[string]interface{}, 0, len(blockNrOrHashes))
	for _, blockNrOrHash := range blockNrOrHashes {
		header, err := s.b.HeaderByNumberOrHash(ctx, blockNrOrHash)
		if err != nil {
			return nil, err
		}
		result := s.rpcMarshalCompactHeader(ctx, header)
		if returnLogs { // add logs if requested
			logs := s.chain.GetLogsWithHeader(header)
			result["logs"] = RPCMarshalCompactLogs(logs)
		}
		resultArray = append(resultArray, result)
	}
	return resultArray, nil
}
