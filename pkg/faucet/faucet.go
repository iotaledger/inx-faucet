package faucet

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"

	"github.com/iotaledger/hive.go/daemon"
	"github.com/iotaledger/hive.go/events"
	"github.com/iotaledger/hive.go/logger"
	"github.com/iotaledger/hive.go/syncutils"
	"github.com/iotaledger/hornet/pkg/common"
	"github.com/iotaledger/hornet/pkg/restapi"
	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/iotaledger/iota.go/v3/builder"
)

// IsNodeSyncedFunc is a function to query if the used node is synced.
type IsNodeSyncedFunc = func() bool

// SendBlockFunc is a function which sends a block to the network.
type SendBlockFunc = func(ctx context.Context, block *iotago.Block) (iotago.BlockID, error)

// Metadata contains the basic block metadata required by the faucet.
type Metadata struct {
	IsReferenced   bool
	IsConflicting  bool
	ShouldReattach bool
}

// BlockMetadataFunc is a function to fetch the required metadata for a given block ID.
// This should return nil if the block is not found.
type BlockMetadataFunc = func(blockID iotago.BlockID) (*Metadata, error)

type UTXOOutput struct {
	OutputID iotago.OutputID
	Output   *iotago.BasicOutput
}

type BasicOutputsForAddressFunc = func(address iotago.Address) ([]UTXOOutput, error)

var (
	// ErrNothingToProcess is returned when there is no need to sweep or send funds.
	ErrNothingToProcess = errors.New("nothing to process")
)

// Events are the events issued by the faucet.
type Events struct {
	// Fired when a faucet block is issued.
	IssuedBlock *events.Event
	// SoftError is triggered when a soft error is encountered.
	SoftError *events.Event
}

// queueItem is an item for the faucet requests queue.
type queueItem struct {
	Bech32  string
	Amount  uint64
	Address iotago.Address
}

// pendingTransaction holds info about a sent transaction that is pending.
type pendingTransaction struct {
	BlockID        iotago.BlockID
	QueuedItems    []*queueItem
	ConsumedInputs iotago.OutputIDs
	TransactionID  iotago.TransactionID
}

// FaucetInfoResponse defines the response of a GET RouteFaucetInfo REST API call.
type FaucetInfoResponse struct {
	// The bech32 address of the faucet.
	Address string `json:"address"`
	// The remaining balance of faucet.
	Balance uint64 `json:"balance"`
	// The name of the token of the faucet.
	TokenName string `json:"tokenName"`
	// The Bech32 human readable part of the the faucet.
	Bech32HRP iotago.NetworkPrefix `json:"bech32HRP"`
}

// FaucetEnqueueResponse defines the response of a POST RouteFaucetEnqueue REST API call.
type FaucetEnqueueResponse struct {
	// The bech32 address.
	Address string `json:"address"`
	// The number of waiting requests in the queue.
	WaitingRequests int `json:"waitingRequests"`
}

// Faucet is used to issue transaction to users that requested funds via a REST endpoint.
type Faucet struct {
	// lock used to secure the state of the faucet.
	syncutils.Mutex
	// the logger used to log events.
	*logger.WrappedLogger

	// used to access the global daemon.
	daemon daemon.Daemon
	// used to access metadata of a block from the node.
	blockMetadataFunc BlockMetadataFunc
	// used to collect unspent outputs for a given address.
	collectOutputsFunc BasicOutputsForAddressFunc
	// used to determine the sync status of the node.
	nodeSyncedFunc IsNodeSyncedFunc
	// Protocol parameters including byte costs
	protoParas *iotago.ProtocolParameters
	// the address of the faucet.
	address iotago.Address
	// used to sign the faucet transactions.
	addressSigner iotago.AddressSigner
	// the function used to send a block.
	sendBlockFunc SendBlockFunc
	// holds the faucet options.
	opts *Options

	// events of the faucet.
	Events *Events

	// faucetBalance is the remaining balance of the faucet if all requests would be processed.
	faucetBalance uint64
	// queue of new requests.
	queue chan *queueItem
	// map with all queued requests per address (bech32).
	queueMap map[string]*queueItem
	// flushQueue is used to signal to stop an ongoing batching of faucet requests.
	flushQueue chan struct{}
	// pendingTransactionsMap is a map of sent transactions that are pending.
	pendingTransactionsMap map[string]*pendingTransaction
	// the block ID of the last sent faucet block.
	lastBlockID *iotago.BlockID
	// the latest unused UTXO output that may not be confirmed yet but can be reused in new transactions.
	// this is used to issue multiple transactions without waiting for the confirmation by milestones.
	lastRemainderOutput *UTXOOutput
}

// the default options applied to the faucet.
var defaultOptions = []Option{
	WithTokenName("TestToken"),
	WithAmount(10000000),            // 10 Mi
	WithSmallAmount(1000000),        // 1 Mi
	WithMaxAddressBalance(20000000), // 20 Mi
	WithMaxOutputCount(iotago.MaxOutputsCount),
	WithTagMessage("HORNET FAUCET"),
	WithBatchTimeout(2 * time.Second),
}

// Options define options for the faucet.
type Options struct {
	// the logger used to log events.
	logger            *logger.Logger
	tokenName         string
	amount            uint64
	smallAmount       uint64
	maxAddressBalance uint64
	maxOutputCount    int
	tagMessage        []byte
	batchTimeout      time.Duration
}

// applies the given Option.
func (so *Options) apply(opts ...Option) {
	for _, opt := range opts {
		opt(so)
	}
}

// WithLogger enables logging within the faucet.
func WithLogger(logger *logger.Logger) Option {
	return func(opts *Options) {
		opts.logger = logger
	}
}

// WithTokenName sets the name of the token.
func WithTokenName(name string) Option {
	return func(opts *Options) {
		opts.tokenName = name
	}
}

// WithAmount defines the amount of funds the requester receives.
func WithAmount(amount uint64) Option {
	return func(opts *Options) {
		opts.amount = amount
	}
}

// WithSmallAmount defines the amount of funds the requester receives
// if the target address has more funds than the faucet amount and less than maximum.
func WithSmallAmount(smallAmount uint64) Option {
	return func(opts *Options) {
		opts.smallAmount = smallAmount
	}
}

// WithMaxAddressBalance defines the maximum allowed amount of funds on the target address.
// If there are more funds already, the faucet request is rejected.
func WithMaxAddressBalance(maxAddressBalance uint64) Option {
	return func(opts *Options) {
		opts.maxAddressBalance = maxAddressBalance
	}
}

// WithMaxOutputCount defines the maximum output count per faucet block.
func WithMaxOutputCount(maxOutputCount int) Option {
	return func(opts *Options) {
		if maxOutputCount > iotago.MaxOutputsCount {
			maxOutputCount = iotago.MaxOutputsCount
		}
		if maxOutputCount < 2 {
			maxOutputCount = 2
		}
		opts.maxOutputCount = maxOutputCount
	}
}

// WithTagMessage defines the faucet transaction tag payload.
func WithTagMessage(tagMessage string) Option {
	return func(opts *Options) {
		opts.tagMessage = []byte(tagMessage)
	}
}

// WithBatchTimeout sets the maximum duration for collecting faucet batches.
func WithBatchTimeout(timeout time.Duration) Option {
	return func(opts *Options) {
		opts.batchTimeout = timeout
	}
}

// Option is a function setting a faucet option.
type Option func(opts *Options)

func BlockIDCaller(handler interface{}, params ...interface{}) {
	handler.(func(blockID iotago.BlockID))(params[0].(iotago.BlockID))
}

// New creates a new faucet instance.
func New(
	daemon daemon.Daemon,
	blockMetadataFunc BlockMetadataFunc,
	collectOutputsFunc BasicOutputsForAddressFunc,
	nodeSyncedFunc IsNodeSyncedFunc,
	protoParas *iotago.ProtocolParameters,
	address iotago.Address,
	addressSigner iotago.AddressSigner,
	sendBlockFunc SendBlockFunc,
	opts ...Option) *Faucet {

	options := &Options{}
	options.apply(defaultOptions...)
	options.apply(opts...)

	faucet := &Faucet{
		daemon:             daemon,
		blockMetadataFunc:  blockMetadataFunc,
		collectOutputsFunc: collectOutputsFunc,
		nodeSyncedFunc:     nodeSyncedFunc,
		protoParas:         protoParas,
		address:            address,
		addressSigner:      addressSigner,
		sendBlockFunc:      sendBlockFunc,
		opts:               options,

		Events: &Events{
			IssuedBlock: events.NewEvent(BlockIDCaller),
			SoftError:   events.NewEvent(events.ErrorCaller),
		},
	}
	faucet.WrappedLogger = logger.NewWrappedLogger(options.logger)
	faucet.init()

	return faucet
}

func (f *Faucet) init() {
	f.faucetBalance = 0
	f.queue = make(chan *queueItem, 5000)
	f.queueMap = make(map[string]*queueItem)
	f.flushQueue = make(chan struct{})
	f.pendingTransactionsMap = make(map[string]*pendingTransaction)
	f.lastBlockID = nil
	f.lastRemainderOutput = nil
}

// Info returns the used faucet address and remaining balance.
func (f *Faucet) Info() (*FaucetInfoResponse, error) {
	return &FaucetInfoResponse{
		Address:   f.address.Bech32(f.protoParas.Bech32HRP),
		Balance:   f.faucetBalance,
		TokenName: f.opts.tokenName,
		Bech32HRP: f.protoParas.Bech32HRP,
	}, nil
}

func (f *Faucet) collectUnspentBasicOutputsWithoutConstraints(address iotago.Address) ([]UTXOOutput, uint64, error) {

	outputs, err := f.collectOutputsFunc(address)
	if err != err {
		return nil, 0, err
	}

	var balance uint64
	for _, output := range outputs {
		balance += output.Output.Deposit()
	}

	return outputs, balance, nil
}

func (f *Faucet) computeAddressBalance(address iotago.Address) (uint64, error) {
	_, balance, err := f.collectUnspentBasicOutputsWithoutConstraints(address)
	return balance, err
}

// Enqueue adds a new faucet request to the queue.
func (f *Faucet) Enqueue(bech32Addr string) (*FaucetEnqueueResponse, error) {

	addr, err := f.parseBech32Address(bech32Addr)
	if err != nil {
		return nil, err
	}

	if !f.nodeSyncedFunc() {
		return nil, errors.WithMessage(echo.ErrInternalServerError, "Faucet node is not synchronized. Please try again later!")
	}

	f.Lock()
	defer f.Unlock()

	if _, exists := f.queueMap[bech32Addr]; exists {
		return nil, errors.WithMessage(restapi.ErrInvalidParameter, "Address is already in the queue.")
	}

	amount := f.opts.amount
	balance, err := f.computeAddressBalance(addr)
	if err == nil && balance >= f.opts.amount {
		amount = f.opts.smallAmount

		if balance >= f.opts.maxAddressBalance {
			return nil, errors.WithMessage(restapi.ErrInvalidParameter, "You already have enough funds on your address.")
		}
	}

	if amount > f.faucetBalance {
		return nil, errors.WithMessage(echo.ErrInternalServerError, "Faucet does not have enough funds to process your request. Please try again later!")
	}

	request := &queueItem{
		Bech32:  bech32Addr,
		Amount:  amount,
		Address: addr,
	}

	select {
	case f.queue <- request:
		f.faucetBalance -= amount
		f.queueMap[bech32Addr] = request
		return &FaucetEnqueueResponse{
			Address:         bech32Addr,
			WaitingRequests: len(f.queueMap),
		}, nil

	default:
		// queue is full
		return nil, errors.WithMessage(echo.ErrInternalServerError, "Faucet queue is full. Please try again later!")
	}
}

// FlushRequests stops current batching of faucet requests.
func (f *Faucet) FlushRequests() {
	f.flushQueue <- struct{}{}
}

// parseBech32Address parses a bech32 address.
func (f *Faucet) parseBech32Address(bech32Addr string) (iotago.Address, error) {

	hrp, bech32Address, err := iotago.ParseBech32(bech32Addr)
	if err != nil {
		return nil, errors.WithMessage(restapi.ErrInvalidParameter, "Invalid bech32 address provided!")
	}

	if hrp != f.protoParas.Bech32HRP {
		return nil, errors.WithMessagef(restapi.ErrInvalidParameter, "Invalid bech32 address provided! Address does not start with \"%s\".", f.protoParas.Bech32HRP)
	}

	return bech32Address, nil
}

// clearRequestWithoutLocking clear the old request from the map.
// this is necessary to be able to send a new request to the same address.
// write lock must be acquired outside.
func (f *Faucet) clearRequestWithoutLocking(request *queueItem) {
	delete(f.queueMap, request.Bech32)
}

// clearRequestsWithoutLocking clears the old requests from the map.
// this is necessary to be able to send new requests to the same addresses.
// write lock must be acquired outside.
func (f *Faucet) clearRequestsWithoutLocking(batchedRequests []*queueItem) {
	for _, request := range batchedRequests {
		f.clearRequestWithoutLocking(request)
	}
}

// readdRequestsWithoutLocking adds old requests back to the queue.
// write lock must be acquired outside.
func (f *Faucet) readdRequestsWithoutLocking(batchedRequests []*queueItem) {
	for _, request := range batchedRequests {
		select {
		case f.queue <- request:
		default:
			// queue full => no way to readd it, delete it from the map as well so user are able to send a new request
			f.clearRequestWithoutLocking(request)
		}
	}
}

// addPendingTransactionWithoutLocking tracks a pending transaction.
// write lock must be acquired outside.
func (f *Faucet) addPendingTransactionWithoutLocking(pending *pendingTransaction) {
	f.pendingTransactionsMap[string(pending.BlockID[:])] = pending
}

// clearPendingTransactionWithoutLocking removes tracking of a pending transaction.
// write lock must be acquired outside.
func (f *Faucet) clearPendingTransactionWithoutLocking(blockID iotago.BlockID) {
	delete(f.pendingTransactionsMap, string(blockID[:]))
}

// createBlock creates a new block and references the last faucet block.
func (f *Faucet) createBlock(txPayload iotago.Payload, tip ...iotago.BlockID) (*iotago.Block, error) {

	tips := iotago.BlockIDs{}
	if len(tip) > 0 {
		// if a tip was passed, use that one
		tips = append(tips, tip[0])
	}

	return builder.NewBlockBuilder().
		ProtocolVersion(f.protoParas.Version).
		Parents(tips).
		Payload(txPayload).
		Build()
}

// buildTransactionPayload creates a signed transaction payload with all UTXO and batched requests.
func (f *Faucet) buildTransactionPayload(unspentOutputs []UTXOOutput, batchedRequests []*queueItem) (*iotago.Transaction, iotago.TransactionID, iotago.OutputIDs, *iotago.UTXOInput, uint64, error) {

	txBuilder := builder.NewTransactionBuilder(f.protoParas.NetworkID())
	txBuilder.AddTaggedDataPayload(&iotago.TaggedData{Tag: f.opts.tagMessage, Data: nil})

	outputCount := 0
	var remainderAmount int64 = 0

	// collect all unspent output of the faucet address
	consumedInputs := []iotago.OutputID{}
	for _, unspentOutput := range unspentOutputs {
		outputCount++
		remainderAmount += int64(unspentOutput.Output.Deposit())
		txBuilder.AddInput(&builder.TxInput{UnlockTarget: f.address, InputID: unspentOutput.OutputID, Input: unspentOutput.Output})
		consumedInputs = append(consumedInputs, unspentOutput.OutputID)
	}

	// add all requests as outputs
	for _, req := range batchedRequests {
		outputCount++

		if outputCount >= f.opts.maxOutputCount-1 {
			// do not collect further requests
			// the last slot is for the remainder
			break
		}

		if remainderAmount == 0 {
			// do not collect further requests
			break
		}

		amount := req.Amount
		if remainderAmount < int64(amount) {
			// not enough funds left
			amount = uint64(remainderAmount)
		}
		remainderAmount -= int64(amount)

		txBuilder.AddOutput(&iotago.BasicOutput{
			Amount: amount,
			Conditions: iotago.UnlockConditions{
				&iotago.AddressUnlockCondition{Address: req.Address},
			},
		})
	}

	if remainderAmount > 0 {
		txBuilder.AddOutput(&iotago.BasicOutput{
			Amount: uint64(remainderAmount),
			Conditions: iotago.UnlockConditions{
				&iotago.AddressUnlockCondition{Address: f.address},
			},
		})
	}

	txPayload, err := txBuilder.Build(f.protoParas, f.addressSigner)
	if err != nil {
		return nil, iotago.TransactionID{}, nil, nil, 0, err
	}

	transactionID, err := txPayload.ID()
	if err != nil {
		return nil, iotago.TransactionID{}, nil, nil, 0, fmt.Errorf("can't compute the transaction ID, error: %w", err)
	}

	if remainderAmount == 0 {
		// no remainder available
		return txPayload, transactionID, consumedInputs, nil, 0, nil
	}

	remainderOutput := &iotago.UTXOInput{}
	copy(remainderOutput.TransactionID[:], transactionID[:iotago.TransactionIDLength])

	// search remainder address in the outputs
	found := false
	var outputIndex uint16 = 0
	for _, output := range txPayload.Essence.Outputs {
		basicOutput := output.(*iotago.BasicOutput)
		addr := basicOutput.UnlockConditionSet().Address().Address

		if f.address.Equal(addr) {
			// found the remainder address in the outputs
			found = true
			remainderOutput.TransactionOutputIndex = outputIndex
			break
		}
		outputIndex++
	}

	if !found {
		return nil, iotago.TransactionID{}, nil, nil, 0, errors.New("can't find the faucet remainder output")
	}

	return txPayload, transactionID, consumedInputs, remainderOutput, uint64(remainderAmount), nil
}

// sendFaucetBlock creates a faucet transaction payload and remembers the last sent blockID and the lastRemainderOutput.
func (f *Faucet) sendFaucetBlock(ctx context.Context, unspentOutputs []UTXOOutput, batchedRequests []*queueItem, tip ...iotago.BlockID) error {

	txPayload, transactionID, consumedInputs, remainderIotaGoOutput, remainderAmount, err := f.buildTransactionPayload(unspentOutputs, batchedRequests)
	if err != nil {
		return fmt.Errorf("build transaction payload failed, error: %w", err)
	}

	block, err := f.createBlock(txPayload, tip...)
	if err != nil {
		return fmt.Errorf("build faucet block failed, error: %w", err)
	}

	blockID, err := f.sendBlockFunc(ctx, block)
	if err != nil {
		return fmt.Errorf("send faucet block failed, error: %w", err)
	}

	f.Lock()
	f.lastBlockID = &blockID
	f.addPendingTransactionWithoutLocking(&pendingTransaction{
		BlockID:        blockID,
		QueuedItems:    batchedRequests,
		ConsumedInputs: consumedInputs,
		TransactionID:  transactionID,
	})

	if remainderIotaGoOutput != nil {
		remainderIotaGoOutputID := remainderIotaGoOutput.ID()
		output := &iotago.BasicOutput{
			Amount: remainderAmount,
			Conditions: iotago.UnlockConditions{
				&iotago.AddressUnlockCondition{Address: f.address},
			},
		}
		f.lastRemainderOutput = &UTXOOutput{
			OutputID: remainderIotaGoOutputID,
			Output:   output,
		}
	} else {
		// no funds remaining => no remainder output
		f.lastRemainderOutput = nil
	}
	f.Unlock()

	f.Events.IssuedBlock.Trigger(blockID)

	return nil
}

// logSoftError logs a soft error and triggers the event.
func (f *Faucet) logSoftError(err error) {
	f.LogWarn(err)
	f.Events.SoftError.Trigger(err)
}

// collectRequests collects faucet requests until the maximum amount or a timeout is reached.
// locking not required.
func (f *Faucet) collectRequests(ctx context.Context) ([]*queueItem, error) {

	batchedRequests := []*queueItem{}
	collectedRequestsCounter := 0

CollectValues:
	for collectedRequestsCounter < f.opts.maxOutputCount {
		select {
		case <-ctx.Done():
			// faucet was stopped
			return nil, common.ErrOperationAborted

		case <-time.After(f.opts.batchTimeout):
			// timeout was reached => stop collecting requests
			break CollectValues

		case <-f.flushQueue:
			// flush signal => stop collecting requests
			for collectedRequestsCounter < f.opts.maxOutputCount {
				// collect all pending requests
				select {
				case request := <-f.queue:
					batchedRequests = append(batchedRequests, request)
					collectedRequestsCounter++

				default:
					// no pending requests
					break CollectValues
				}
			}
			break CollectValues

		case request := <-f.queue:
			batchedRequests = append(batchedRequests, request)
			collectedRequestsCounter++
		}
	}

	return batchedRequests, nil
}

// processRequestsWithoutLocking processes all possible requests considering the maximum transaction size and the remaining funds of the faucet.
// write lock must be acquired outside.
func (f *Faucet) processRequestsWithoutLocking(collectedRequestsCounter int, amount uint64, batchedRequests []*queueItem) []*queueItem {
	processedBatchedRequests := []*queueItem{}
	unprocessedBatchedRequests := []*queueItem{}
	nodeSynced := f.nodeSyncedFunc()

	for i := range batchedRequests {
		request := batchedRequests[i]

		if !nodeSynced {
			// request can't be processed because the node is not synchronized => re-add it to the queue
			unprocessedBatchedRequests = append(unprocessedBatchedRequests, request)
			continue
		}

		if collectedRequestsCounter >= f.opts.maxOutputCount-1 {
			// request can't be processed in this transaction => re-add it to the queue
			unprocessedBatchedRequests = append(unprocessedBatchedRequests, request)
			continue
		}

		if amount < request.Amount {
			// not enough funds to process this request => ignore the request
			f.clearRequestWithoutLocking(request)
			continue
		}

		// request can be processed in this transaction
		amount -= request.Amount
		collectedRequestsCounter++
		processedBatchedRequests = append(processedBatchedRequests, request)
	}

	f.readdRequestsWithoutLocking(unprocessedBatchedRequests)

	return processedBatchedRequests
}

// RunFaucetLoop collects unspent outputs on the faucet address and batches the requests from the queue.
func (f *Faucet) RunFaucetLoop(ctx context.Context, initDoneCallback func()) error {

	// set initial faucet balance
	faucetBalance, err := f.computeAddressBalance(f.address)
	if err != nil {
		return common.CriticalError(fmt.Errorf("reading faucet address balance failed: %s, error: %s", f.address.Bech32(f.protoParas.Bech32HRP), err))
	}
	f.faucetBalance = faucetBalance

	if initDoneCallback != nil {
		initDoneCallback()
	}

	for {
		select {
		case <-ctx.Done():
			// faucet was stopped
			return nil

		default:
			// first collect requests
			batchedRequests, err := f.collectRequests(ctx)
			if err != nil {
				if err == common.ErrOperationAborted {
					return nil
				}
				if common.IsCriticalError(err) != nil {
					// error is a critical error
					// => stop the faucet
					return err
				}
				f.logSoftError(err)
				continue
			}

			collectUnspentOutputsWithoutLocking := func() ([]UTXOOutput, uint64, error) {
				if f.lastRemainderOutput != nil {
					// the lastRemainderOutput is reused as input in the next transaction, even if it was not yet referenced by a milestone.
					// this is done to increase the throughput of the faucet in high load situations.
					// we can't collect unspent outputs, as long as the lastRemainderOutput was not confirmed,
					// since it's creating transaction could also have consumed the same UTXOs.
					return []UTXOOutput{*f.lastRemainderOutput}, f.lastRemainderOutput.Output.Deposit(), nil
				}
				return f.collectUnspentBasicOutputsWithoutConstraints(f.address)
			}

			processRequests := func() ([]UTXOOutput, []*queueItem, iotago.BlockIDs, error) {
				// there must be a lock between collectUnspentOutputsWithoutLocking and "tipselection", otherwise the chaining may fail
				f.Lock()
				defer f.Unlock()

				unspentOutputs, amount, err := collectUnspentOutputsWithoutLocking()
				if err != nil {
					return nil, nil, nil, err
				}

				if len(unspentOutputs) < 2 && len(batchedRequests) == 0 {
					// no need to sweep or send funds
					return nil, nil, nil, ErrNothingToProcess
				}

				// if a lastBlockID exists, we need to reference it to chain the transactions in the correct order for whiteflag.
				// lastBlockID is reset by ApplyConfirmation in case the last faucet block is not confirmed and below max depth.
				var tips iotago.BlockIDs
				if f.lastBlockID != nil {
					tips = append(tips, *f.lastBlockID)
				}

				processableRequests := f.processRequestsWithoutLocking(len(unspentOutputs), amount, batchedRequests)

				return unspentOutputs, processableRequests, tips, nil
			}

			unspentOutputs, processableRequests, tips, err := processRequests()
			if err != nil {
				if err != ErrNothingToProcess {
					if common.IsCriticalError(err) != nil {
						// error is a critical error
						// => stop the faucet
						return err
					}
					f.logSoftError(err)
				}
				continue
			}

			if err := f.sendFaucetBlock(ctx, unspentOutputs, processableRequests, tips...); err != nil {
				if common.IsCriticalError(err) != nil {
					// error is a critical error
					// => stop the faucet
					return err
				}
				f.readdRequestsWithoutLocking(processableRequests)
				f.logSoftError(err)
				continue
			}
		}
	}
}

// ApplyNewLedgerUpdate applies a new ledger update to the faucet.
// Pending transactions are checked for their current state and either removed, readded, or left pending.
// If a conflict is found, all remaining pending transactions are readded to the queue.
// no need to ReadLockLedger, because this function should be called from milestone confirmation event anyway.
func (f *Faucet) ApplyNewLedgerUpdate(createdOutputs iotago.OutputIDs, consumedOutputs iotago.OutputIDs) error {
	f.Lock()
	defer f.Unlock()

	conflicting := false

	// create maps for faster lookup.
	// outputs that are created and consumed in the same milestone exist in both maps.
	newSpentsMap := make(map[string]struct{})
	for _, spent := range consumedOutputs {
		newSpentsMap[spent.ToHex()] = struct{}{}
	}

	newOutputsMap := make(map[string]struct{})
	for _, output := range createdOutputs {
		newOutputsMap[output.ToHex()] = struct{}{}
	}

	if f.lastRemainderOutput != nil {
		if _, created := newOutputsMap[f.lastRemainderOutput.OutputID.ToHex()]; created {
			// the latest transaction got confirmed, reset the lastRemainderOutput
			f.lastRemainderOutput = nil
		}
	}

	// check if pending transactions were affected by the ledger update.
	for _, pendingTx := range f.pendingTransactionsMap {

		inputWasSpent := false
		for _, consumedInput := range pendingTx.ConsumedInputs {
			if _, spent := newSpentsMap[consumedInput.ToHex()]; spent {
				inputWasSpent = true
				break
			}
		}

		if inputWasSpent {
			// a referenced input of this transaction was spent, so the pending transaction is affected by this ledger update.
			// => we need to check if the outputs were created, otherwise this is a conflicting transaction.

			// we can easily check this by searching for output index 0.
			// if this was created, the rest was created as well because transactions are atomic.
			txOutputIndexZero := iotago.UTXOInput{
				TransactionID:          pendingTx.TransactionID,
				TransactionOutputIndex: 0,
			}

			if _, created := newOutputsMap[txOutputIndexZero.ID().ToHex()]; !created {
				// transaction was conflicting => readd the items to the queue and delete the pending transaction
				conflicting = true
				f.readdRequestsWithoutLocking(pendingTx.QueuedItems)
				f.clearPendingTransactionWithoutLocking(pendingTx.BlockID)
			} else {
				// transaction was confirmed => delete the requests and the pending transaction
				f.clearRequestsWithoutLocking(pendingTx.QueuedItems)
				f.clearPendingTransactionWithoutLocking(pendingTx.BlockID)

				if f.lastBlockID != nil && bytes.Equal(f.lastBlockID[:], pendingTx.BlockID[:]) {
					// the latest block got confirmed, reset the lastBlockID
					f.lastBlockID = nil
				}
			}
		}
	}

	checkPendingBlockMetadata := func(pendingTx *pendingTransaction) {
		blockID := pendingTx.BlockID

		metadata, err := f.blockMetadataFunc(blockID)
		if err != nil {
			// an error occurred => re-add the items to the queue and delete the pending transaction
			conflicting = true
			f.readdRequestsWithoutLocking(pendingTx.QueuedItems)
			f.clearPendingTransactionWithoutLocking(blockID)
			return
		}
		if metadata == nil {
			// block unknown => re-add the items to the queue and delete the pending transaction
			conflicting = true
			f.readdRequestsWithoutLocking(pendingTx.QueuedItems)
			f.clearPendingTransactionWithoutLocking(blockID)
			return
		}

		if metadata.IsReferenced {
			if metadata.IsConflicting {
				// transaction was conflicting => re-add the items to the queue and delete the pending transaction
				conflicting = true
				f.readdRequestsWithoutLocking(pendingTx.QueuedItems)
				f.clearPendingTransactionWithoutLocking(blockID)
				return
			}

			// transaction was confirmed => delete the requests and the pending transaction
			f.clearRequestsWithoutLocking(pendingTx.QueuedItems)
			f.clearPendingTransactionWithoutLocking(blockID)
			return
		}

		if metadata.ShouldReattach {
			// below max depth => re-add the items to the queue and delete the pending transaction
			conflicting = true
			f.readdRequestsWithoutLocking(pendingTx.QueuedItems)
			f.clearPendingTransactionWithoutLocking(blockID)
		}
	}

	// check all remaining pending transactions
	for _, pendingTx := range f.pendingTransactionsMap {
		checkPendingBlockMetadata(pendingTx)
	}

	if conflicting {
		// there was a conflict in the chain
		// => reset the lastBlockID and lastRemainderOutput to collect outputs and reissue all pending transactions
		f.lastBlockID = nil
		f.lastRemainderOutput = nil

		for _, pendingTx := range f.pendingTransactionsMap {
			f.readdRequestsWithoutLocking(pendingTx.QueuedItems)
			f.clearPendingTransactionWithoutLocking(pendingTx.BlockID)
		}
	}

	// calculate total balance of all pending requests
	var pendingRequestsBalance uint64 = 0
	for _, pendingRequest := range f.queueMap {
		pendingRequestsBalance += pendingRequest.Amount
	}

	// recalculate the current faucet balance
	// no need to lock since we are in the milestone confirmation anyway
	faucetBalance, err := f.computeAddressBalance(f.address)
	if err != nil {
		return common.CriticalError(fmt.Errorf("reading faucet address balance failed: %s, error: %s", f.address.Bech32(f.protoParas.Bech32HRP), err))
	}

	if faucetBalance < pendingRequestsBalance {
		f.faucetBalance = 0
		return nil
	}

	f.faucetBalance = faucetBalance - pendingRequestsBalance
	return nil
}
