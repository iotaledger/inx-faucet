package faucet_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/iotaledger/hive.go/app/daemon"
	"github.com/iotaledger/hive.go/serializer/v2"
	"github.com/iotaledger/hornet/v2/pkg/common"
	"github.com/iotaledger/hornet/v2/pkg/dag"
	"github.com/iotaledger/hornet/v2/pkg/model/storage"
	"github.com/iotaledger/hornet/v2/pkg/model/utxo"
	"github.com/iotaledger/hornet/v2/pkg/protocol/gossip"
	"github.com/iotaledger/hornet/v2/pkg/testsuite"
	"github.com/iotaledger/hornet/v2/pkg/testsuite/utils"
	"github.com/iotaledger/hornet/v2/pkg/whiteflag"
	"github.com/iotaledger/inx-faucet/pkg/faucet"
	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/iotaledger/iota.go/v3/pow"
)

const (
	faucetMaxOutputCount = iotago.MaxOutputsCount
	faucetTagMessage     = "FAUCET"
	faucetBatchTimeout   = 2 * time.Second
)

const (
	MinPoWScore     = 10
	ProtocolVersion = 2
	BelowMaxDepth   = 15
)

var (
	genesisSeed, _ = hex.DecodeString("2f54b071657e6644629a40518ba6554de4eee89f0757713005ad26137d80968d05e1ca1bca555d8b4b85a3f4fcf11a6a48d3d628d1ace40f48009704472fc8f9")
	faucetSeed, _  = hex.DecodeString("96d9ff7a79e4b0a5f3e5848ae7867064402da92a62eabb4ebbe463f12d1f3b1aace1775488f51cb1e3a80732a03ef60b111d6833ab605aa9f8faebeb33bbe3d9")
	seed1, _       = hex.DecodeString("b15209ddc93cbdb600137ea6a8f88cdd7c5d480d5815c9352a0fb5c4e4b86f7151dcb44c2ba635657a2df5a8fd48cb9bab674a9eceea527dbbb254ef8c9f9cd7")
	seed2, _       = hex.DecodeString("d5353ceeed380ab89a0f6abe4630c2091acc82617c0edd4ff10bd60bba89e2ed30805ef095b989c2bf208a474f8748d11d954aade374380422d4d812b6f1da90")
	seed3, _       = hex.DecodeString("bd6fe09d8a309ca309c5db7b63513240490109cd0ac6b123551e9da0d5c8916c4a5a4f817e4b4e9df89885ce1af0986da9f1e56b65153c2af1e87ab3b11dabb4")
)

type FaucetTestEnv struct {
	t       *testing.T
	TestEnv *testsuite.TestEnvironment

	GenesisWallet *utils.HDWallet
	FaucetWallet  *utils.HDWallet
	Wallet1       *utils.HDWallet
	Wallet2       *utils.HDWallet
	Wallet3       *utils.HDWallet

	Faucet *faucet.Faucet

	faucetCtxCancel context.CancelFunc
}

func NewFaucetTestEnv(t *testing.T,
	faucetBalance uint64,
	wallet1Balance uint64,
	wallet2Balance uint64,
	wallet3Balance uint64,
	faucetAmount uint64,
	faucetSmallAmount uint64,
	faucetMaxAddressBalance uint64,
	assertSteps bool) *FaucetTestEnv {

	genesisWallet := utils.NewHDWallet("Genesis", genesisSeed, 0)
	faucetWallet := utils.NewHDWallet("Faucet", faucetSeed, 0)
	seed1Wallet := utils.NewHDWallet("Seed1", seed1, 0)
	seed2Wallet := utils.NewHDWallet("Seed2", seed2, 0)
	seed3Wallet := utils.NewHDWallet("Seed3", seed3, 0)

	genesisAddress := genesisWallet.Address()

	te := testsuite.SetupTestEnvironment(t, genesisAddress, 2, ProtocolVersion, uint8(BelowMaxDepth), uint32(MinPoWScore), false)

	// Add token supply to our local HDWallet
	genesisWallet.BookOutput(te.GenesisOutput)
	if assertSteps {
		te.AssertWalletBalance(genesisWallet, te.ProtocolParameters().TokenSupply)
	}

	var lastBlockID iotago.BlockID
	blocksCount := 0

	// Fund Faucet
	if faucetBalance > 0 {
		blockA := te.NewBlockBuilder("A").
			Parents(iotago.BlockIDs{lastBlockID, te.LastMilestoneBlockID()}).
			FromWallet(genesisWallet).
			Amount(faucetBalance).
			BuildTransactionToWallet(faucetWallet).
			Store().
			BookOnWallets()

		blocksCount++
		lastBlockID = blockA.StoredBlockID()
	}

	// Fund Wallet1
	if wallet1Balance > 0 {
		blockB := te.NewBlockBuilder("B").
			Parents(iotago.BlockIDs{lastBlockID, te.LastMilestoneBlockID()}).
			FromWallet(genesisWallet).
			Amount(wallet1Balance).
			BuildTransactionToWallet(seed1Wallet).
			Store().
			BookOnWallets()

		blocksCount++
		lastBlockID = blockB.StoredBlockID()
	}

	// Fund Wallet2
	if wallet2Balance > 0 {
		blockC := te.NewBlockBuilder("C").
			Parents(iotago.BlockIDs{lastBlockID, te.LastMilestoneBlockID()}).
			FromWallet(genesisWallet).
			Amount(wallet2Balance).
			BuildTransactionToWallet(seed2Wallet).
			Store().
			BookOnWallets()

		blocksCount++
		lastBlockID = blockC.StoredBlockID()

	}

	// Fund Wallet3
	if wallet3Balance > 0 {
		blockD := te.NewBlockBuilder("D").
			Parents(iotago.BlockIDs{lastBlockID, te.LastMilestoneBlockID()}).
			FromWallet(genesisWallet).
			Amount(wallet3Balance).
			BuildTransactionToWallet(seed3Wallet).
			Store().
			BookOnWallets()

		blocksCount++
		lastBlockID = blockD.StoredBlockID()

	}

	// Confirming milestone at message D
	_, confStats := te.IssueAndConfirmMilestoneOnTips(iotago.BlockIDs{lastBlockID}, false)
	if assertSteps {

		require.Equal(t, blocksCount+1, confStats.BlocksReferenced) // blocksCount + milestone itself
		require.Equal(t, blocksCount, confStats.BlocksIncludedWithTransactions)
		require.Equal(t, 0, confStats.BlocksExcludedWithConflictingTransactions)
		require.Equal(t, 1, confStats.BlocksExcludedWithoutTransactions) // the milestone

		// Verify balances
		te.AssertWalletBalance(genesisWallet, te.ProtocolParameters().TokenSupply-faucetBalance-wallet1Balance-wallet2Balance-wallet3Balance)
		te.AssertWalletBalance(faucetWallet, faucetBalance)
		te.AssertWalletBalance(seed1Wallet, wallet1Balance)
		te.AssertWalletBalance(seed2Wallet, wallet2Balance)
		te.AssertWalletBalance(seed3Wallet, wallet3Balance)
	}

	defaultDaemon := daemon.New()
	defaultDaemon.Start()

	fetchMetadataFunc := func(blockID iotago.BlockID) (*faucet.Metadata, error) {
		metadata := te.Storage().CachedBlockMetadataOrNil(blockID) // meta +1
		if metadata == nil {
			//nolint:nilnil // nil, nil is ok in this context, even if it is not go idiomatic
			return nil, nil
		}
		metadata.Release(true) // meta -1

		if metadata.Metadata().IsReferenced() {
			return &faucet.Metadata{
				IsReferenced:   metadata.Metadata().IsReferenced(),
				IsConflicting:  metadata.Metadata().IsConflictingTx(),
				ShouldReattach: false,
			}, nil
		}

		cmi := te.SyncManager().ConfirmedMilestoneIndex()
		_, ocri, err := dag.ConeRootIndexes(context.Background(), te.Storage(), metadata.Retain(), cmi) // meta pass +1
		if err != nil {
			return nil, err
		}

		return &faucet.Metadata{
			IsReferenced:   false,
			IsConflicting:  false,
			ShouldReattach: (cmi - ocri) > iotago.MilestoneIndex(BelowMaxDepth),
		}, nil
	}

	collectOutputsFunc := func(address iotago.Address) ([]faucet.UTXOOutput, error) {
		faucetOutputs := []faucet.UTXOOutput{}
		outputs, err := te.UnspentAddressOutputsWithoutConstraints(address, utxo.ReadLockLedger(false))
		if err != nil {
			return nil, err
		}
		for _, output := range outputs {
			basicOutput, ok := output.Output().(*iotago.BasicOutput)
			if !ok {
				panic(fmt.Sprintf("invalid type: expected *iotago.BasicOutput, got %T", output.Output()))
			}

			faucetOutputs = append(faucetOutputs, faucet.UTXOOutput{
				OutputID: output.OutputID(),
				Output:   basicOutput,
			})
		}

		return faucetOutputs, nil
	}

	storeMessageFunc := func(ctx context.Context, block *iotago.Block) (iotago.BlockID, error) {
		if block.ProtocolVersion != te.ProtocolParameters().Version {
			return iotago.BlockID{}, fmt.Errorf("block has invalid protocol version %d instead of %d", block.ProtocolVersion, te.ProtocolParameters().Version)
		}

		if len(block.Parents) == 0 {
			block.Parents = iotago.BlockIDs{te.LastMilestoneBlockID()}
		}
		_, err := te.PoWHandler.DoPoW(ctx, block, serializer.DeSeriModePerformValidation, te.ProtocolParameters(), 1, nil)
		if err != nil {
			return iotago.BlockID{}, err
		}

		blk, err := storage.NewBlock(block, serializer.DeSeriModePerformValidation, te.ProtocolParameters())
		if err != nil {
			return iotago.BlockID{}, err
		}

		score := pow.Score(blk.Data())
		if score < float64(MinPoWScore) {
			return iotago.BlockID{}, fmt.Errorf("block has insufficient PoW score %0.2f", score)
		}

		cmi := te.SyncManager().ConfirmedMilestoneIndex()

		checkParentFunc := func(blockID iotago.BlockID) error {
			cachedBlockMeta := te.Storage().CachedBlockMetadataOrNil(blockID) // meta +1
			if cachedBlockMeta == nil {
				// parent not found
				entryPointIndex, exists, err := te.Storage().SolidEntryPointsIndex(blockID)
				if err != nil {
					return err
				}
				if !exists {
					return gossip.ErrBlockNotSolid
				}

				if (cmi - entryPointIndex) > iotago.MilestoneIndex(BelowMaxDepth) {
					// the parent is below max depth
					return gossip.ErrBlockBelowMaxDepth
				}

				// block is a SEP and not below max depth
				return nil
			}
			defer cachedBlockMeta.Release(true) // meta -1

			if !cachedBlockMeta.Metadata().IsSolid() {
				// if the parent is not solid, the block itself can't be solid
				return gossip.ErrBlockNotSolid
			}

			// we pass a background context here to not prevent emitting messages at shutdown (COO etc).
			_, ocri, err := dag.ConeRootIndexes(context.Background(), te.Storage(), cachedBlockMeta.Retain(), cmi) // meta pass +1
			if err != nil {
				return err
			}

			if (cmi - ocri) > iotago.MilestoneIndex(BelowMaxDepth) {
				// the parent is below max depth
				return gossip.ErrBlockBelowMaxDepth
			}

			return nil
		}

		for _, parentBlockID := range block.Parents {
			err := checkParentFunc(parentBlockID)
			if err != nil {
				return iotago.BlockID{}, err
			}
		}

		_ = te.StoreBlock(blk) // no need to release, since we remember all the blocks for later cleanup

		return blk.BlockID(), nil
	}

	f := faucet.New(
		defaultDaemon,
		fetchMetadataFunc,
		collectOutputsFunc,
		te.SyncManager().IsNodeSynced,
		te.ProtocolParameters,
		faucetWallet.Address(),
		faucetWallet.AddressSigner(),
		storeMessageFunc,
		faucet.WithAmount(faucetAmount),
		faucet.WithSmallAmount(faucetSmallAmount),
		faucet.WithMaxAddressBalance(faucetMaxAddressBalance),
		faucet.WithMaxOutputCount(faucetMaxOutputCount),
		faucet.WithTagMessage(faucetTagMessage),
		faucet.WithBatchTimeout(faucetBatchTimeout),
	)

	faucetCtx, faucetCtxCancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		if err := f.RunFaucetLoop(faucetCtx, func() {
			wg.Done()
		}); err != nil && common.IsCriticalError(err) != nil {
			require.NoError(t, err)
		}
	}()

	// wait until faucet is initialized
	wg.Wait()

	// Connect the callbacks from the testsuite to the Faucet
	te.ConfigureUTXOCallbacks(
		func(index iotago.MilestoneIndex, newOutputs utxo.Outputs, newSpents utxo.Spents) {

			createdOutputs := iotago.OutputIDs{}
			for _, output := range newOutputs {
				createdOutputs = append(createdOutputs, output.OutputID())
			}
			consumedOutputs := iotago.OutputIDs{}
			for _, spent := range newSpents {
				consumedOutputs = append(consumedOutputs, spent.OutputID())
			}

			require.NoError(t, f.ApplyNewLedgerUpdate(createdOutputs, consumedOutputs))
		},
	)

	return &FaucetTestEnv{
		t:               t,
		TestEnv:         te,
		GenesisWallet:   genesisWallet,
		FaucetWallet:    faucetWallet,
		Wallet1:         seed1Wallet,
		Wallet2:         seed2Wallet,
		Wallet3:         seed3Wallet,
		Faucet:          f,
		faucetCtxCancel: faucetCtxCancel,
	}
}

func (env *FaucetTestEnv) ProtocolParameters() *iotago.ProtocolParameters {
	return env.TestEnv.ProtocolParameters()
}

func (env *FaucetTestEnv) ConfirmedMilestoneIndex() iotago.MilestoneIndex {
	return env.TestEnv.SyncManager().ConfirmedMilestoneIndex()
}

func (env *FaucetTestEnv) Cleanup() {
	if env.faucetCtxCancel != nil {
		env.faucetCtxCancel()
	}
	env.TestEnv.CleanupTestEnvironment(true)
}

func (env *FaucetTestEnv) processFaucetRequests(preFlushFunc func() error) (iotago.BlockIDs, error) {

	wg := sync.WaitGroup{}
	wg.Add(1)

	var tips iotago.BlockIDs
	unhook := env.Faucet.Events.IssuedBlock.Hook(func(blockID iotago.BlockID) {
		tips = append(tips, blockID)
		wg.Done()
	}).Unhook
	defer unhook()

	if preFlushFunc != nil {
		if err := preFlushFunc(); err != nil {
			return nil, err
		}
	}

	env.Faucet.FlushRequests()

	chanDone := make(chan struct{})

	go func() {
		wg.Wait()
		close(chanDone)
	}()

	select {
	case <-chanDone:
	case <-time.After(1 * time.Second):
		env.t.Error("attachment of faucet block took too long")
	}

	return tips, nil
}

// RequestFunds sends requests to the faucet and waits until the next faucet block is issued.
func (env *FaucetTestEnv) RequestFunds(wallets ...*utils.HDWallet) (iotago.BlockIDs, error) {

	require.Greater(env.t, len(wallets), 0)

	tips, err := env.processFaucetRequests(func() error {
		for _, wallet := range wallets {
			if _, err := env.Faucet.Enqueue(wallet.Address().Bech32(iotago.PrefixTestnet)); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return tips, nil
}

// RequestFundsAndIssueMilestone sends requests to the faucet, waits until the next faucet block is issued and
// issues a milestone on top of it.
func (env *FaucetTestEnv) RequestFundsAndIssueMilestone(wallets ...*utils.HDWallet) error {

	tips, err := env.RequestFunds(wallets...)
	if err != nil {
		return err
	}

	// issue milestone on top of new faucet message
	_, _ = env.IssueMilestone(tips...)

	return nil
}

// FlushRequestsAndConfirmNewFaucetBlock flushes pending faucet requests, waits until the next faucet block is issued and
// issues a milestone on top of it.
func (env *FaucetTestEnv) FlushRequestsAndConfirmNewFaucetBlock() error {

	tips, err := env.processFaucetRequests(nil)
	if err != nil {
		return err
	}

	// issue milestone on top of new faucet message
	_, _ = env.IssueMilestone(tips...)

	return nil
}

func (env *FaucetTestEnv) IssueMilestone(onTips ...iotago.BlockID) (*whiteflag.Confirmation, *whiteflag.ConfirmedMilestoneStats) {
	return env.TestEnv.IssueAndConfirmMilestoneOnTips(onTips, false)
}

func (env *FaucetTestEnv) AssertFaucetBalance(expected uint64) {
	faucetInfo, err := env.Faucet.Info()
	require.NoError(env.t, err)
	require.Exactly(env.t, expected, faucetInfo.Balance)
}

func (env *FaucetTestEnv) AssertAddressUTXOCount(address iotago.Address, expected int) {
	_, count, err := env.TestEnv.ComputeAddressBalanceWithoutConstraints(address)
	require.NoError(env.t, err)
	require.Equal(env.t, expected, count)
}
