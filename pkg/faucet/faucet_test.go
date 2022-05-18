package faucet_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gohornet/hornet/pkg/model/milestone"
	"github.com/gohornet/inx-faucet/pkg/faucet/test"
	iotago "github.com/iotaledger/iota.go/v3"
)

func TestSingleRequest(t *testing.T) {
	// requests to a single address

	var faucetBalance uint64 = 1_000_000_000        //  1 Gi
	var wallet1Balance uint64 = 0                   //  0  i
	var wallet2Balance uint64 = 0                   //  0  i
	var wallet3Balance uint64 = 0                   //  0  i
	var faucetAmount uint64 = 10_000_000            // 10 Mi
	var faucetSmallAmount uint64 = 1_000_000        //  1 Mi
	var faucetMaxAddressBalance uint64 = 20_000_000 // 20 Mi

	env := test.NewFaucetTestEnv(t,
		faucetBalance,
		wallet1Balance,
		wallet2Balance,
		wallet3Balance,
		faucetAmount,
		faucetSmallAmount,
		faucetMaxAddressBalance,
		false)
	defer env.Cleanup()
	require.NotNil(t, env)

	confirmedMilestoneIndex := env.ConfirmedMilestoneIndex() // 4
	require.Equal(t, milestone.Index(4), confirmedMilestoneIndex)

	// Verify balances
	genesisBalance := env.ProtocolParameters().TokenSupply - faucetBalance - wallet1Balance - wallet2Balance - wallet3Balance

	env.AssertFaucetBalance(faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.GenesisWallet, genesisBalance)
	env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.Wallet1, wallet1Balance)
	env.TestEnv.AssertLedgerBalance(env.Wallet2, wallet2Balance)
	env.TestEnv.AssertLedgerBalance(env.Wallet3, wallet3Balance)

	err := env.RequestFundsAndIssueMilestone(env.Wallet1)
	require.NoError(t, err)

	faucetBalance -= faucetAmount
	calculatedWallet1Balance := wallet1Balance + faucetAmount
	env.AssertFaucetBalance(faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.Wallet1, calculatedWallet1Balance)

	// small amount
	for calculatedWallet1Balance < faucetMaxAddressBalance {
		err = env.RequestFundsAndIssueMilestone(env.Wallet1)
		require.NoError(t, err)

		faucetBalance -= faucetSmallAmount
		calculatedWallet1Balance += faucetSmallAmount
		env.AssertFaucetBalance(faucetBalance)
		env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)
		env.TestEnv.AssertLedgerBalance(env.Wallet1, calculatedWallet1Balance)
	}

	// max reached
	err = env.RequestFundsAndIssueMilestone(env.Wallet1)
	require.Error(t, err)
}

func TestMultipleRequests(t *testing.T) {
	// requests to multiple addresses

	var faucetBalance uint64 = 1_000_000_000        //  1 Gi
	var wallet1Balance uint64 = 0                   //  0  i
	var wallet2Balance uint64 = 0                   //  0  i
	var wallet3Balance uint64 = 0                   //  0  i
	var faucetAmount uint64 = 10_000_000            // 10 Mi
	var faucetSmallAmount uint64 = 1_000_000        //  1 Mi
	var faucetMaxAddressBalance uint64 = 20_000_000 // 20 Mi

	env := test.NewFaucetTestEnv(t,
		faucetBalance,
		wallet1Balance,
		wallet2Balance,
		wallet3Balance,
		faucetAmount,
		faucetSmallAmount,
		faucetMaxAddressBalance,
		false)
	defer env.Cleanup()
	require.NotNil(t, env)

	confirmedMilestoneIndex := env.ConfirmedMilestoneIndex() // 4
	require.Equal(t, milestone.Index(4), confirmedMilestoneIndex)

	// Verify balances
	genesisBalance := env.ProtocolParameters().TokenSupply - faucetBalance - wallet1Balance - wallet2Balance - wallet3Balance

	env.AssertFaucetBalance(faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.GenesisWallet, genesisBalance)
	env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.Wallet1, wallet1Balance)
	env.TestEnv.AssertLedgerBalance(env.Wallet2, wallet2Balance)
	env.TestEnv.AssertLedgerBalance(env.Wallet3, wallet3Balance)

	// multiple target addresses in single blocks
	tips1, err := env.RequestFunds(env.Wallet1)
	require.NoError(t, err)

	tips2, err := env.RequestFunds(env.Wallet2)
	require.NoError(t, err)

	tips3, err := env.RequestFunds(env.Wallet3)
	require.NoError(t, err)

	var tips iotago.BlockIDs
	tips = append(tips, tips1...)
	tips = append(tips, tips2...)
	tips = append(tips, tips3...)
	_, _ = env.IssueMilestone(tips...)

	fmt.Printf("Wallet1: %s\n", tips1.ToHex())
	fmt.Printf("Wallet2: %s\n", tips2.ToHex())
	fmt.Printf("Wallet3: %s\n", tips3.ToHex())

	faucetBalance -= 3 * faucetAmount
	calculatedWallet1Balance := wallet1Balance + faucetAmount
	calculatedWallet2Balance := wallet2Balance + faucetAmount
	calculatedWallet3Balance := wallet3Balance + faucetAmount
	env.AssertAddressUTXOCount(env.Wallet1.Address(), 1)
	env.AssertAddressUTXOCount(env.Wallet2.Address(), 1)
	env.AssertAddressUTXOCount(env.Wallet3.Address(), 1)
	env.AssertAddressUTXOCount(env.FaucetWallet.Address(), 1)
	env.AssertFaucetBalance(faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.Wallet1, calculatedWallet1Balance)
	env.TestEnv.AssertLedgerBalance(env.Wallet2, calculatedWallet2Balance)
	env.TestEnv.AssertLedgerBalance(env.Wallet3, calculatedWallet3Balance)

	// small amount
	for calculatedWallet1Balance < faucetMaxAddressBalance {
		// multiple target addresses in one block
		err = env.RequestFundsAndIssueMilestone(env.Wallet1, env.Wallet2, env.Wallet3)
		require.NoError(t, err)

		faucetBalance -= 3 * faucetSmallAmount
		calculatedWallet1Balance += faucetSmallAmount
		calculatedWallet2Balance += faucetSmallAmount
		calculatedWallet3Balance += faucetSmallAmount
		env.AssertFaucetBalance(faucetBalance)
		env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)
		env.TestEnv.AssertLedgerBalance(env.Wallet1, calculatedWallet1Balance)
		env.TestEnv.AssertLedgerBalance(env.Wallet2, calculatedWallet2Balance)
		env.TestEnv.AssertLedgerBalance(env.Wallet3, calculatedWallet3Balance)
	}

	// max reached
	err = env.RequestFundsAndIssueMilestone(env.Wallet1, env.Wallet2, env.Wallet3)
	require.Error(t, err)
}

func TestDoubleSpent(t *testing.T) {
	// reuse of the private key of the faucet (double spent)

	var faucetBalance uint64 = 1_000_000_000        //  1 Gi
	var wallet1Balance uint64 = 0                   //  0  i
	var wallet2Balance uint64 = 0                   //  0  i
	var wallet3Balance uint64 = 0                   //  0  i
	var faucetAmount uint64 = 10_000_000            // 10 Mi
	var faucetSmallAmount uint64 = 1_000_000        //  1 Mi
	var faucetMaxAddressBalance uint64 = 20_000_000 // 20 Mi

	env := test.NewFaucetTestEnv(t,
		faucetBalance,
		wallet1Balance,
		wallet2Balance,
		wallet3Balance,
		faucetAmount,
		faucetSmallAmount,
		faucetMaxAddressBalance,
		false)
	defer env.Cleanup()
	require.NotNil(t, env)

	confirmedMilestoneIndex := env.ConfirmedMilestoneIndex() // 4
	require.Equal(t, milestone.Index(4), confirmedMilestoneIndex)

	// Verify balances
	genesisBalance := env.ProtocolParameters().TokenSupply - faucetBalance - wallet1Balance - wallet2Balance - wallet3Balance

	env.AssertFaucetBalance(faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.GenesisWallet, genesisBalance)
	env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.Wallet1, wallet1Balance)
	env.TestEnv.AssertLedgerBalance(env.Wallet2, wallet2Balance)
	env.TestEnv.AssertLedgerBalance(env.Wallet3, wallet3Balance)

	// create a conflicting transaction that gets confirmed instead of the faucet block
	block := env.TestEnv.NewBlockBuilder().
		LatestMilestoneAsParents().
		FromWallet(env.FaucetWallet).
		ToWallet(env.GenesisWallet).
		Amount(faucetAmount).
		Build().
		Store().
		BookOnWallets()

	// create the conflicting block in the faucet
	tips, err := env.RequestFunds(env.Wallet1)
	require.NoError(t, err)

	// Confirming milestone at block
	_, _ = env.IssueMilestone(block.StoredBlockID())

	genesisBalance += faucetAmount
	faucetBalance -= faucetAmount                         // we stole some funds from the faucet
	env.AssertFaucetBalance(faucetBalance - faucetAmount) // pending request is also taken into account
	env.TestEnv.AssertLedgerBalance(env.GenesisWallet, genesisBalance)
	env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)

	// Confirming milestone at block (double spent)
	_, _ = env.IssueMilestone(tips...)

	env.AssertFaucetBalance(faucetBalance - faucetAmount) // request is still pending
	env.TestEnv.AssertLedgerBalance(env.GenesisWallet, genesisBalance)
	env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)

	err = env.FlushRequestsAndConfirmNewFaucetBlock()
	require.NoError(t, err)

	faucetBalance -= faucetAmount // now the request is booked
	calculatedWallet1Balance := wallet1Balance + faucetAmount
	env.AssertFaucetBalance(faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.GenesisWallet, genesisBalance)
	env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.Wallet1, calculatedWallet1Balance)
}

func TestBelowMaxDepth(t *testing.T) {
	// faucet block is below max depth and never confirmed

	var faucetBalance uint64 = 1_000_000_000        //  1 Gi
	var wallet1Balance uint64 = 0                   //  0  i
	var wallet2Balance uint64 = 0                   //  0  i
	var wallet3Balance uint64 = 0                   //  0  i
	var faucetAmount uint64 = 10_000_000            // 10 Mi
	var faucetSmallAmount uint64 = 1_000_000        //  1 Mi
	var faucetMaxAddressBalance uint64 = 20_000_000 // 20 Mi

	env := test.NewFaucetTestEnv(t,
		faucetBalance,
		wallet1Balance,
		wallet2Balance,
		wallet3Balance,
		faucetAmount,
		faucetSmallAmount,
		faucetMaxAddressBalance,
		false)
	defer env.Cleanup()
	require.NotNil(t, env)

	confirmedMilestoneIndex := env.ConfirmedMilestoneIndex() // 4
	require.Equal(t, milestone.Index(4), confirmedMilestoneIndex)

	// Verify balances
	genesisBalance := env.ProtocolParameters().TokenSupply - faucetBalance - wallet1Balance - wallet2Balance - wallet3Balance

	env.AssertFaucetBalance(faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.GenesisWallet, genesisBalance)
	env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.Wallet1, wallet1Balance)
	env.TestEnv.AssertLedgerBalance(env.Wallet2, wallet2Balance)
	env.TestEnv.AssertLedgerBalance(env.Wallet3, wallet3Balance)

	// create a request that doesn't get confirmed
	_, err := env.RequestFunds(env.Wallet1)
	require.NoError(t, err)

	// issue several milestones, so that the faucet block gets below max depth.
	// hint: we need to issue BelowMaxDepth+1 milestones, because we use the
	// LastMilestoneBlockID as a tip for the faucet, but the milestone block
	// itself is part of the future cone, so it needs to be BMD+1 milestones
	// to become below max depth.
	for i := 0; i <= test.BelowMaxDepth+1; i++ {
		_, _ = env.IssueMilestone()
	}

	env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.Wallet1, wallet1Balance)

	// flushing requests should reissue the requests that were in the below max depth block
	err = env.FlushRequestsAndConfirmNewFaucetBlock()
	require.NoError(t, err)

	calculatedWallet1Balance := wallet1Balance + faucetAmount
	faucetBalance -= faucetAmount
	env.AssertFaucetBalance(faucetBalance)

	env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.Wallet1, calculatedWallet1Balance)
}

func TestBelowMaxDepthAfterRequest(t *testing.T) {
	// first a faucet block is confirmed, but then the old block
	// was used as a tip for the next faucet block
	// which caused that it is below max depth and never confirmed

	var faucetBalance uint64 = 1_000_000_000        //  1 Gi
	var wallet1Balance uint64 = 0                   //  0  i
	var wallet2Balance uint64 = 0                   //  0  i
	var wallet3Balance uint64 = 0                   //  0  i
	var faucetAmount uint64 = 10_000_000            // 10 Mi
	var faucetSmallAmount uint64 = 1_000_000        //  1 Mi
	var faucetMaxAddressBalance uint64 = 20_000_000 // 20 Mi

	env := test.NewFaucetTestEnv(t,
		faucetBalance,
		wallet1Balance,
		wallet2Balance,
		wallet3Balance,
		faucetAmount,
		faucetSmallAmount,
		faucetMaxAddressBalance,
		false)
	defer env.Cleanup()
	require.NotNil(t, env)

	confirmedMilestoneIndex := env.ConfirmedMilestoneIndex() // 4
	require.Equal(t, milestone.Index(4), confirmedMilestoneIndex)

	// Verify balances
	genesisBalance := env.ProtocolParameters().TokenSupply - faucetBalance - wallet1Balance - wallet2Balance - wallet3Balance

	env.AssertFaucetBalance(faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.GenesisWallet, genesisBalance)
	env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.Wallet1, wallet1Balance)
	env.TestEnv.AssertLedgerBalance(env.Wallet2, wallet2Balance)
	env.TestEnv.AssertLedgerBalance(env.Wallet3, wallet3Balance)

	err := env.RequestFundsAndIssueMilestone(env.Wallet1)
	require.NoError(t, err)

	faucetBalance -= faucetAmount
	calculatedWallet1Balance := wallet1Balance + faucetAmount
	env.AssertFaucetBalance(faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.Wallet1, calculatedWallet1Balance)

	// issue several milestones, so that the faucet block gets below max depth.
	// hint: we need to issue BelowMaxDepth+1 milestones, because we use the
	// LastMilestoneBlockID as a tip for the faucet, but the milestone block
	// itself is part of the future cone, so it needs to be BMD+1 milestones
	// to become below max depth.
	for i := 0; i <= test.BelowMaxDepth+1; i++ {
		_, _ = env.IssueMilestone()
	}

	err = env.RequestFundsAndIssueMilestone(env.Wallet1)
	require.NoError(t, err)

	faucetBalance -= faucetSmallAmount
	calculatedWallet1Balance += faucetSmallAmount
	env.AssertFaucetBalance(faucetBalance)

	env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.Wallet1, calculatedWallet1Balance)
}

func TestNotEnoughFaucetFunds(t *testing.T) {
	// check if faucet returns an error if not enough funds available

	var faucetBalance uint64 = 29000000             // 29 Mi
	var wallet1Balance uint64 = 0                   //  0  i
	var wallet2Balance uint64 = 0                   //  0  i
	var wallet3Balance uint64 = 0                   //  0  i
	var faucetAmount uint64 = 10_000_000            // 10 Mi
	var faucetSmallAmount uint64 = 1_000_000        //  1 Mi
	var faucetMaxAddressBalance uint64 = 20_000_000 // 20 Mi

	env := test.NewFaucetTestEnv(t,
		faucetBalance,
		wallet1Balance,
		wallet2Balance,
		wallet3Balance,
		faucetAmount,
		faucetSmallAmount,
		faucetMaxAddressBalance,
		false)
	defer env.Cleanup()
	require.NotNil(t, env)

	// Verify balances
	genesisBalance := env.ProtocolParameters().TokenSupply - faucetBalance - wallet1Balance - wallet2Balance - wallet3Balance

	env.AssertFaucetBalance(faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.GenesisWallet, genesisBalance)
	env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.Wallet1, wallet1Balance)
	env.TestEnv.AssertLedgerBalance(env.Wallet2, wallet2Balance)
	env.TestEnv.AssertLedgerBalance(env.Wallet3, wallet3Balance)

	// 29 Mi - 10 Mi = 19 Mi
	err := env.RequestFundsAndIssueMilestone(env.Wallet1)
	require.NoError(t, err)

	faucetBalance -= faucetAmount
	env.AssertFaucetBalance(faucetBalance)

	// 19 Mi - 10 Mi = 9 Mi
	err = env.RequestFundsAndIssueMilestone(env.Wallet2)
	require.NoError(t, err)

	faucetBalance -= faucetAmount
	env.AssertFaucetBalance(faucetBalance)

	// 9 Mi - 10 Mi = error
	err = env.RequestFundsAndIssueMilestone(env.Wallet3)
	require.Error(t, err)

	env.AssertFaucetBalance(faucetBalance)
}

func TestCollectFaucetFunds(t *testing.T) {
	// check if faucet collects funds if no requests left

	var faucetBalance uint64 = 1_000_000_000        //  1 Gi
	var wallet1Balance uint64 = 0                   //  0  i
	var wallet2Balance uint64 = 0                   //  0  i
	var wallet3Balance uint64 = 0                   //  0  i
	var faucetAmount uint64 = 10_000_000            // 10 Mi
	var faucetSmallAmount uint64 = 1_000_000        //  1 Mi
	var faucetMaxAddressBalance uint64 = 20_000_000 // 20 Mi

	env := test.NewFaucetTestEnv(t,
		faucetBalance,
		wallet1Balance,
		wallet2Balance,
		wallet3Balance,
		faucetAmount,
		faucetSmallAmount,
		faucetMaxAddressBalance,
		false)
	defer env.Cleanup()
	require.NotNil(t, env)

	confirmedMilestoneIndex := env.ConfirmedMilestoneIndex() // 4
	require.Equal(t, milestone.Index(4), confirmedMilestoneIndex)

	// Verify balances
	genesisBalance := env.ProtocolParameters().TokenSupply - faucetBalance - wallet1Balance - wallet2Balance - wallet3Balance

	env.AssertFaucetBalance(faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.GenesisWallet, genesisBalance)
	env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.Wallet1, wallet1Balance)
	env.TestEnv.AssertLedgerBalance(env.Wallet2, wallet2Balance)
	env.TestEnv.AssertLedgerBalance(env.Wallet3, wallet3Balance)

	env.AssertAddressUTXOCount(env.FaucetWallet.Address(), 1)

	err := env.RequestFundsAndIssueMilestone(env.Wallet1)
	require.NoError(t, err)

	env.AssertAddressUTXOCount(env.FaucetWallet.Address(), 1)

	faucetBalance -= faucetAmount
	calculatedWallet1Balance := wallet1Balance + faucetAmount
	env.AssertFaucetBalance(faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.Wallet1, calculatedWallet1Balance)

	block := env.TestEnv.NewBlockBuilder().
		LatestMilestoneAsParents().
		FromWallet(env.GenesisWallet).
		ToWallet(env.FaucetWallet).
		Amount(faucetAmount).
		Build().
		Store().
		BookOnWallets()

	// Confirming milestone at block
	_, _ = env.IssueMilestone(block.StoredBlockID())

	faucetBalance += faucetAmount
	env.AssertFaucetBalance(faucetBalance)
	env.TestEnv.AssertLedgerBalance(env.FaucetWallet, faucetBalance)

	env.AssertAddressUTXOCount(env.FaucetWallet.Address(), 2)

	// Flushing requests should collect all outputs
	err = env.FlushRequestsAndConfirmNewFaucetBlock()
	require.NoError(t, err)

	env.AssertAddressUTXOCount(env.FaucetWallet.Address(), 1)
}
