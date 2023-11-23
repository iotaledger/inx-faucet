package faucet

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/dig"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/iotaledger/hive.go/app"
	"github.com/iotaledger/hive.go/app/shutdown"
	"github.com/iotaledger/hive.go/crypto"
	"github.com/iotaledger/hive.go/ds/types"
	"github.com/iotaledger/hive.go/ierrors"
	"github.com/iotaledger/hive.go/lo"
	"github.com/iotaledger/inx-app/pkg/httpserver"
	"github.com/iotaledger/inx-app/pkg/nodebridge"
	"github.com/iotaledger/inx-faucet/pkg/daemon"
	"github.com/iotaledger/inx-faucet/pkg/faucet"
	iotago "github.com/iotaledger/iota.go/v4"
	"github.com/iotaledger/iota.go/v4/api"
	"github.com/iotaledger/iota.go/v4/builder"
	"github.com/iotaledger/iota.go/v4/nodeclient"
)

const (
	inxRequestTimeout             = 5 * time.Second
	indexerPluginAvailableTimeout = 30 * time.Second
)

func init() {
	Component = &app.Component{
		Name:     "Faucet",
		DepsFunc: func(cDeps dependencies) { deps = cDeps },
		Params:   params,
		Provide:  provide,
		Run:      run,
	}
}

var (
	Component *app.Component
	deps      dependencies
)

type dependencies struct {
	dig.In
	NodeBridge      *nodebridge.NodeBridge
	Faucet          *faucet.Faucet
	ShutdownHandler *shutdown.ShutdownHandler
}

func provide(c *dig.Container) error {

	// we use a restricted address for the faucet, so we don't need to filter indexer requests.
	// we only allow to receive mana, the rest is blocked.
	faucetAddressRestricted, faucetSigner, err := getRestrictedFaucetAddressAndSigner()
	if err != nil {
		Component.LogErrorAndExit(err)
	}

	// get the block issuer client
	type blockIssuerClientDeps struct {
		dig.In
		NodeBridge *nodebridge.NodeBridge
	}

	if err := c.Provide(func(deps blockIssuerClientDeps) (nodeclient.BlockIssuerClient, error) {
		Component.LogInfo("Initializing INX node client...")
		nodeClient, err := deps.NodeBridge.INXNodeClient()
		if err != nil {
			return nil, err
		}
		Component.LogInfo("Initializing INX node client...done!")

		ctx, cancel := context.WithTimeout(Component.Daemon().ContextStopped(), 5*time.Second)
		defer cancel()

		Component.LogInfo("Initializing blockissuer...")

		blockissuer, err := nodeClient.BlockIssuer(ctx)
		if err != nil {
			return nil, err
		}

		Component.LogInfo("Initializing blockissuer...done!")

		return blockissuer, nil
	}); err != nil {
		Component.LogPanic(err)
	}

	type faucetDeps struct {
		dig.In
		NodeBridge        *nodebridge.NodeBridge
		BlockIssuerClient nodeclient.BlockIssuerClient
	}

	if err := c.Provide(func(deps faucetDeps) (*faucet.Faucet, error) {

		fetchTransactionMetadata := func(blockID iotago.BlockID) (*faucet.TransactionMetadata, error) {
			ctx, cancel := context.WithTimeout(Component.Daemon().ContextStopped(), 5*time.Second)
			defer cancel()

			metadata, err := deps.NodeBridge.BlockMetadata(ctx, blockID)
			if err != nil {
				st, ok := status.FromError(err)
				if ok && st.Code() == codes.NotFound {
					// the block is either not found, or it was evicted
					//nolint:nilnil // nil, nil is ok in this context, even if it is not go idiomatic
					return nil, nil
				}

				return nil, err
			}

			return &faucet.TransactionMetadata{
				State:         metadata.GetTransactionState(),
				FailureReason: metadata.GetTransactionFailureReason(),
			}, nil
		}

		Component.LogInfo("Initializing indexer...")

		ctxIndexer, cancelIndexer := context.WithTimeout(Component.Daemon().ContextStopped(), indexerPluginAvailableTimeout)
		defer cancelIndexer()

		indexer, err := deps.NodeBridge.Indexer(ctxIndexer)
		if err != nil {
			return nil, err
		}

		Component.LogInfo("Initializing indexer... done!")

		collectUnlockableFaucetOutputs := func() ([]faucet.UTXOBasicOutput, error) {
			ctxRequest, cancelRequest := context.WithTimeout(Component.Daemon().ContextStopped(), inxRequestTimeout)
			defer cancelRequest()

			// the restricted address only returns simple outputs, which are basic outputs without timelocks,
			// expiration, native tokens, storage deposit return unlocks conditions.
			query := &api.BasicOutputsQuery{
				AddressBech32: faucetAddressRestricted.Bech32(deps.NodeBridge.APIProvider().CommittedAPI().ProtocolParameters().Bech32HRP()),
			}

			result, err := indexer.Outputs(ctxRequest, query)
			if err != nil {
				return nil, err
			}

			faucetOutputs := make([]faucet.UTXOBasicOutput, 0)
			for result.Next() {
				outputs, err := result.Outputs(ctxRequest)
				if err != nil {
					return nil, err
				}

				outputIDs := result.Response.Items.MustOutputIDs()

				for i := range outputs {
					basicOutput, ok := outputs[i].(*iotago.BasicOutput)
					if !ok {
						Component.LogWarnf("invalid type: expected *iotago.BasicOutput, got %T", outputs[i])

						continue
					}

					faucetOutputs = append(faucetOutputs, faucet.UTXOBasicOutput{
						OutputID: outputIDs[i],
						Output:   basicOutput,
					})
				}
			}
			if result.Error != nil {
				return nil, result.Error
			}

			return faucetOutputs, nil
		}

		computeUnlockableAddressBalance := func(address iotago.Address) (iotago.BaseToken, error) {
			ctxRequest, cancelRequest := context.WithTimeout(Component.Daemon().ContextStopped(), inxRequestTimeout)
			defer cancelRequest()

			// collect all possible outputs that are owned by that address and evaluate later if they are unlockable.
			query := &api.OutputsQuery{
				IndexerUnlockableByAddressParams: api.IndexerUnlockableByAddressParams{
					UnlockableByAddressBech32: address.Bech32(deps.NodeBridge.APIProvider().CommittedAPI().ProtocolParameters().Bech32HRP()),
				},
			}

			result, err := indexer.Outputs(ctxRequest, query)
			if err != nil {
				return 0, err
			}

			var unlockableBalance iotago.BaseToken
			for result.Next() {
				outputs, err := result.Outputs(ctxRequest)
				if err != nil {
					return 0, err
				}

				for i := range outputs {
					output := outputs[i]

					if output.UnlockConditionSet().HasStorageDepositReturnCondition() && output.UnlockConditionSet().StorageDepositReturn().ReturnAddress.Equal(address) {
						// we don't care about addresses in the storage deposit return unlock conditions
						continue
					}

					lastAcceptedBlockSlot := iotago.SlotIndex(deps.NodeBridge.NodeStatus().LastAcceptedBlockSlot)
					if output.UnlockConditionSet().HasTimelockUntil(lastAcceptedBlockSlot) {
						// ignore timelocked outputs for balance calculation
						continue
					}

					//nolint:godox
					// TODO: what are the correct bounds here?
					maxFutureBoundedSlotIndex := lastAcceptedBlockSlot + deps.NodeBridge.APIProvider().CommittedAPI().ProtocolParameters().MinCommittableAge()
					minPastBoundedSlotIndex := lastAcceptedBlockSlot + deps.NodeBridge.APIProvider().CommittedAPI().ProtocolParameters().MaxCommittableAge()

					actualIdentToUnlock, err := output.UnlockConditionSet().CheckExpirationCondition(maxFutureBoundedSlotIndex, minPastBoundedSlotIndex)
					if err != nil {
						// this means the output has an unlock condition and it is currently in the blocked range around the expiration slot.
						// => add the balance to the expiration return address, because it will belong to this address after the blocked range.
						if !output.UnlockConditionSet().Expiration().ReturnAddress.Equal(address) {
							// the output belongs to the expiration return address, but this is not the address in the request
							continue
						}
					} else if actualIdentToUnlock != nil && !actualIdentToUnlock.Equal(address) {
						// the output belongs to the expiration return address, but this is not the address in the request
						continue
					}

					unlockableBalance += outputs[i].BaseTokenAmount()
				}
			}
			if result.Error != nil {
				return 0, result.Error
			}

			return unlockableBalance, nil
		}

		getLatestSlot := func() iotago.SlotIndex {
			return iotago.SlotIndex(deps.NodeBridge.NodeStatus().LastAcceptedBlockSlot)
		}

		submitTransactionPayload := func(ctx context.Context, builder *builder.TransactionBuilder, signer iotago.AddressSigner, storedManaOutputIndex int, numPoWWorkers ...int) (iotago.ApplicationPayload, iotago.BlockID, error) {
			Component.LogDebug("sending transaction payload...")
			signedTx, blockCreatedResponse, err := deps.BlockIssuerClient.SendPayloadWithTransactionBuilder(ctx, builder, signer, storedManaOutputIndex, numPoWWorkers...)
			if err != nil {
				return nil, iotago.EmptyBlockID, err
			}
			//nolint:forcetypeassert // we can safely assume that this is a SignedTransaction
			Component.LogDebugf("sent transaction payload, blockID: %s, txID: %s", blockCreatedResponse.BlockID, lo.Return1(signedTx.(*iotago.SignedTransaction).ID()))

			return signedTx, blockCreatedResponse.BlockID, nil
		}

		Component.LogInfo("Initializing faucet...")

		faucet := faucet.New(
			Component.Daemon(),
			deps.NodeBridge.IsNodeHealthy,
			fetchTransactionMetadata,
			collectUnlockableFaucetOutputs,
			computeUnlockableAddressBalance,
			getLatestSlot,
			submitTransactionPayload,
			deps.NodeBridge.APIProvider(),
			faucetAddressRestricted,
			faucetSigner,
			faucet.WithLogger(Component.Logger()),
			faucet.WithTokenName(deps.NodeBridge.NodeConfig.BaseToken.Name),
			faucet.WithBaseTokenAmount(iotago.BaseToken(ParamsFaucet.BaseTokenAmount)),
			faucet.WithBaseTokenAmountSmall(iotago.BaseToken(ParamsFaucet.BaseTokenAmountSmall)),
			faucet.WithBaseTokenAmountMaxTarget(iotago.BaseToken(ParamsFaucet.BaseTokenAmountMaxTarget)),
			faucet.WithManaAmount(iotago.Mana(ParamsFaucet.ManaAmount)),
			faucet.WithManaAmountMinFaucet(iotago.Mana(ParamsFaucet.ManaAmountMinFaucet)),
			faucet.WithTagMessage(ParamsFaucet.TagMessage),
			faucet.WithBatchTimeout(ParamsFaucet.BatchTimeout),
			faucet.WithPoWWorkerCount(ParamsFaucet.PoW.WorkerCount),
		)

		Component.LogInfo("Initializing faucet... done!")

		return faucet, nil
	}); err != nil {
		Component.LogPanic(err)
	}

	return nil
}

func run() error {

	// create a background worker that handles the accepted transactions
	if err := Component.Daemon().BackgroundWorker("Faucet[ListenToAcceptedTransactions]", func(ctx context.Context) {
		if err := deps.NodeBridge.ListenToAcceptedTransactions(ctx, func(tx *nodebridge.AcceptedTransaction) error {
			// create maps for faster lookup.
			// outputs that are created and consumed in the same update exist in both maps.
			createdOutputs := make(map[iotago.OutputID]struct{})
			for _, output := range tx.Created {
				createdOutputs[output.UnwrapOutputID()] = types.Void
			}
			consumedOutputs := make(map[iotago.OutputID]struct{})
			for _, spent := range tx.Consumed {
				consumedOutputs[spent.GetOutput().UnwrapOutputID()] = types.Void
			}

			err := deps.Faucet.ApplyAcceptedTransaction(createdOutputs, consumedOutputs)
			if err != nil {
				deps.ShutdownHandler.SelfShutdown(fmt.Sprintf("faucet plugin hit a critical error while applying new accepted transaction: %s", err.Error()), true)
			}

			return err
		}); err != nil {
			deps.ShutdownHandler.SelfShutdown(fmt.Sprintf("Listening to AcceptedTransactions failed, error: %s", err), false)
		}
	}, daemon.PriorityStopFaucetAcceptedTransactions); err != nil {
		Component.LogPanicf("failed to start worker: %s", err)
	}

	// create a background worker that handles the enqueued faucet requests
	if err := Component.Daemon().BackgroundWorker("Faucet", func(ctx context.Context) {
		if err := deps.Faucet.RunFaucetLoop(ctx); err != nil && faucet.IsCriticalError(err) != nil {
			deps.ShutdownHandler.SelfShutdown(fmt.Sprintf("faucet plugin hit a critical error: %s", err.Error()), true)
		}
	}, daemon.PriorityStopFaucet); err != nil {
		Component.LogPanicf("failed to start worker: %s", err)
	}

	e := httpserver.NewEcho(Component.Logger(), nil, ParamsFaucet.DebugRequestLoggerEnabled)
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodPost},
	}))

	setupRoutes(e)

	go func() {
		Component.LogInfof("You can now access the faucet website using: http://%s", ParamsFaucet.BindAddress)
		Component.LogInfof("The deposit address of the faucet is %s", deps.Faucet.Address().Bech32(deps.NodeBridge.APIProvider().CommittedAPI().ProtocolParameters().Bech32HRP()))

		if err := e.Start(ParamsFaucet.BindAddress); err != nil && !ierrors.Is(err, http.ErrServerClosed) {
			Component.LogWarnf("Stopped faucet website server due to an error (%s)", err)
		}
	}()

	return nil
}

// loadEd25519PrivateKeysFromEnvironment loads ed25519 private keys from the given environment variable.
func loadEd25519PrivateKeysFromEnvironment(name string) ([]ed25519.PrivateKey, error) {
	keys, exists := os.LookupEnv(name)
	if !exists {
		return nil, fmt.Errorf("environment variable '%s' not set", name)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("environment variable '%s' not set", name)
	}

	privateKeysSplitted := strings.Split(keys, ",")
	privateKeys := make([]ed25519.PrivateKey, len(privateKeysSplitted))
	for i, key := range privateKeysSplitted {
		privateKey, err := crypto.ParseEd25519PrivateKeyFromString(key)
		if err != nil {
			return nil, fmt.Errorf("environment variable '%s' contains an invalid private key '%s'", name, key)

		}
		privateKeys[i] = privateKey
	}

	return privateKeys, nil
}

func getRestrictedFaucetAddressAndSigner() (iotago.Address, iotago.AddressSigner, error) {
	privateKeys, err := loadEd25519PrivateKeysFromEnvironment("FAUCET_PRV_KEY")
	if err != nil {
		return nil, nil, ierrors.Errorf("loading faucet private key failed, err: %w", err)
	}

	if len(privateKeys) == 0 {
		return nil, nil, ierrors.New("loading faucet private key failed, err: no private keys given")
	}

	if len(privateKeys) > 1 {
		return nil, nil, ierrors.New("loading faucet private key failed, err: too many private keys given")
	}

	privateKey := privateKeys[0]
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, nil, ierrors.New("loading faucet private key failed, err: wrong private key length")
	}

	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, ierrors.Errorf("invalid type: expected ed25519.PublicKey, got %T", privateKey.Public())
	}

	faucetAddress := iotago.Ed25519AddressFromPubKey(publicKey)
	faucetSigner := iotago.NewInMemoryAddressSigner(iotago.NewAddressKeysForEd25519Address(faucetAddress, privateKey))

	faucetAddressRestricted := iotago.RestrictedAddressWithCapabilities(
		faucetAddress,
		iotago.WithAddressCanReceiveMana(true),
	)

	return faucetAddressRestricted, faucetSigner, nil
}
