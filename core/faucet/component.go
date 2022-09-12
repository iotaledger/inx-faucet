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
	"github.com/pkg/errors"
	"go.uber.org/dig"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/iotaledger/hive.go/core/app"
	"github.com/iotaledger/hive.go/core/app/pkg/shutdown"
	"github.com/iotaledger/hive.go/core/crypto"
	"github.com/iotaledger/hornet/v2/pkg/common"
	"github.com/iotaledger/inx-app/httpserver"
	"github.com/iotaledger/inx-app/nodebridge"
	"github.com/iotaledger/inx-faucet/pkg/daemon"
	"github.com/iotaledger/inx-faucet/pkg/faucet"
	inx "github.com/iotaledger/inx/go"
	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/iotaledger/iota.go/v3/nodeclient"
)

const (
	inxRequestTimeout             = 5 * time.Second
	indexerPluginAvailableTimeout = 30 * time.Second
)

func init() {
	CoreComponent = &app.CoreComponent{
		Component: &app.Component{
			Name:     "Faucet",
			DepsFunc: func(cDeps dependencies) { deps = cDeps },
			Params:   params,
			Provide:  provide,
			Run:      run,
		},
	}
}

var (
	CoreComponent *app.CoreComponent
	deps          dependencies
)

type dependencies struct {
	dig.In
	NodeBridge      *nodebridge.NodeBridge
	Faucet          *faucet.Faucet
	ShutdownHandler *shutdown.ShutdownHandler
}

func provide(c *dig.Container) error {

	privateKeys, err := loadEd25519PrivateKeysFromEnvironment("FAUCET_PRV_KEY")
	if err != nil {
		CoreComponent.LogErrorfAndExit("loading faucet private key failed, err: %s", err)
	}

	if len(privateKeys) == 0 {
		CoreComponent.LogErrorAndExit("loading faucet private key failed, err: no private keys given")
	}

	if len(privateKeys) > 1 {
		CoreComponent.LogErrorAndExit("loading faucet private key failed, err: too many private keys given")
	}

	privateKey := privateKeys[0]
	if len(privateKey) != ed25519.PrivateKeySize {
		CoreComponent.LogErrorAndExit("loading faucet private key failed, err: wrong private key length")
	}

	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		panic(fmt.Sprintf("invalid type: expected ed25519.PublicKey, got %T", privateKey.Public()))
	}

	faucetAddress := iotago.Ed25519AddressFromPubKey(publicKey)
	faucetSigner := iotago.NewInMemoryAddressSigner(iotago.NewAddressKeysForEd25519Address(&faucetAddress, privateKey))

	type faucetDeps struct {
		dig.In
		NodeBridge *nodebridge.NodeBridge
	}

	if err := c.Provide(func(deps faucetDeps) (*faucet.Faucet, error) {

		fetchMetadata := func(blockID iotago.BlockID) (*faucet.Metadata, error) {
			ctx, cancel := context.WithTimeout(CoreComponent.Daemon().ContextStopped(), 5*time.Second)
			defer cancel()

			metadata, err := deps.NodeBridge.BlockMetadata(ctx, blockID)
			if err != nil {
				st, ok := status.FromError(err)
				if ok && st.Code() == codes.NotFound {
					//nolint:nilnil // nil, nil is ok in this context, even if it is not go idiomatic
					return nil, nil
				}

				return nil, err
			}

			return &faucet.Metadata{
				IsReferenced: metadata.GetReferencedByMilestoneIndex() != 0,
				//nolint:nosnakecase // grpc uses underscores
				IsConflicting:  metadata.GetConflictReason() != inx.BlockMetadata_CONFLICT_REASON_NONE,
				ShouldReattach: metadata.GetShouldReattach(),
			}, nil
		}

		ctxIndexer, cancelIndexer := context.WithTimeout(CoreComponent.Daemon().ContextStopped(), indexerPluginAvailableTimeout)
		defer cancelIndexer()

		indexer, err := deps.NodeBridge.Indexer(ctxIndexer)
		if err != nil {
			return nil, err
		}

		collectOutputs := func(address iotago.Address) ([]faucet.UTXOOutput, error) {
			ctxRequest, cancelRequest := context.WithTimeout(CoreComponent.Daemon().ContextStopped(), inxRequestTimeout)
			defer cancelRequest()

			protoParas := deps.NodeBridge.ProtocolParameters()

			falseCondition := false
			query := &nodeclient.BasicOutputsQuery{
				AddressBech32: address.Bech32(protoParas.Bech32HRP),
				IndexerExpirationParas: nodeclient.IndexerExpirationParas{
					HasExpiration: &falseCondition,
				},
				IndexerTimelockParas: nodeclient.IndexerTimelockParas{
					HasTimelock: &falseCondition,
				},
				IndexerStorageDepositParas: nodeclient.IndexerStorageDepositParas{
					HasStorageDepositReturn: &falseCondition,
				},
			}

			result, err := indexer.Outputs(ctxRequest, query)
			if err != nil {
				return nil, err
			}

			faucetOutputs := []faucet.UTXOOutput{}
			for result.Next() {
				outputs, err := result.Outputs()
				if err != nil {
					return nil, err
				}
				outputIDs := result.Response.Items.MustOutputIDs()

				for i := range outputs {
					basicOutput, ok := outputs[i].(*iotago.BasicOutput)
					if !ok {
						CoreComponent.LogWarnf("invalid type: expected *iotago.BasicOutput, got %T", outputs[i])

						continue
					}

					faucetOutputs = append(faucetOutputs, faucet.UTXOOutput{
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

		submitBlock := func(ctx context.Context, block *iotago.Block) (iotago.BlockID, error) {
			if !deps.NodeBridge.IsNodeAlmostSynced() {
				return iotago.BlockID{}, errors.New("node is not synced")
			}

			return deps.NodeBridge.SubmitBlock(ctx, block)
		}

		return faucet.New(
			CoreComponent.Daemon(),
			fetchMetadata,
			collectOutputs,
			deps.NodeBridge.IsNodeSynced,
			deps.NodeBridge.ProtocolParameters,
			&faucetAddress,
			faucetSigner,
			submitBlock,
			faucet.WithLogger(CoreComponent.Logger()),
			faucet.WithTokenName(deps.NodeBridge.NodeConfig.BaseToken.Name),
			faucet.WithAmount(ParamsFaucet.Amount),
			faucet.WithSmallAmount(ParamsFaucet.SmallAmount),
			faucet.WithMaxAddressBalance(ParamsFaucet.MaxAddressBalance),
			faucet.WithMaxOutputCount(ParamsFaucet.MaxOutputCount),
			faucet.WithTagMessage(ParamsFaucet.TagMessage),
			faucet.WithBatchTimeout(ParamsFaucet.BatchTimeout),
		), nil
	}); err != nil {
		CoreComponent.LogPanic(err)
	}

	return nil
}

func run() error {

	// create a background worker that handles the ledger updates
	if err := CoreComponent.Daemon().BackgroundWorker("Faucet[LedgerUpdates]", func(ctx context.Context) {
		if err := deps.NodeBridge.ListenToLedgerUpdates(ctx, 0, 0, func(update *nodebridge.LedgerUpdate) error {
			createdOutputs := iotago.OutputIDs{}
			for _, output := range update.Created {
				createdOutputs = append(createdOutputs, output.GetOutputId().Unwrap())
			}
			consumedOutputs := iotago.OutputIDs{}
			for _, spent := range update.Consumed {
				consumedOutputs = append(consumedOutputs, spent.GetOutput().GetOutputId().Unwrap())
			}

			err := deps.Faucet.ApplyNewLedgerUpdate(createdOutputs, consumedOutputs)
			if err != nil {
				deps.ShutdownHandler.SelfShutdown(fmt.Sprintf("faucet plugin hit a critical error while applying new ledger update: %s", err.Error()), true)
			}

			return err
		}); err != nil {
			deps.ShutdownHandler.SelfShutdown(fmt.Sprintf("Listening to LedgerUpdates failed, error: %s", err), false)
		}
	}, daemon.PriorityStopFaucetLedgerUpdates); err != nil {
		CoreComponent.LogPanicf("failed to start worker: %s", err)
	}

	// create a background worker that handles the enqueued faucet requests
	if err := CoreComponent.Daemon().BackgroundWorker("Faucet", func(ctx context.Context) {
		if err := deps.Faucet.RunFaucetLoop(ctx, nil); err != nil && common.IsCriticalError(err) != nil {
			deps.ShutdownHandler.SelfShutdown(fmt.Sprintf("faucet plugin hit a critical error: %s", err.Error()), true)
		}
	}, daemon.PriorityStopFaucet); err != nil {
		CoreComponent.LogPanicf("failed to start worker: %s", err)
	}

	e := httpserver.NewEcho(CoreComponent.Logger(), nil, ParamsFaucet.DebugRequestLoggerEnabled)
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodPost},
	}))

	setupRoutes(e)

	go func() {
		CoreComponent.LogInfof("You can now access the faucet website using: http://%s", ParamsFaucet.BindAddress)

		if err := e.Start(ParamsFaucet.BindAddress); err != nil && !errors.Is(err, http.ErrServerClosed) {
			CoreComponent.LogWarnf("Stopped faucet website server due to an error (%s)", err)
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
