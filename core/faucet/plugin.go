package faucet

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/pkg/errors"
	"go.uber.org/dig"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gohornet/hornet/pkg/common"
	"github.com/gohornet/hornet/pkg/node"
	"github.com/gohornet/hornet/pkg/shutdown"
	"github.com/gohornet/hornet/pkg/utils"
	"github.com/gohornet/inx-faucet/pkg/daemon"
	"github.com/gohornet/inx-faucet/pkg/faucet"
	"github.com/gohornet/inx-faucet/pkg/nodebridge"
	"github.com/iotaledger/hive.go/configuration"
	"github.com/iotaledger/hive.go/events"
	inx "github.com/iotaledger/inx/go"
	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/iotaledger/iota.go/v3/nodeclient"
)

func init() {
	CorePlugin = &node.CorePlugin{
		Pluggable: node.Pluggable{
			Name:      "Faucet",
			DepsFunc:  func(cDeps dependencies) { deps = cDeps },
			Params:    params,
			Provide:   provide,
			Configure: configure,
			Run:       run,
		},
	}
}

var (
	CorePlugin *node.CorePlugin
	deps       dependencies

	// closures
	onLedgerUpdated *events.Closure
)

type dependencies struct {
	dig.In
	AppConfig       *configuration.Configuration `name:"appConfig"`
	NodeBridge      *nodebridge.NodeBridge
	Faucet          *faucet.Faucet
	ShutdownHandler *shutdown.ShutdownHandler
}

func provide(c *dig.Container) {

	privateKeys, err := utils.LoadEd25519PrivateKeysFromEnvironment("FAUCET_PRV_KEY")
	if err != nil {
		CorePlugin.LogPanicf("loading faucet private key failed, err: %s", err)
	}

	if len(privateKeys) == 0 {
		CorePlugin.LogPanic("loading faucet private key failed, err: no private keys given")
	}

	if len(privateKeys) > 1 {
		CorePlugin.LogPanic("loading faucet private key failed, err: too many private keys given")
	}

	privateKey := privateKeys[0]
	if len(privateKey) != ed25519.PrivateKeySize {
		CorePlugin.LogPanic("loading faucet private key failed, err: wrong private key length")
	}

	faucetAddress := iotago.Ed25519AddressFromPubKey(privateKey.Public().(ed25519.PublicKey))
	faucetSigner := iotago.NewInMemoryAddressSigner(iotago.NewAddressKeysForEd25519Address(&faucetAddress, privateKey))

	type faucetDeps struct {
		dig.In
		AppConfig  *configuration.Configuration `name:"appConfig"`
		NodeBridge *nodebridge.NodeBridge
	}

	if err := c.Provide(func(deps faucetDeps) *faucet.Faucet {

		fetchMetadata := func(ctx context.Context, messageID iotago.MessageID) (*faucet.Metadata, error) {
			metadata, err := deps.NodeBridge.MessageMetadata(ctx, messageID)
			if err != nil {
				st, ok := status.FromError(err)
				if ok && st.Code() == codes.NotFound {
					return nil, nil
				}
				return nil, err
			}
			return &faucet.Metadata{
				IsReferenced:   metadata.GetReferencedByMilestoneIndex() != 0,
				IsConflicting:  metadata.GetConflictReason() != inx.MessageMetadata_NONE,
				ShouldReattach: metadata.GetShouldReattach(),
			}, nil
		}

		nodeClient := deps.NodeBridge.INXNodeClient()
		bech32Prefix := deps.NodeBridge.ProtocolParameters.NetworkPrefix()

		collectOutputs := func(ctx context.Context, address iotago.Address) ([]faucet.UTXOOutput, error) {

			indexer, err := nodeClient.Indexer(ctx)
			if err != nil {
				return nil, err
			}

			query := &nodeclient.BasicOutputsQuery{
				AddressBech32: address.Bech32(bech32Prefix),
				IndexerExpirationParas: nodeclient.IndexerExpirationParas{
					HasExpirationCondition: false,
				},
				IndexerTimelockParas: nodeclient.IndexerTimelockParas{
					HasTimelockCondition: false,
				},
				IndexerStorageDepositParas: nodeclient.IndexerStorageDepositParas{
					RequiresStorageDepositReturn: false,
				},
			}

			result, err := indexer.Outputs(ctx, query)
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
					faucetOutputs = append(faucetOutputs, faucet.UTXOOutput{
						OutputID: outputIDs[i],
						Output:   outputs[i].(*iotago.BasicOutput),
					})
				}
			}
			if result.Error != nil {
				return nil, result.Error
			}

			return faucetOutputs, nil
		}

		return faucet.New(
			CorePlugin.Daemon(),
			fetchMetadata,
			collectOutputs,
			deps.NodeBridge.IsNodeSynced,
			iotago.NetworkIDFromString(deps.NodeBridge.ProtocolParameters.GetNetworkName()),
			deps.NodeBridge.DeSerializationParameters(),
			&faucetAddress,
			faucetSigner,
			deps.NodeBridge.EmitMessage,
			faucet.WithLogger(CorePlugin.Logger()),
			faucet.WithHRPNetworkPrefix(bech32Prefix),
			faucet.WithTokenName("IOTA"), //TODO: get name from future protocol params
			faucet.WithAmount(uint64(deps.AppConfig.Int64(CfgFaucetAmount))),
			faucet.WithSmallAmount(uint64(deps.AppConfig.Int64(CfgFaucetSmallAmount))),
			faucet.WithMaxAddressBalance(uint64(deps.AppConfig.Int64(CfgFaucetMaxAddressBalance))),
			faucet.WithMaxOutputCount(deps.AppConfig.Int(CfgFaucetMaxOutputCount)),
			faucet.WithTagMessage(deps.AppConfig.String(CfgFaucetTagMessage)),
			faucet.WithBatchTimeout(deps.AppConfig.Duration(CfgFaucetBatchTimeout)),
			faucet.WithPowWorkerCount(deps.AppConfig.Int(CfgFaucetPoWWorkerCount)),
		)
	}); err != nil {
		CorePlugin.LogPanic(err)
	}
}

func configure() {
	configureEvents()
}

func run() {
	// create a background worker that handles the enqueued faucet requests
	if err := CorePlugin.Daemon().BackgroundWorker("Faucet", func(ctx context.Context) {
		attachEvents()
		if err := deps.Faucet.RunFaucetLoop(ctx, nil); err != nil && common.IsCriticalError(err) != nil {
			deps.ShutdownHandler.SelfShutdown(fmt.Sprintf("faucet plugin hit a critical error: %s", err.Error()))
		}
		detachEvents()
	}, daemon.PriorityStopFaucet); err != nil {
		CorePlugin.LogPanicf("failed to start worker: %s", err)
	}

	bindAddr := deps.AppConfig.String(CfgFaucetBindAddress)

	e := echo.New()
	e.HideBanner = true
	e.Use(middleware.Recover())

	setupRoutes(e)

	go func() {
		CorePlugin.LogInfof("You can now access the faucet website using: http://%s", bindAddr)

		if err := e.Start(bindAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
			CorePlugin.LogWarnf("Stopped faucet website server due to an error (%s)", err)
		}
	}()

}

func configureEvents() {
	onLedgerUpdated = events.NewClosure(func(update *inx.LedgerUpdate) {

		createdOutputs := iotago.OutputIDs{}
		for _, output := range update.GetCreated() {
			createdOutputs = append(createdOutputs, *output.GetOutputId().Unwrap())
		}
		consumedOutputs := iotago.OutputIDs{}
		for _, spent := range update.GetConsumed() {
			consumedOutputs = append(consumedOutputs, *spent.GetOutput().GetOutputId().Unwrap())
		}

		if err := deps.Faucet.ApplyNewLedgerUpdate(createdOutputs, consumedOutputs); err != nil {
			deps.ShutdownHandler.SelfShutdown(fmt.Sprintf("faucet plugin hit a critical error while applying new ledger update: %s", err.Error()))
		}
	})
}

func attachEvents() {
	deps.NodeBridge.Events.LedgerUpdated.Attach(onLedgerUpdated)
}

func detachEvents() {
	deps.NodeBridge.Events.LedgerUpdated.Detach(onLedgerUpdated)
}
