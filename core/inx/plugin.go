package inx

import (
	"context"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"go.uber.org/dig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/gohornet/hornet/pkg/node"
	"github.com/gohornet/hornet/pkg/shutdown"
	"github.com/gohornet/inx-faucet/pkg/daemon"
	"github.com/gohornet/inx-faucet/pkg/nodebridge"
	"github.com/iotaledger/hive.go/configuration"
	inx "github.com/iotaledger/inx/go"
)

func init() {
	CorePlugin = &node.CorePlugin{
		Pluggable: node.Pluggable{
			Name:     "INX",
			DepsFunc: func(cDeps dependencies) { deps = cDeps },
			Params:   params,
			Provide:  provide,
			Run:      run,
		},
	}
}

type dependencies struct {
	dig.In
	AppConfig  *configuration.Configuration `name:"appConfig"`
	NodeBridge *nodebridge.NodeBridge
	Connection *grpc.ClientConn
}

var (
	CorePlugin *node.CorePlugin
	deps       dependencies
)

func provide(c *dig.Container) {

	type inxDeps struct {
		dig.In
		AppConfig       *configuration.Configuration `name:"appConfig"`
		ShutdownHandler *shutdown.ShutdownHandler
	}

	type inxDepsOut struct {
		dig.Out
		Connection *grpc.ClientConn
		INXClient  inx.INXClient
	}

	if err := c.Provide(func(deps inxDeps) (inxDepsOut, error) {
		conn, err := grpc.Dial(deps.AppConfig.String(CfgINXAddress),
			grpc.WithChainUnaryInterceptor(grpc_retry.UnaryClientInterceptor(), grpc_prometheus.UnaryClientInterceptor),
			grpc.WithStreamInterceptor(grpc_prometheus.StreamClientInterceptor),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			return inxDepsOut{}, err
		}
		client := inx.NewINXClient(conn)

		return inxDepsOut{
			Connection: conn,
			INXClient:  client,
		}, nil
	}); err != nil {
		CorePlugin.LogPanic(err)
	}

	if err := c.Provide(func(client inx.INXClient) (*nodebridge.NodeBridge, error) {
		return nodebridge.NewNodeBridge(CorePlugin.Daemon().ContextStopped(),
			client,
			CorePlugin.Logger())
	}); err != nil {
		CorePlugin.LogPanic(err)
	}
}

func run() {
	if err := CorePlugin.Daemon().BackgroundWorker("INX", func(ctx context.Context) {
		CorePlugin.LogInfo("Starting NodeBridge")
		deps.NodeBridge.Run(ctx)
		CorePlugin.LogInfo("Stopped NodeBridge")
		deps.Connection.Close()
	}, daemon.PriorityDisconnectINX); err != nil {
		CorePlugin.LogPanicf("failed to start worker: %s", err)
	}
}
