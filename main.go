package main

import (
	"github.com/gohornet/hornet/core/gracefulshutdown"
	"github.com/gohornet/hornet/pkg/node"
	"github.com/gohornet/inx-faucet/core/app"
	"github.com/gohornet/inx-faucet/core/inx"
	"github.com/gohornet/inx-faucet/plugins/faucet"
)

func main() {
	node.Run(
		node.WithInitPlugin(app.InitPlugin),
		node.WithCorePlugins([]*node.CorePlugin{
			inx.CorePlugin,
			gracefulshutdown.CorePlugin,
		}...),
		node.WithPlugins([]*node.Plugin{
			faucet.Plugin,
		}...),
	)
}
