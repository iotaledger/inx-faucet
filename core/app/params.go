package app

import (
	flag "github.com/spf13/pflag"

	"github.com/gohornet/hornet/pkg/node"
)

const (
	// CfgAppDisablePlugins defines a list of plugins that shall be disabled
	CfgAppDisablePlugins = "app.disablePlugins"
	// CfgAppEnablePlugins defines a list of plugins that shall be enabled
	CfgAppEnablePlugins = "app.enablePlugins"

	CfgConfigFilePathAppConfig = "config"
)

var params = &node.PluginParams{
	Params: map[string]*flag.FlagSet{
		"appConfig": func() *flag.FlagSet {
			fs := flag.NewFlagSet("", flag.ContinueOnError)
			fs.StringSlice(CfgAppDisablePlugins, nil, "a list of plugins that shall be disabled")
			fs.StringSlice(CfgAppEnablePlugins, nil, "a list of plugins that shall be enabled")
			return fs
		}(),
	},
	Masked: nil,
}
