package inx

import (
	flag "github.com/spf13/pflag"

	"github.com/gohornet/hornet/pkg/node"
)

const (
	// CfgINXAddress the INX address to which to connect to.
	CfgINXAddress = "inx.address"
)

var params = &node.PluginParams{
	Params: map[string]*flag.FlagSet{
		"appConfig": func() *flag.FlagSet {
			fs := flag.NewFlagSet("", flag.ContinueOnError)
			fs.String(CfgINXAddress, "localhost:9029", "the INX address to which to connect to")
			return fs
		}(),
	},
	Masked: nil,
}
