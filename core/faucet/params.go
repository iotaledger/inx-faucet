package faucet

import (
	"time"

	flag "github.com/spf13/pflag"

	"github.com/gohornet/hornet/pkg/node"
	iotago "github.com/iotaledger/iota.go/v3"
)

const (
	// the amount of funds the requester receives.
	CfgFaucetAmount = "faucet.amount"
	// the amount of funds the requester receives if the target address has more funds than the faucet amount and less than maximum.
	CfgFaucetSmallAmount = "faucet.smallAmount"
	// the maximum allowed amount of funds on the target address.
	CfgFaucetMaxAddressBalance = "faucet.maxAddressBalance"
	// the maximum output count per faucet message.
	CfgFaucetMaxOutputCount = "faucet.maxOutputCount"
	// the faucet transaction tag payload.
	CfgFaucetTagMessage = "faucet.tagMessage"
	// the maximum duration for collecting faucet batches.
	CfgFaucetBatchTimeout = "faucet.batchTimeout"
	// the bind address on which the faucet website can be accessed from
	CfgFaucetBindAddress = "faucet.bindAddress"
)

var params = &node.PluginParams{
	Params: map[string]*flag.FlagSet{
		"appConfig": func() *flag.FlagSet {
			fs := flag.NewFlagSet("", flag.ContinueOnError)
			fs.Int64(CfgFaucetAmount, 1000000000, "the amount of funds the requester receives")
			fs.Int64(CfgFaucetSmallAmount, 100000000, "the amount of funds the requester receives if the target address has more funds than the faucet amount and less than maximum")
			fs.Int64(CfgFaucetMaxAddressBalance, 2000000000, "the maximum allowed amount of funds on the target address")
			fs.Int(CfgFaucetMaxOutputCount, iotago.MaxOutputsCount, "the maximum output count per faucet message")
			fs.String(CfgFaucetTagMessage, "HORNET FAUCET", "the faucet transaction tag payload")
			fs.Duration(CfgFaucetBatchTimeout, 2*time.Second, "the maximum duration for collecting faucet batches")
			fs.String(CfgFaucetBindAddress, "localhost:8091", "the bind address on which the faucet website can be accessed from")
			return fs
		}(),
	},
	Masked: nil,
}
