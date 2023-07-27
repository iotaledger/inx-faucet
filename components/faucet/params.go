package faucet

import (
	"time"

	"github.com/iotaledger/hive.go/app"
	iotago "github.com/iotaledger/iota.go/v4"
)

type ParametersFaucet struct {
	Amount            uint64        `default:"1000000000" usage:"the amount of funds the requester receives"`
	SmallAmount       uint64        `default:"100000000" usage:"the amount of funds the requester receives if the target address has more funds than the faucet amount and less than maximum"`
	MaxAddressBalance uint64        `default:"2000000000" usage:"the maximum allowed amount of funds on the target address"`
	MaxOutputCount    int           `usage:"the maximum output count per faucet message"`
	TagMessage        string        `default:"HORNET FAUCET" usage:"the faucet transaction tag payload"`
	BatchTimeout      time.Duration `default:"2s" usage:"the maximum duration for collecting faucet batches"`
	BindAddress       string        `default:"localhost:8091" usage:"the bind address on which the faucet website can be accessed from"`
	RateLimit         struct {
		Enabled     bool          `default:"true" usage:"whether the rate limiting should be enabled"`
		Period      time.Duration `default:"5m" usage:"the period for rate limiting"`
		MaxRequests int           `default:"10" usage:"the maximum number of requests per period"`
		MaxBurst    int           `default:"20" usage:"additional requests allowed in the burst period"`
	}
	// DebugRequestLoggerEnabled defines whether the debug logging for requests should be enabled
	DebugRequestLoggerEnabled bool `default:"false" usage:"whether the debug logging for requests should be enabled"`
}

var ParamsFaucet = &ParametersFaucet{
	MaxOutputCount: iotago.MaxOutputsCount,
}

var params = &app.ComponentParams{
	Params: map[string]any{
		"faucet": ParamsFaucet,
	},
	Masked: nil,
}
