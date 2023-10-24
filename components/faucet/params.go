package faucet

import (
	"time"

	"github.com/iotaledger/hive.go/app"
)

type ParametersFaucet struct {
	BaseTokenAmount          uint64        `default:"1000000000" usage:"the amount of funds the requester receives"`
	BaseTokenAmountSmall     uint64        `default:"100000000" usage:"the amount of funds the requester receives if the target address has more funds than the faucet amount and less than maximum"`
	BaseTokenAmountMaxTarget uint64        `default:"5000000000" usage:"the maximum allowed amount of funds on the target address"`
	ManaAmount               uint64        `default:"1000" usage:"the amount of mana the requester receives"`
	ManaAmountMinFaucet      uint64        `default:"1000000" usage:"the minimum amount of mana the faucet needs to hold before mana payouts become active"`
	TagMessage               string        `default:"FAUCET" usage:"the faucet transaction tag payload"`
	BatchTimeout             time.Duration `default:"2s" usage:"the maximum duration for collecting faucet batches"`
	BindAddress              string        `default:"localhost:8091" usage:"the bind address on which the faucet website can be accessed from"`
	RateLimit                struct {
		Enabled     bool          `default:"true" usage:"whether the rate limiting should be enabled"`
		Period      time.Duration `default:"5m" usage:"the period for rate limiting"`
		MaxRequests int           `default:"10" usage:"the maximum number of requests per period"`
		MaxBurst    int           `default:"20" usage:"additional requests allowed in the burst period"`
	}
	PoW struct {
		// the amount of workers used for calculating PoW when sending payloads to the block issuer
		WorkerCount int `default:"4" usage:"the amount of workers used for calculating PoW when sending payloads to the block issuer"`
	} `name:"pow"`
	// DebugRequestLoggerEnabled defines whether the debug logging for requests should be enabled
	DebugRequestLoggerEnabled bool `default:"false" usage:"whether the debug logging for requests should be enabled"`
}

var ParamsFaucet = &ParametersFaucet{}

var params = &app.ComponentParams{
	Params: map[string]any{
		"faucet": ParamsFaucet,
	},
	Masked: nil,
}
