package daemon

const (
	PriorityDisconnectINX = iota // no dependencies
	PriorityStopFaucetLedgerUpdates
	PriorityStopFaucet
)
