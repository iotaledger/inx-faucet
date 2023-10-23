package daemon

const (
	PriorityDisconnectINX = iota // no dependencies
	PriorityStopFaucetAcceptedTransactions
	PriorityStopFaucet
)
