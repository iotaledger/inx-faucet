package faucet

import "github.com/iotaledger/hive.go/ierrors"

// CriticalError wraps the given error as a critical error.
func CriticalError(err error) error {
	return &criticalError{err: err}
}

// IsCriticalError unwraps the inner error held by the critical error if the given error is a critical error.
// If the given error is not a critical error, nil is returned.
func IsCriticalError(err error) error {
	var critErr *criticalError
	if ierrors.As(err, &critErr) {
		return critErr.Unwrap()
	}

	return nil
}

// criticalError is an error which is critical, meaning that the node must halt operation.
type criticalError struct {
	err error
}

func (ce criticalError) Error() string { return ce.err.Error() }
func (ce criticalError) Unwrap() error { return ce.err }
