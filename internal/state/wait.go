package state

import (
	"context"
	"errors"
	"time"
)

// pollInterval is how often the waits below re-read state that another
// agent process may change.
const pollInterval = 250 * time.Millisecond

// WaitUntilConnectionEnabled returns once the connection preference allows
// a portal session, or with the context's error.
func (s *Store) WaitUntilConnectionEnabled(ctx context.Context) error {
	return poll(ctx, func() (bool, error) {
		return s.ConnectionEnabled()
	})
}

// WaitUntilConnectionDisabled returns nil once the connection preference no
// longer allows a portal session, the context's error when it ends first, or
// the error that kept the preference from being read.
func (s *Store) WaitUntilConnectionDisabled(ctx context.Context) error {
	return poll(ctx, func() (bool, error) {
		enabled, err := s.ConnectionEnabled()

		return !enabled, err
	})
}

// LockConnection waits until no other runner holds the connection lock and
// acquires it.
func (s *Store) LockConnection(ctx context.Context) (*Lock, error) {
	var lock *Lock
	err := poll(ctx, func() (bool, error) {
		acquired, err := s.TryLockConnection()
		if errors.Is(err, ErrConnectionActive) {
			return false, nil
		}
		if err != nil {
			return false, err
		}

		lock = acquired

		return true, nil
	})
	if err != nil {
		return nil, err
	}

	return lock, nil
}

// WaitUntilConnectionReleased returns once no runner holds the connection
// lock, or with the context's error.
func (s *Store) WaitUntilConnectionReleased(ctx context.Context) error {
	lock, err := s.LockConnection(ctx)
	if err != nil {
		return err
	}

	return lock.Close()
}

// AgentRunning reports whether an agent process holds this state directory.
func (s *Store) AgentRunning() (bool, error) {
	lock, err := s.TryLockProcess()
	if err == nil {
		return false, lock.Close()
	}
	if errors.Is(err, ErrAgentRunning) {
		return true, nil
	}

	return false, err
}

// poll calls done until it reports true or fails, checking first and then
// every pollInterval.
func poll(ctx context.Context, done func() (bool, error)) error {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		ok, err := done()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
