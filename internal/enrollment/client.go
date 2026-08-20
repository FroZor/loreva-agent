// Package enrollment registers and persists a node's first portal identity.
package enrollment

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/connectivity"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/state"
)

const handshakeTimeout = 30 * time.Second

var errAlreadyEnrolled = errors.New("agent identity already exists; refusing to overwrite it")

// Options defines the bootstrap inputs used for initial enrollment.
type Options struct {
	PortalURL          string
	Token              string
	PortalCAPEM        string
	PortalPQRoot       *agentcrypto.JWK
	StateDir           string
	Version            string
	Hostname           string
	AllowDevelopmentWS bool
	OnRetry            func(error, time.Duration)
}

type rejectedError struct {
	Code    string
	Message string
}

type httpStatusError struct{ statusCode int }

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("portal returned HTTP %d during enrollment", e.statusCode)
}

func (e *rejectedError) Error() string {
	if e.Message == "" {
		return "portal rejected enrollment: " + e.Code
	}
	return "portal rejected enrollment: " + e.Code + ": " + e.Message
}

// Enroll registers a new agent identity and persists it before returning.
func Enroll(ctx context.Context, options Options) (*state.Identity, error) {
	if err := normalizeAndValidateOptions(&options); err != nil {
		return nil, err
	}

	attempt := 0

	for {
		identity, err := enrollOnce(ctx, options)
		if err == nil {
			return identity, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !retryableEnrollmentError(err) {
			return nil, err
		}

		attempt++
		delay := retryDelay(attempt)

		if options.OnRetry != nil {
			options.OnRetry(err, delay)
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func enrollOnce(ctx context.Context, options Options) (*state.Identity, error) {
	store, err := state.New(options.StateDir)
	if err != nil {
		return nil, err
	}

	if _, err := store.LoadIdentity(); err == nil {
		return nil, errAlreadyEnrolled
	} else if !errors.Is(err, state.ErrNotFound) {
		return nil, fmt.Errorf("load existing identity: %w", err)
	}

	dialer, err := connectivity.NewDialer(connectivity.Config{
		PortalCAPEM:        options.PortalCAPEM,
		AllowDevelopmentWS: options.AllowDevelopmentWS,
	})
	if err != nil {
		return nil, err
	}

	endpoint, err := connectivity.Endpoint(options.PortalURL, "/agent/v1/enroll")
	if err != nil {
		return nil, err
	}

	tokenID, err := enrollmentTokenID(options.Token)
	if err != nil {
		return nil, err
	}

	pending, material, err := loadOrCreatePending(store, options, endpoint, tokenID)
	if err != nil {
		return nil, err
	}

	handshakeCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()

	header := make(http.Header)
	header.Set("Authorization", "Bearer "+options.Token)

	conn, response, err := dialer.Dial(handshakeCtx, endpoint, connectivity.DialOptions{
		Header:       header,
		Subprotocols: []string{protocol.EnrollmentSubprotocol},
	})
	if err != nil {
		if response != nil {
			return nil, &httpStatusError{statusCode: response.StatusCode}
		}
		return nil, err
	}
	defer conn.CloseNow()

	enrolledIdentity, err := exchangeEnrollment(handshakeCtx, conn, options, pending, material)
	if err != nil {
		return nil, err
	}
	if err := store.SaveIdentity(enrolledIdentity); err != nil {
		return nil, fmt.Errorf("persist enrolled identity: %w", err)
	}
	if err := store.ClearPending(); err != nil {
		return nil, fmt.Errorf("enrolled identity committed but pending state cleanup failed: %w", err)
	}

	_ = conn.Close(websocket.StatusNormalClosure, "")

	return enrolledIdentity, nil
}
