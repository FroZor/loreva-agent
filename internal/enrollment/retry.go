package enrollment

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/challenge"
	"github.com/FroZor/loreva-agent/internal/connectivity"
)

const maximumBackoff = 5 * time.Minute

func retryableEnrollmentError(err error) bool {
	if rejected, ok := errors.AsType[*rejectedError](err); ok {
		switch rejected.Code {
		case "expired_pq_proof", "replayed_pq_proof", "internal_error":
			return true
		default:
			return false
		}
	}

	if statusError, ok := errors.AsType[*httpStatusError](err); ok {
		return connectivity.RetryableHTTPStatus(statusError.statusCode)
	}

	if errors.Is(err, connectivity.ErrTLSPolicy) ||
		errors.Is(err, connectivity.ErrSubprotocol) ||
		errors.Is(err, connectivity.ErrInsecureTransport) ||
		errors.Is(err, connectivity.ErrUnsupportedScheme) ||
		errors.Is(err, errAlreadyEnrolled) {
		return false
	}
	if errors.Is(err, challenge.ErrExpired) {
		return true
	}

	status := websocket.CloseStatus(err)
	if status != -1 {
		switch status {
		case websocket.StatusProtocolError,
			websocket.StatusUnsupportedData,
			websocket.StatusPolicyViolation,
			websocket.StatusMessageTooBig,
			websocket.StatusMandatoryExtension:
			return false
		default:
			return true
		}
	}

	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) {
		return true
	}

	_, ok := errors.AsType[net.Error](err)

	return ok
}

func retryDelay(attempt int) time.Duration {
	maximum := 5 * time.Second

	for index := 1; index < attempt && maximum < maximumBackoff; index++ {
		maximum *= 2
		if maximum > maximumBackoff {
			maximum = maximumBackoff
		}
	}

	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0
	}

	return time.Duration(binary.LittleEndian.Uint64(raw[:]) % uint64(maximum+1))
}
