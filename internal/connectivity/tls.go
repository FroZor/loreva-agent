package connectivity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"
)

const tlsHandshakeTimeout = 10 * time.Second

func secureHTTPClient(portalCAPEM string, clientCertificate *tls.Certificate) (*http.Client, error) {
	tlsConfig, err := newTLSConfig(portalCAPEM, clientCertificate)
	if err != nil {
		return nil, err
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSHandshakeTimeout = tlsHandshakeTimeout
	// coder/websocket v1 uses the HTTP/1.1 Upgrade handshake. Explicitly keep
	// this transport off HTTP/2 even when the portal advertises h2 via ALPN.
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	transport.TLSClientConfig = tlsConfig
	transport.DialTLSContext = newTLSDialer(transport.DialContext, tlsConfig)

	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func newTLSConfig(portalCAPEM string, clientCertificate *tls.Certificate) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		NextProtos:       []string{"http/1.1"},
	}

	if portalCAPEM != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(portalCAPEM)) {
			return nil, errors.New("portal_ca does not contain a valid certificate")
		}

		config.RootCAs = roots
	}

	if clientCertificate != nil {
		config.Certificates = []tls.Certificate{*clientCertificate}
	}

	return config, nil
}

func newTLSDialer(baseDial func(context.Context, string, string) (net.Conn, error), config *tls.Config) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		raw, err := baseDial(ctx, network, address)
		if err != nil {
			return nil, err
		}

		connectionConfig := config.Clone()
		if connectionConfig.ServerName == "" {
			host, _, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				_ = raw.Close()
				return nil, fmt.Errorf("resolve TLS server name: %w", splitErr)
			}

			connectionConfig.ServerName = host
		}

		connection := tls.Client(raw, connectionConfig)
		handshakeCtx, cancel := context.WithTimeout(ctx, tlsHandshakeTimeout)
		err = connection.HandshakeContext(handshakeCtx)
		cancel()

		if err != nil {
			_ = raw.Close()
			if retryableTLSIOError(err) {
				return nil, err
			}

			return nil, fmt.Errorf("%w: %v", ErrTLSPolicy, err)
		}

		state := connection.ConnectionState()
		if state.Version != tls.VersionTLS13 || state.CurveID != tls.X25519MLKEM768 {
			_ = connection.Close()
			return nil, ErrTLSPolicy
		}

		return connection, nil
	}
}

func retryableTLSIOError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ENETDOWN) || errors.Is(err, syscall.ENETRESET) ||
		errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTDOWN) ||
		errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ETIMEDOUT) {
		return true
	}

	networkError, ok := errors.AsType[net.Error](err)

	return ok && networkError.Timeout()
}
