package connectivity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDialRejectsClassicalTLSWithoutRetryableError(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	}
	server.StartTLS()
	defer server.Close()

	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	dialer, err := NewDialer(Config{PortalCAPEM: string(ca)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err = dialer.Dial(ctx, "wss"+strings.TrimPrefix(server.URL, "https"), DialOptions{})
	if !errors.Is(err, ErrTLSPolicy) {
		t.Fatalf("classical TLS error = %v, want ErrTLSPolicy", err)
	}
}

func TestCustomPortalCAUsesDedicatedTrustPool(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	config, err := newTLSConfig(string(ca), nil)
	if err != nil {
		t.Fatal(err)
	}

	expected := x509.NewCertPool()
	if !expected.AppendCertsFromPEM(ca) {
		t.Fatal("test portal CA could not be added to expected pool")
	}
	if config.RootCAs == nil || !config.RootCAs.Equal(expected) {
		t.Fatal("custom portal CA was not isolated from the system trust pool")
	}
}

func TestRetryableTLSIOErrorRecognizesNetworkReset(t *testing.T) {
	err := &net.OpError{Op: "read", Net: "tcp", Err: syscall.ENETRESET}
	if !retryableTLSIOError(err) {
		t.Fatal("network reset during TLS handshake was classified as a policy violation")
	}
}

func TestRetryableHTTPStatus(t *testing.T) {
	for _, status := range []int{http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		if !RetryableHTTPStatus(status) {
			t.Fatalf("temporary HTTP status %d was classified as terminal", status)
		}
	}
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusUpgradeRequired} {
		if RetryableHTTPStatus(status) {
			t.Fatalf("terminal HTTP status %d was classified as retryable", status)
		}
	}
}
