package certpin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"
)

func generateTLS(t *testing.T) (Identity, tls.Certificate) {
	t.Helper()

	identity, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := identity.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}

	return identity, certificate
}

// handshake runs both sides over an in-memory pipe and returns their errors.
func handshake(t *testing.T, server, client *tls.Config) (error, error) {
	t.Helper()

	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() { _ = serverSide.Close(); _ = clientSide.Close() })
	_ = serverSide.SetDeadline(time.Now().Add(5 * time.Second))
	_ = clientSide.SetDeadline(time.Now().Add(5 * time.Second))

	serverErr := make(chan error, 1)
	go func() {
		conn := tls.Server(serverSide, server)
		err := conn.Handshake()
		if err == nil {
			// TLS 1.3 servers verify the client after sending Finished;
			// a read surfaces the outcome to the client too.
			_, _ = conn.Write([]byte{1})
		}
		_ = conn.Close()
		serverErr <- err
	}()

	conn := tls.Client(clientSide, client)
	err := conn.Handshake()
	if err == nil {
		_, err = conn.Read(make([]byte, 1))
	}
	_ = conn.Close()

	return <-serverErr, err
}

func TestPinnedMutualTLS(t *testing.T) {
	node, nodeCertificate := generateTLS(t)
	device, deviceCertificate := generateTLS(t)
	nodePin, _ := node.Pin()
	devicePin, _ := device.Pin()

	authorizeDevice := func(pin string) error {
		if pin != devicePin {
			return ErrPolicy
		}
		return nil
	}

	serverErr, clientErr := handshake(t, ServerConfig(nodeCertificate, authorizeDevice), ClientConfig(deviceCertificate, nodePin))
	if serverErr != nil || clientErr != nil {
		t.Fatalf("paired handshake: server %v, client %v", serverErr, clientErr)
	}

	_, stranger := generateTLS(t)
	if serverErr, _ := handshake(t, ServerConfig(nodeCertificate, authorizeDevice), ClientConfig(stranger, nodePin)); serverErr == nil {
		t.Fatal("server accepted an unknown device key")
	}

	if _, clientErr := handshake(t, ServerConfig(nodeCertificate, authorizeDevice), ClientConfig(deviceCertificate, devicePin)); clientErr == nil {
		t.Fatal("client accepted a node key that does not match the pin")
	}
}

func TestServerRefusesClassicalKeyExchangeAndMissingCertificate(t *testing.T) {
	node, nodeCertificate := generateTLS(t)
	_, deviceCertificate := generateTLS(t)
	nodePin, _ := node.Pin()
	allowAll := func(string) error { return nil }

	classical := ClientConfig(deviceCertificate, nodePin)
	classical.CurvePreferences = []tls.CurveID{tls.X25519}
	if serverErr, _ := handshake(t, ServerConfig(nodeCertificate, allowAll), classical); serverErr == nil {
		t.Fatal("server accepted a classical key exchange")
	}

	noCertificate := ClientConfig(deviceCertificate, nodePin)
	noCertificate.Certificates = nil
	if serverErr, _ := handshake(t, ServerConfig(nodeCertificate, allowAll), noCertificate); serverErr == nil {
		t.Fatal("server accepted a client without a certificate")
	}
}

func TestServerRefusesRSAClientKeys(t *testing.T) {
	node, nodeCertificate := generateTLS(t)
	nodePin, _ := node.Pin()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	rsaCertificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	if serverErr, _ := handshake(t, ServerConfig(nodeCertificate, func(string) error { return nil }), ClientConfig(rsaCertificate, nodePin)); serverErr == nil {
		t.Fatal("server accepted an RSA client key")
	}
}

func TestIdentityValidation(t *testing.T) {
	identity, _ := generateTLS(t)
	other, _ := generateTLS(t)

	mismatched := Identity{PrivateKey: identity.PrivateKey, Certificate: other.Certificate}
	if _, err := mismatched.TLSCertificate(); err == nil {
		t.Fatal("TLSCertificate() accepted a key that does not match the certificate")
	}

	pin, err := identity.Pin()
	if err != nil || Validate(pin) != nil {
		t.Fatalf("Pin() = %q, %v", pin, err)
	}
	if Validate("short") == nil {
		t.Fatal("Validate() accepted a malformed pin")
	}
}
