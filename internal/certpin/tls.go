package certpin

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// ErrPolicy means a connection did not use TLS 1.3 with the hybrid
// post-quantum key exchange, or its peer key is not the expected one.
var ErrPolicy = errors.New("connection does not meet the direct access TLS policy")

// Direct access accepts only TLS 1.3 with X25519MLKEM768, on both sides:
// there is no classical fallback to downgrade to.
var postQuantumGroups = []tls.CurveID{tls.X25519MLKEM768}

// ServerConfig requires a client certificate on every connection and lets
// authorize decide, by the client's pin, whether the handshake may finish.
// A peer that authorize rejects never reaches HTTP.
func ServerConfig(certificate tls.Certificate, authorize func(pin string) error) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: postQuantumGroups,
		Certificates:     []tls.Certificate{certificate},
		NextProtos:       []string{"http/1.1"},
		// Self-signed device certificates are checked by pin, not by a CA.
		ClientAuth: tls.RequireAnyClientCert,
		// Tickets would let a revoked device resume without the checks below.
		SessionTicketsDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			certificate, err := peerCertificate(state)
			if err != nil {
				return err
			}

			return authorize(Of(certificate))
		},
	}
}

// ClientConfig presents the device certificate and accepts only the node key
// with the given pin.
func ClientConfig(certificate tls.Certificate, nodePin string) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: postQuantumGroups,
		Certificates:     []tls.Certificate{certificate},
		NextProtos:       []string{"http/1.1"},
		// The node certificate is self-signed; VerifyConnection checks its pin.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			certificate, err := peerCertificate(state)
			if err != nil {
				return err
			}
			if subtle.ConstantTimeCompare([]byte(Of(certificate)), []byte(nodePin)) != 1 {
				return ErrPolicy
			}

			return nil
		},
	}
}

func peerCertificate(state tls.ConnectionState) (*x509.Certificate, error) {
	if state.Version != tls.VersionTLS13 || state.CurveID != tls.X25519MLKEM768 {
		return nil, ErrPolicy
	}
	if len(state.PeerCertificates) == 0 {
		return nil, ErrPolicy
	}

	certificate := state.PeerCertificates[0]
	if !AcceptedKey(certificate) {
		return nil, ErrPolicy
	}

	return certificate, nil
}
