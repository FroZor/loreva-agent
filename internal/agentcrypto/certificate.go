package agentcrypto

import (
	"crypto/tls"
	"fmt"
	"strings"
)

// ClientCertificate loads the persisted ECDSA private key and portal-issued
// certificate chain for mutual TLS.
func ClientCertificate(privateKeyPEM string, certificateChain []string) (tls.Certificate, error) {
	certificatePEM := []byte(strings.Join(certificateChain, "\n"))
	certificate, err := tls.X509KeyPair(certificatePEM, []byte(privateKeyPEM))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load mTLS identity: %w", err)
	}

	return certificate, nil
}
