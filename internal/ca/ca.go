// Package ca generates and loads the local Leash MITM CA. Per
// ARCHITECTURE.md section 0.5: this CA is trusted only via environment
// variables injected into the session's child process tree — v0.1 never
// touches the OS trust store.
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Paths holds the on-disk locations of the CA cert and key.
type Paths struct {
	CertPath string
	KeyPath  string
}

// Ensure loads the CA at dir if present, generating a new one otherwise.
// Returns the PEM-encoded cert and key bytes plus their file paths.
//
// Known limitation (E7, v0.1 security review): two `leash run` processes
// racing on first ever launch (CA files not yet present) can each generate
// and write their own CA, with the second write winning on disk while the
// first process keeps its own in-memory cert — every TLS handshake in that
// first session then fails (fail-closed, not a security hole, just
// confusing). Not fixed in v0.1, which is explicitly single-session scoped
// (ARCHITECTURE.md 0.2); if/when concurrent sessions are supported, this
// should switch to an O_EXCL create with a re-read-on-conflict fallback.
func Ensure(dir string) (certPEM, keyPEM []byte, paths Paths, err error) {
	paths = Paths{
		CertPath: filepath.Join(dir, "ca.pem"),
		KeyPath:  filepath.Join(dir, "ca-key.pem"),
	}

	if _, statErr := os.Stat(paths.CertPath); statErr == nil {
		certPEM, err = os.ReadFile(paths.CertPath)
		if err != nil {
			return nil, nil, paths, err
		}
		keyPEM, err = os.ReadFile(paths.KeyPath)
		if err != nil {
			return nil, nil, paths, err
		}
		return certPEM, keyPEM, paths, nil
	}

	if err = os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, paths, err
	}

	certPEM, keyPEM, err = generate()
	if err != nil {
		return nil, nil, paths, err
	}
	if err = os.WriteFile(paths.CertPath, certPEM, 0o644); err != nil {
		return nil, nil, paths, err
	}
	if err = os.WriteFile(paths.KeyPath, keyPEM, 0o600); err != nil {
		return nil, nil, paths, err
	}
	return certPEM, keyPEM, paths, nil
}

func generate() (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Leash Local MITM CA",
			Organization: []string{"Leash (local, session-scoped trust)"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}
