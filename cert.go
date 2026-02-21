package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// ensureCertificate loads or generates a self-signed certificate for OPC UA.
// Returns the paths to the cert and key PEM files.
func ensureCertificate(pkiDir string) (certFile, keyFile string, err error) {
	certFile = filepath.Join(pkiDir, "cert.pem")
	keyFile = filepath.Join(pkiDir, "key.pem")

	// Check if both files exist
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			return certFile, keyFile, nil
		}
	}

	// Generate new self-signed certificate
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		return "", "", fmt.Errorf("create PKI directory: %w", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generate RSA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("generate serial number: %w", err)
	}

	appURI, _ := url.Parse("urn:tentacle-opcua")

	// Get hostname for SAN (OPC UA Part 6 requires it)
	hostname, _ := os.Hostname()
	dnsNames := []string{"localhost"}
	if hostname != "" && hostname != "localhost" {
		dnsNames = append(dnsNames, hostname)
	}

	// Compute SubjectKeyIdentifier per RFC 5280 method 1:
	// SHA-1 hash of the BIT STRING subjectPublicKey (excluding tag/length)
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	ski := sha1.Sum(pubKeyBytes)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "tentacle-opcua",
			Organization: []string{"Tentacle"},
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years

		// Match Ignition's own cert format exactly:
		// Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Cert Sign
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
			x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment |
			x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,

		// SAN: ApplicationURI + hostnames + loopback
		URIs:        []*url.URL{appURI},
		DNSNames:    dnsNames,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},

		// SKI + AKI (both required for self-signed cert chain validation)
		SubjectKeyId:   ski[:],
		AuthorityKeyId: ski[:],
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("create certificate: %w", err)
	}

	// Write cert PEM
	certOut, err := os.Create(certFile)
	if err != nil {
		return "", "", fmt.Errorf("create cert file: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return "", "", fmt.Errorf("encode cert PEM: %w", err)
	}

	// Write key PEM
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", "", fmt.Errorf("create key file: %w", err)
	}
	defer keyOut.Close()
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}); err != nil {
		return "", "", fmt.Errorf("encode key PEM: %w", err)
	}

	return certFile, keyFile, nil
}
