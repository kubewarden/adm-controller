package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestVerifyCertInvalidPEMHeader(t *testing.T) {
	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Marshall it
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	// PEM encode with WRONG header "RSA PRIVATE KEY"
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Generate a dummy cert to go with it
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.com"},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	// Create CertPool (self-signed)
	pool := x509.NewCertPool()

	// VerifyCert should FAIL
	err = VerifyCert(certPEM, privateKeyPEM, pool, "example.com", time.Now())
	if err == nil {
		t.Fatal("VerifyCert should have failed with invalid PEM header")
	}
	expectedError := "private key has invalid PEM header, expected 'EC PRIVATE KEY'"
	if err.Error() != expectedError {
		t.Fatalf("Expected error %q, got %q", expectedError, err.Error())
	}
}

func TestVerifyCertValidPEMHeader(t *testing.T) {
	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Marshall it
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	// PEM encode with CORRECT header "EC PRIVATE KEY"
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Generate a dummy cert to go with it
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.com"},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	// Create CertPool (self-signed)
	pool := x509.NewCertPool()
	cert, _ := x509.ParseCertificate(certBytes)
	pool.AddCert(cert)

	// VerifyCert should SUCCEED
	err = VerifyCert(certPEM, privateKeyPEM, pool, "example.com", time.Now())
	if err != nil {
		t.Fatalf("VerifyCert failed with valid PEM header: %v", err)
	}
}

func TestInvalidPEMReturnsError(t *testing.T) {
	caCert, caPrivateKey, err := GenerateCA(time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	garbage := []byte("not a PEM block")

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "VerifyCert with an invalid certificate",
			run: func() error {
				return VerifyCert(garbage, nil, x509.NewCertPool(), "", time.Now())
			},
		},
		{
			name: "VerifyCA with an invalid certificate",
			run: func() error {
				return VerifyCA(garbage, nil, time.Now())
			},
		},
		{
			name: "GenerateCert with an invalid CA certificate",
			run: func() error {
				_, _, err := GenerateCert(garbage, caPrivateKey, time.Now(), time.Now().Add(time.Hour), "example.com")
				return err
			},
		},
		{
			name: "GenerateCert with an invalid CA private key",
			run: func() error {
				_, _, err := GenerateCert(caCert, garbage, time.Now(), time.Now().Add(time.Hour), "example.com")
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}
