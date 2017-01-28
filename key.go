package badssl

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// RSAKeyBits is the number of bits setting used for generating keys.
// It is exposed for reference.
const RSAKeyBits = 2048

// PublicKey is an interface that wraps an *rsa.PrivateKey and implements
// the Encodable interface for the associated public key.
type PublicKey struct {
	privateKey *rsa.PrivateKey
}

// GetPEM implements the Encodable interface for PublicKey.
// GetPEM encodes the associated public key in PEM format.
func (k *PublicKey) GetPEM() (PEM, error) {
	der, err := x509.MarshalPKIXPublicKey(k.privateKey)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	err = pem.Encode(&b, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	return b.Bytes(), err
}

// PrivateKey is an interface that wraps an *rsa.PrivateKey and implements
// the Encodable interface for it.
type PrivateKey struct {
	privateKey *rsa.PrivateKey
}

// NewPrivateKey generates a new RSA private key with default settings.
func NewPrivateKey() (*PrivateKey, error) {
	k, err := newKey()
	if err != nil {
		return nil, err
	}
	return &PrivateKey{privateKey: k}, nil
}

// ParseKeyPEM parses and loads a private key from PEM data.
func ParseKeyPEM(data PEM) (k *PrivateKey, err error) {
	var block *pem.Block
	if block, err = decodePEMData(data); err != nil {
		return
	}
	if block.Type != "RSA PRIVATE KEY" {
		err = fmt.Errorf("PEM block is not of type RSA PRIVATE KEY: %q", block.Type)
		return
	}
	return ParseKeyDER(block.Bytes)
}

// ParseKeyDER parses and loads a private key from ASN.1 DER data.
func ParseKeyDER(data DER) (k *PrivateKey, err error) {
	var key *rsa.PrivateKey
	if key, err = x509.ParsePKCS1PrivateKey(data); err != nil {
		return
	}
	return &PrivateKey{privateKey: key}, nil
}

// GetPEM implements the Encodable interface for PrivateKey.
// GetPEM encodes the associated private key in PEM format.
func (k *PrivateKey) GetPEM() (PEM, error) {
	var b bytes.Buffer
	err := pem.Encode(&b, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k.privateKey),
	})
	return b.Bytes(), err
}

// Public retrieves the public key from PrivateKey.
func (k *PrivateKey) Public() *PublicKey {
	return &PublicKey{privateKey: k.privateKey}
}

func newKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, RSAKeyBits)
}
