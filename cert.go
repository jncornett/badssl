package badssl

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Certificate is an interface that represents a certificate with an associated
// private key. Certificate extends the Encodable interface.
type Certificate interface {
	GetKey() *PrivateKey
	Encodable
}

type certificate struct {
	privateKey *PrivateKey
	cert       *x509.Certificate
	der        DER
}

// ParseCertificatePEM parses and loads a certificate from PEM data.
func ParseCertificatePEM(data PEM, k *PrivateKey) (c Certificate, err error) {
	return parseCertificatePEM(data, k)
}

// ParseCertificateDER parses and loads a certificate from ASN.1 DER data.
func ParseCertificateDER(data DER, k *PrivateKey) (c Certificate, err error) {
	return parseCertificateDER(data, k)
}

func (c *certificate) GetKey() *PrivateKey {
	return c.privateKey
}

func (c *certificate) GetPEM() (PEM, error) {
	return certDERToPEM(c.der)
}

func certDERToPEM(der DER) (PEM, error) {
	var b bytes.Buffer
	err := pem.Encode(&b, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	return b.Bytes(), err
}

func parseCertificatePEM(data PEM, k *PrivateKey) (c *certificate, err error) {
	var block *pem.Block
	if block, err = decodePEMData(data); err != nil {
		return
	}
	if block.Type != "CERTIFICATE" {
		err = fmt.Errorf("PEM block is not of type CERTIFICATE: %q", block.Type)
	}
	return parseCertificateDER(block.Bytes, k)
}

func parseCertificateDER(data DER, k *PrivateKey) (c *certificate, err error) {
	var cert *x509.Certificate
	if cert, err = x509.ParseCertificate(data); err != nil {
		return
	}
	c = &certificate{
		cert:       cert,
		privateKey: k,
		der:        data,
	}
	return
}

func decodePEMData(data []byte) (block *pem.Block, err error) {
	if len(data) == 0 {
		err = errors.New("zero-length PEM block")
		return
	}
	block, _ = pem.Decode(data)
	if block == nil {
		err = errors.New("no PEM block could be decoded")
	}
	return
}
