package badssl

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

const (
	// RootCAKeyUsage is the key usage setting used for creating the root
	// certificate authority. It is exposed for reference.
	RootCAKeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
)

// CertOptions is used to configure a certificate during certificate creation.
type CertOptions struct {
	// ValidFor is the amount of time that a certificate will be valid for.
	ValidFor time.Duration
	// CommonName is the common name associated with the certificate subject.
	CommonName string
}

// Authority is an interface that represents a certificate authority.
// It extends the Certificate interface with the ability to create
// child certificates.
type Authority interface {
	Certificate
	// NewCert creates a new certificate that is signed by Authority.
	NewCert(*PrivateKey, CertOptions) (Certificate, error)
}

type authority struct {
	c *certificate
}

// NewAuthority generates a new (root) certificate authority with private key
// k and configuration options o. If k is nil, a new private key will be
// generated.
func NewAuthority(k *PrivateKey, o CertOptions) (a Authority, err error) {
	if k == nil {
		if k, err = NewPrivateKey(); err != nil {
			return
		}
	}
	var cert *x509.Certificate
	if cert, err = newAuthorityCertificate(o); err != nil {
		return
	}
	var der DER
	der, err = x509.CreateCertificate(
		rand.Reader,
		cert,
		cert,
		&k.privateKey.PublicKey,
		k.privateKey,
	)
	if err != nil {
		return
	}
	auth := &authority{
		c: &certificate{
			cert:       cert,
			privateKey: k,
			der:        der,
		},
	}
	a, err = auth.Reload()
	return
}

// ParseAuthorityPEM parses and loads a certificate authority from PEM data.
func ParseAuthorityPEM(data PEM, k *PrivateKey) (a Authority, err error) {
	var c *certificate
	if c, err = parseCertificatePEM(data, k); err != nil {
		return
	}
	a = &authority{c: c}
	return
}

// ParseAuthorityDER parses and loads a certificate authority from
// ASN.1 DER data.
func ParseAuthorityDER(data DER, k *PrivateKey) (a Authority, err error) {
	var c *certificate
	if c, err = parseCertificateDER(data, k); err != nil {
		return
	}
	a = &authority{c: c}
	return
}

func (a *authority) GetPEM() (PEM, error) {
	return a.c.GetPEM()
}

func (a *authority) GetKey() *PrivateKey {
	return a.c.GetKey()
}

func (a *authority) NewCert(
	k *PrivateKey,
	o CertOptions,
) (c Certificate, err error) {
	if k == nil {
		if k, err = NewPrivateKey(); err != nil {
			return
		}
	}
	var cert *x509.Certificate
	if cert, err = newServerCertificate(o); err != nil {
		return
	}
	var der DER
	der, err = x509.CreateCertificate(
		rand.Reader,
		cert,
		a.c.cert,
		&k.privateKey.PublicKey,
		a.c.privateKey.privateKey,
	)
	if err != nil {
		return
	}
	c = &certificate{
		cert:       cert,
		privateKey: k,
		der:        der,
	}
	return
}

func (a *authority) Reload() (Authority, error) {
	return ParseAuthorityDER(a.c.der, a.c.privateKey)
}

func newAuthorityCertificate(o CertOptions) (*x509.Certificate, error) {
	sn, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(o.ValidFor)
	cert := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: o.CommonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              RootCAKeyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
	}
	return cert, nil
}

func newServerCertificate(o CertOptions) (*x509.Certificate, error) {
	sn, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(o.ValidFor)
	cert := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: o.CommonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              0,   // TODO
		ExtKeyUsage:           nil, // TODO
		BasicConstraintsValid: true,
	}
	return cert, nil
}

func randomSerialNumber() (sn *big.Int, err error) {
	snLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	sn, err = rand.Int(rand.Reader, snLimit)
	return
}
