package badssl

// PEM denotes byte data that is PEM-encoded.
type PEM []byte

// DER denotes byte data that is ASN.1 DER-encoded.
type DER []byte

// Encodable is an interface that provides the GetPEM method.
type Encodable interface {
	GetPEM() (PEM, error)
}
