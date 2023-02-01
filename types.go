package authrootstl

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

type rawCertificates struct {
	Raw asn1.RawContent
}

type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                contentInfo
	CertBytes                  rawCertificates        `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo           `asn1:"set"`
}

func (d signedData) Certificates() ([]*x509.Certificate, error) {
	var val asn1.RawValue
	if _, err := asn1.Unmarshal(d.CertBytes.Raw, &val); err != nil {
		return nil, err
	}

	return x509.ParseCertificates(val.Bytes)
}

type signerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"optional,omitempty,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []attribute `asn1:"optional,omitempty,tag:1"`
}

type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type usageIdentifierType struct {
	Identifier asn1.ObjectIdentifier
}

type ctlInfoType struct {
	Version         int `asn1:"optional,default:0"`
	Usage           usageIdentifierType
	ListIdentifier  asn1.BitString `asn1:"optional"`
	SequenceNumber  *big.Int       `asn1:"optional"`
	ThisUpdate      time.Time
	NextUpdate      time.Time `asn1:"optional"`
	Algorithm       pkix.AlgorithmIdentifier
	TrustedSubjects []trustedSubjectType `asn1:"optional"`
	Extensions      asn1.RawValue        `asn1:"optional,explicit"`
}

type trustedSubjectType struct {
	SubjectIdentifier []byte
	SubjectAttributes []attributeType `asn1:"set"`
}

type attributeType struct {
	Identifier asn1.ObjectIdentifier
	Values     [][]byte `asn1:"set"`
}

// TrustedSubject describes a single trusted subject
type TrustedSubject struct {
	FriendlyName              string
	SHA256Fingerprint         string
	SHA1Fingerprint           string
	MicrosoftExtendedKeyUsage int
}

// Microsoft extended key usage designators
const (
	KeyUsageClientAuthentication   = iota << 1 // 1.3.6.1.5.5.7.3.2
	KeyUsageCodeSigning                        // 1.3.6.1.5.5.7.3.3
	KeyUsageDocumentSigning                    // 1.3.6.1.4.1.311.10.3.12
	KeyUsageEncryptingFileSystem               // 1.3.6.1.4.1.311.10.3.4
	KeyUsageIPSecEndSystem                     // 1.3.6.1.5.5.7.3.5
	KeyUsageIPSecIKEIntermediate               // 1.3.6.1.5.5.8.2.2
	KeyUsageIPSecTunnelTermination             // 1.3.6.1.5.5.7.3.6
	KeyUsageIPSecUser                          // 1.3.6.1.5.5.7.3.7
	KeyUsageOCSPSigning                        // 1.3.6.1.5.5.7.3.9
	KeyUsageSecureEmail                        // 1.3.6.1.5.5.7.3.4
	KeyUsageServerAuthentication               // 1.3.6.1.5.5.7.3.1
	KeyUsageTimeStamping                       // 1.3.6.1.5.5.7.3.8
)

var kuMap = map[string]int{
	"1.3.6.1.5.5.7.3.2":       KeyUsageClientAuthentication,
	"1.3.6.1.5.5.7.3.3":       KeyUsageCodeSigning,
	"1.3.6.1.4.1.311.10.3.12": KeyUsageDocumentSigning,
	"1.3.6.1.4.1.311.10.3.4":  KeyUsageEncryptingFileSystem,
	"1.3.6.1.5.5.7.3.5":       KeyUsageIPSecEndSystem,
	"1.3.6.1.5.5.8.2.2":       KeyUsageIPSecIKEIntermediate,
	"1.3.6.1.5.5.7.3.6":       KeyUsageIPSecTunnelTermination,
	"1.3.6.1.5.5.7.3.7":       KeyUsageIPSecUser,
	"1.3.6.1.5.5.7.3.9":       KeyUsageOCSPSigning,
	"1.3.6.1.5.5.7.3.4":       KeyUsageSecureEmail,
	"1.3.6.1.5.5.7.3.1":       KeyUsageServerAuthentication,
	"1.3.6.1.5.5.7.3.8":       KeyUsageTimeStamping,
}
