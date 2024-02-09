package authrootstl

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// Subject describes a participate in the Microsoft trusted root program. Note that a Subject does not contain the
// root certificate itself, but instead provides information as to how the certificate could be used. A subject may be
// distrusted or expired.
type Subject struct {
	// A friendly name for this subject. This may differ from the subject name of the certificate.
	FriendlyName string
	// The SHA-256 fingerprint of the certificate in uppercase hex.
	SHA256Fingerprint string
	// The SHA-1 fingerprint of the certificate in uppercase hex.
	SHA1Fingerprint string
	// A MD5 hash of the certificates subject name in uppercase hex. Note that this is NOT a hash of the certificate.
	SubjectNameMD5 string
	// The key ID of the certicate in uppercase hex.
	KeyID string
	// A list of key usage OIDs accepted for this subject. These typically aren't present on the certificate themselves.
	MicrosoftExtendedKeyUsage []asn1.ObjectIdentifier
	// If this subject has been distrusted by Microsoft then this field will contain the date of when that occurred.
	DisabledDate *time.Time
	// An optional date used to restrict certificates under this subject after the given date.
	NotBefore *time.Time
	// If a value is present in NotBefore then this field may contain MSEKUs that further restrict the use of certificates under this subject.
	NotBeforeEKU []asn1.ObjectIdentifier
}

// Microsoft extended key usage designators. These are provided for your conveience
// and is not a complete list of all EKUs that might appear on the authroot
var (
	MicrosoftEKUClientAuthentication   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	MicrosoftEKUCodeSigning            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	MicrosoftEKUDocumentSigning        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 12}
	MicrosoftEKUEncryptingFileSystem   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 4}
	MicrosoftEKUEVDisabled             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 94, 1, 1}
	MicrosoftEKUIPSecEndSystem         = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	MicrosoftEKUIPSecIKEIntermediate   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 8, 2, 2}
	MicrosoftEKUIPSecTunnelTermination = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	MicrosoftEKUIPSecUser              = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	MicrosoftEKUOCSPSigning            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	MicrosoftEKUSecureEmail            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	MicrosoftEKUServerAuthentication   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	MicrosoftEKUTimeStamping           = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
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
	CertBytes                  rawCertificates       `asn1:"optional,tag:0"`
	CRLs                       []x509.RevocationList `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo          `asn1:"set"`
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
