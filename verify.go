package authrootstl

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	_ "embed"
)

//go:embed ca.crt
var caCertData []byte

// Verify will verify the PKCS#7 signature and return the certificate chain or an error.
// The leaf (signing) certificate will be index 0.
func (d signedData) Verify() ([]x509.Certificate, error) {
	var val asn1.RawValue
	if _, err := asn1.Unmarshal(d.CertBytes.Raw, &val); err != nil {
		return nil, fmt.Errorf("asn1: %s", err)
	}

	certificates, err := x509.ParseCertificates(val.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509: %s", err)
	}

	var compound asn1.RawValue
	asn1.Unmarshal(d.ContentInfo.Content.Bytes, &compound)
	if len(d.SignerInfos) != 1 {
		return nil, fmt.Errorf("pkcs7: unexpected number of signatures. expected 1 got %d", len(d.SignerInfos))
	}

	return verifySignature(compound.Bytes, certificates, d.SignerInfos[0])
}

// This is based on https://github.com/mozilla-services/pkcs7/blob/master/verify.go
func verifySignature(signedData []byte, certificates []*x509.Certificate, signer signerInfo) ([]x509.Certificate, error) {
	ee := getCertFromCertsByIssuerAndSerial(certificates, signer.IssuerAndSerialNumber)
	if ee == nil {
		return nil, errors.New("pkcs7: No certificate for signer")
	}

	if len(signer.AuthenticatedAttributes) == 0 {
		return nil, fmt.Errorf("pkcs7: no authenticated attributed")
	}

	var digest []byte
	if err := unmarshalAttribute(signer.AuthenticatedAttributes, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}, &digest); err != nil {
		return nil, err
	}
	computed := sha256.Sum256(signedData)
	if subtle.ConstantTimeCompare(digest, computed[:]) != 1 {
		return nil, fmt.Errorf("pkcs7: signature does not match")
	}
	signedData, err := marshalAttributes(signer.AuthenticatedAttributes)
	if err != nil {
		return nil, fmt.Errorf("asn1: %s", err)
	}

	truststore := x509.NewCertPool()
	caCert, err := x509.ParseCertificate(caCertData)
	if err != nil {
		panic("invalid ca certificate file")
	}
	truststore.AddCert(caCert)

	intermediates := x509.NewCertPool()
	for _, intermediate := range certificates {
		intermediates.AddCert(intermediate)
	}
	verifyOptions := x509.VerifyOptions{
		Roots:         truststore,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		// The signing certificate for certificate trust lists does sometime expire before Microsoft will
		// issue a new list update. However, by observing how Windows' certutil.exe utility behaves with expired
		// trust lists it appears that it either isn't validating the expiry date, or it's using the last update
		// attribute within the CTL itself (as opposed to a signingTime attribute). I cannot find this being documented
		// anywhere online.
		CurrentTime: ee.NotAfter.AddDate(0, 0, -1),
	}
	if _, err := ee.Verify(verifyOptions); err != nil {
		return nil, fmt.Errorf("pkcs7: failed to verify certificate chain: %v", err)
	}

	if err := ee.CheckSignature(x509.SHA256WithRSA, signedData, signer.EncryptedDigest); err != nil {
		return nil, fmt.Errorf("signature: %s", err)
	}

	chain := []x509.Certificate{*ee}
	for _, intermediate := range certificates {
		chain = append(chain, *intermediate)
	}
	chain = append(chain, *caCert)
	return chain, nil
}

func getCertFromCertsByIssuerAndSerial(certs []*x509.Certificate, ias issuerAndSerial) *x509.Certificate {
	for _, cert := range certs {
		if cert.SerialNumber.Cmp(ias.SerialNumber) == 0 && bytes.Equal(cert.RawIssuer, ias.IssuerName.FullBytes) {
			return cert
		}
	}
	return nil
}

func unmarshalAttribute(attrs []attribute, attributeType asn1.ObjectIdentifier, out interface{}) error {
	for _, attr := range attrs {
		if attr.Type.Equal(attributeType) {
			_, err := asn1.Unmarshal(attr.Value.Bytes, out)
			return err
		}
	}
	return errors.New("pkcs7: attribute type not in attributes")
}

func marshalAttributes(attrs []attribute) ([]byte, error) {
	encodedAttributes, err := asn1.Marshal(struct {
		A []attribute `asn1:"set"`
	}{A: attrs})
	if err != nil {
		return nil, err
	}

	// Remove the leading sequence octets
	var raw asn1.RawValue
	asn1.Unmarshal(encodedAttributes, &raw)
	return raw.Bytes, nil
}
