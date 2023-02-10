package authrootstl

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	_ "embed"
)

//go:embed ca.crt
var caCert []byte

func (d signedData) Verify() error {
	var val asn1.RawValue
	if _, err := asn1.Unmarshal(d.CertBytes.Raw, &val); err != nil {
		return err
	}

	certificates, err := x509.ParseCertificates(val.Bytes)
	if err != nil {
		return err
	}

	var compound asn1.RawValue
	asn1.Unmarshal(d.ContentInfo.Content.Bytes, &compound)
	for _, signer := range d.SignerInfos {
		if err := verifySignature(compound.Bytes, certificates, signer); err != nil {
			return err
		}
	}
	return nil
}

// src:https://github.com/mozilla-services/pkcs7/blob/master/verify.go

func verifySignature(signedData []byte, certificates []*x509.Certificate, signer signerInfo) (err error) {
	ee := getCertFromCertsByIssuerAndSerial(certificates, signer.IssuerAndSerialNumber)
	if ee == nil {
		return errors.New("pkcs7: No certificate for signer")
	}
	signingTime := time.Now().UTC()

	if len(signer.AuthenticatedAttributes) == 0 {
		return fmt.Errorf("pkcs7: no authenticated attributed")
	}

	var digest []byte
	if err := unmarshalAttribute(signer.AuthenticatedAttributes, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}, &digest); err != nil {
		return err
	}
	computed := sha256.Sum256(signedData)
	if subtle.ConstantTimeCompare(digest, computed[:]) != 1 {
		return fmt.Errorf("pkcs7: signature does not match")
	}
	signedData, err = marshalAttributes(signer.AuthenticatedAttributes)
	if err != nil {
		return err
	}
	err = unmarshalAttribute(signer.AuthenticatedAttributes, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}, &signingTime)
	if err == nil {
		// signing time found, performing validity check
		if signingTime.After(ee.NotAfter) || signingTime.Before(ee.NotBefore) {
			return fmt.Errorf("pkcs7: signing time %q is outside of certificate validity %q to %q",
				signingTime.Format(time.RFC3339),
				ee.NotBefore.Format(time.RFC3339),
				ee.NotAfter.Format(time.RFC3339))
		}
	}

	truststore := x509.NewCertPool()
	cert, err := x509.ParseCertificate(caCert)
	if err != nil {
		panic("invalid ca certificate file")
	}
	truststore.AddCert(cert)

	intermediates := x509.NewCertPool()
	for _, intermediate := range certificates {
		intermediates.AddCert(intermediate)
	}
	verifyOptions := x509.VerifyOptions{
		Roots:         truststore,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   signingTime,
	}
	if _, err := ee.Verify(verifyOptions); err != nil {
		return fmt.Errorf("pkcs7: failed to verify certificate chain: %v", err)
	}

	return ee.CheckSignature(x509.SHA256WithRSA, signedData, signer.EncryptedDigest)
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
