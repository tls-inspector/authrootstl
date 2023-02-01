// Package authrootstl provides a interface to parse & validate Microsoft Window's authroot.stl file
package authrootstl

import (
	"encoding/asn1"
	"fmt"
	"io"
	"os"
)

// ParseFile will parse and validate the authroot.stl file at the given path
func ParseFile(filePath string) ([]TrustedSubject, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	return ParseData(data)
}

// ParseData will parse and validate the given data for an authroot.stl file
func ParseData(data []byte) ([]TrustedSubject, error) {
	var info contentInfo
	rest, err := asn1.Unmarshal(data, &info)
	if len(rest) > 0 {
		return nil, fmt.Errorf("asn1: unexpected trailing data")
	}
	if err != nil {
		return nil, err
	}

	var sd signedData
	rest, err = asn1.Unmarshal(info.Content.Bytes, &sd)
	if len(rest) > 0 {
		return nil, fmt.Errorf("asn1: unexpected trailing data")
	}
	if err != nil {
		return nil, err
	}

	if sd.ContentInfo.ContentType.String() != "1.3.6.1.4.1.311.10.1" {
		return nil, fmt.Errorf("pkcs7: unexpected content type")
	}

	certificates, err := sd.Certificates()
	if err != nil {
		return nil, err
	}
	var compound asn1.RawValue
	asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &compound)
	for _, signer := range sd.SignerInfos {
		if err := verifySignature(compound.Bytes, certificates, signer); err != nil {
			return nil, fmt.Errorf("verify: %s", err.Error())
		}
	}

	var ctlInfo ctlInfoType
	rest, err = asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &ctlInfo)
	if len(rest) > 0 {
		return nil, fmt.Errorf("asn1: unexpected trailing data")
	}
	if err != nil {
		return nil, err
	}

	subjects := []TrustedSubject{}
	for _, subject := range ctlInfo.TrustedSubjects {
		var FriendlyName string
		var SHA256Fingerprint string
		var SHA1Fingerprint = fmt.Sprintf("%X", subject.SubjectIdentifier)
		var MicrosoftExtendedKeyUsage int

		for _, attribute := range subject.SubjectAttributes {
			switch attribute.Identifier.String() {
			case "1.3.6.1.4.1.311.10.11.11":
				FriendlyName = string(attribute.Values[0])
			case "1.3.6.1.4.1.311.10.11.98":
				SHA256Fingerprint = fmt.Sprintf("%X", attribute.Values[0])
			case "1.3.6.1.4.1.311.10.11.9":
				var v []asn1.ObjectIdentifier
				if _, err := asn1.Unmarshal(attribute.Values[0], &v); err != nil {
					return nil, fmt.Errorf("stl: invalid attribute value for key usage attribute: %s", err.Error())
				}

				for _, oid := range v {
					ku, known := kuMap[oid.String()]
					if !known {
						continue
					}
					MicrosoftExtendedKeyUsage |= ku
				}
			}
		}

		subjects = append(subjects, TrustedSubject{
			FriendlyName:              FriendlyName,
			SHA256Fingerprint:         SHA256Fingerprint,
			SHA1Fingerprint:           SHA1Fingerprint,
			MicrosoftExtendedKeyUsage: MicrosoftExtendedKeyUsage,
		})
	}

	return subjects, nil
}

// ParseFile will parse and validate the authroot.stl data from the given reader
func ParseReader(r io.Reader) ([]TrustedSubject, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return ParseData(data)
}
