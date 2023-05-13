// Package authrootstl provides a interface to parse & validate Microsoft Windows authroot.stl file
// which contains the list of participants in the Microsoft Trusted Root Program. The trust list
// file contains so-called "subjects", which describe a certificate, their accepted use within Windows,
// and their trust status.
//
// This package is not affiliated with or endorsed by Microsoft. Windows is a registered trademark of Microsoft Corporation.
package authrootstl

import (
	"encoding/asn1"
	"fmt"
)

const oidCTL = "1.3.6.1.4.1.311.10.1"

// Parse will parse and validate the given data for an authroot.stl file
func Parse(data []byte) ([]Subject, error) {
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

	if sd.ContentInfo.ContentType.String() != oidCTL {
		return nil, fmt.Errorf("pkcs7: unexpected content type")
	}

	signingChain, err := sd.Verify()
	if err != nil {
		return nil, fmt.Errorf("verify: %s", err.Error())
	}

	var ctlInfo ctlInfoType
	rest, err = asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &ctlInfo)
	if len(rest) > 0 {
		return nil, fmt.Errorf("asn1: unexpected trailing data")
	}
	if err != nil {
		return nil, err
	}

	if ctlInfo.ThisUpdate.Before(signingChain[0].NotBefore) {
		return nil, fmt.Errorf("verify: not valid signing certificate: not before '%s' is before last update '%s'", signingChain[0].NotBefore.String(), ctlInfo.ThisUpdate.String())
	}
	if ctlInfo.ThisUpdate.After(signingChain[0].NotAfter) {
		return nil, fmt.Errorf("verify: expired signing certificate: not after '%s' is after last update '%s'", signingChain[0].NotAfter.String(), ctlInfo.ThisUpdate.String())
	}

	subjects := []Subject{}
	for i, s := range ctlInfo.TrustedSubjects {
		subject, err := s.Subject()
		if err != nil {
			return nil, fmt.Errorf("stl: invalid subject at index %d: %s", i, err.Error())
		}
		subjects = append(subjects, *subject)
	}

	return subjects, nil
}
