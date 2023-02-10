package authrootstl

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"os"
	"time"
	"unicode/utf16"
)

func (subject trustedSubjectType) Subject() (*Subject, error) {
	result := Subject{
		SHA1Fingerprint: fmt.Sprintf("%X", subject.SubjectIdentifier),
	}

	for _, attribute := range subject.SubjectAttributes {
		if err := processAttribute(attribute, &result); err != nil {
			return nil, err
		}
	}

	if result.FriendlyName == "" {
		return nil, fmt.Errorf("no friendly name")
	}
	if result.SHA256Fingerprint == "" {
		return nil, fmt.Errorf("no sha256 fingerprint")
	}
	if result.SHA1Fingerprint == "" {
		return nil, fmt.Errorf("no sha1 fingerprint")
	}

	return &result, nil
}

func processAttribute(attribute attributeType, subject *Subject) error {
	attrOid := attribute.Identifier.String()
	switch attrOid {
	case "1.3.6.1.4.1.311.10.11.11":
		subject.FriendlyName = decodeUTF16Bytes(attribute.Values[0])
	case "1.3.6.1.4.1.311.10.11.20":
		subject.KeyID = fmt.Sprintf("%0X", attribute.Values[0])
	case "1.3.6.1.4.1.311.10.11.29":
		subject.SubjectNameMD5 = fmt.Sprintf("%X", attribute.Values[0])
	case "1.3.6.1.4.1.311.10.11.98":
		subject.SHA256Fingerprint = fmt.Sprintf("%X", attribute.Values[0])
	case "1.3.6.1.4.1.311.10.11.9", "1.3.6.1.4.1.311.10.11.127":
		var v []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(attribute.Values[0], &v); err != nil {
			return fmt.Errorf("stl: invalid attribute value for key usage attribute: %s", err.Error())
		}
		var eku uint16
		for _, oid := range v {
			ku, known := kuMap[oid.String()]
			if !known {
				fmt.Fprintf(os.Stderr, "Unknown oid %s\n", oid.String())
				continue
			}
			eku |= ku
		}
		if attrOid == "1.3.6.1.4.1.311.10.11.9" {
			subject.MicrosoftExtendedKeyUsage |= eku
		} else {
			subject.NotBeforeEKU |= eku
		}
	case "1.3.6.1.4.1.311.10.11.104":
		if len(attribute.Values[0]) != 8 {
			return nil
		}
		t := filetimeBytesToTime(attribute.Values[0])
		subject.DisabledDate = &t
	case "1.3.6.1.4.1.311.10.11.126":
		if len(attribute.Values[0]) != 8 {
			return nil
		}
		t := filetimeBytesToTime(attribute.Values[0])
		subject.NotBefore = &t
	}
	return nil
}

func filetimeBytesToTime(ft []byte) time.Time {
	low := binary.LittleEndian.Uint32(ft[:4])
	high := binary.LittleEndian.Uint32(ft[4:])
	nsec := int64(high)<<32 + int64(low)
	nsec -= 116444736000000000
	nsec *= 100
	return time.Unix(0, nsec)
}

func decodeUTF16Bytes(b []byte) string {
	utf := make([]uint16, (len(b)+1)/2)
	for i := 0; i+1 < len(b); i += 2 {
		utf[i/2] = binary.LittleEndian.Uint16(b[i:])
	}
	r := utf16.Decode(utf)
	return string(r[0 : len(r)-1]) // strip the \NUL terminator
}
