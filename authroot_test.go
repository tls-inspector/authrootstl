package authrootstl_test

import (
	"crypto/rand"
	"os"
	"path"
	"testing"
	"time"

	"github.com/tls-inspector/authrootstl"
)

func TestParse(t *testing.T) {
	data, err := os.ReadFile(path.Join("tests", "authroot.stl"))
	if err != nil {
		panic(err)
	}
	subjects, err := authrootstl.Parse(data)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if len(subjects) == 0 {
		t.Fatalf("No subjects")
	}

	for _, subject := range subjects {
		if subject.SHA1Fingerprint != "CDD4EEAE6000AC7F40C3802C171E30148030C072" {
			continue
		}

		if subject.FriendlyName != "Microsoft Root Certificate Authority" {
			t.Errorf("Unexpected FriendlyName: %v", subject.FriendlyName)
		}
		if subject.SHA256Fingerprint != "885DE64C340E3EA70658F01E1145F957FCDA27AABEEA1AB9FAA9FDB0102D4077" {
			t.Errorf("Unexpected SHA256Fingerprint: %v", subject.SHA256Fingerprint)
		}
		if subject.SHA1Fingerprint != "CDD4EEAE6000AC7F40C3802C171E30148030C072" {
			t.Errorf("Unexpected SHA1Fingerprint: %v", subject.SHA1Fingerprint)
		}
		if subject.SubjectNameMD5 != "F0C402F0404EA9ADBF25A03DDF2CA6FA" {
			t.Errorf("Unexpected SubjectNameMD5: %v", subject.SubjectNameMD5)
		}
		if subject.KeyID != "0EAC826040562797E52513FC2AE10A539559E4A4" {
			t.Errorf("Unexpected KeyID: %v", subject.KeyID)
		}
		if subject.MicrosoftExtendedKeyUsage != 0 {
			t.Errorf("Unexpected MicrosoftExtendedKeyUsage: %v", subject.MicrosoftExtendedKeyUsage)
		}
		if disableDate := subject.DisabledDate.UTC().Format(time.RFC3339); disableDate != "2021-08-01T00:00:00Z" {
			t.Errorf("Unexpected DisabledDate: %s", disableDate)
		}
		if notBefore := subject.NotBefore.UTC().Format(time.RFC3339); notBefore != "2017-04-30T00:00:00Z" {
			t.Errorf("Unexpected NotBefore: %s", notBefore)
		}
	}
}

func TestParseUnsigned(t *testing.T) {
	data, err := os.ReadFile(path.Join("tests", "authroot_unsigned.stl"))
	if err != nil {
		panic(err)
	}
	subjects, err := authrootstl.Parse(data)
	if err == nil {
		t.Fatalf("No error when expected for parsing unsigned file")
	}
	if len(subjects) > 0 {
		t.Fatalf("Subjects returned from unsigned file")
	}
}

func FuzzParse(f *testing.F) {
	var entropy = make([]byte, 256)
	rand.Read(entropy)
	f.Add(entropy)
	f.Fuzz(func(t *testing.T, a []byte) {
		subjects, err := authrootstl.Parse(a)
		if err == nil {
			t.Fatalf("No error detected when one expected for fuzzed data")
		}
		if subjects != nil {
			t.Fatalf("Subjects returned for fuzzed data")
		}
	})
}
