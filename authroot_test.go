package authrootstl_test

import (
	"testing"

	"github.com/tls-inspector/authrootstl"
)

func TestParse(t *testing.T) {
	subjects, err := authrootstl.ParseFile("authroot.stl")
	if err != nil {
		t.Fatalf(err.Error())
	}

	if len(subjects) == 0 {
		t.Fatalf("No subjects")
	}
}
