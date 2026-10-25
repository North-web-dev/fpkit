package fetch

import (
	"testing"

	"github.com/North-web-dev/fpkit/data"
)

func TestCompareMatch(t *testing.T) {
	e := data.Entry{Name: "chrome", TLS: data.TLS{JA4: "t13d1516h2_8daaf6152771_d8a2da3f94cd"}}
	ref := Reflected{JA4: "t13d1516h2_8daaf6152771_d8a2da3f94cd"}
	res, err := Compare(e, ref, []string{"ja4"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Mismatch {
		t.Errorf("identical JA4 should match, got mismatch: %+v", res.Fields)
	}
}

func TestCompareMismatch(t *testing.T) {
	e := data.Entry{Name: "chrome", TLS: data.TLS{JA4: "t13d1516h2_8daaf6152771_d8a2da3f94cd"}}
	ref := Reflected{JA4: "t13d3113h2_e8f1e7e78f70_ce5650b735ce"} // curl
	res, err := Compare(e, ref, []string{"ja4"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Mismatch {
		t.Error("different JA4 should be flagged as drift")
	}
}

func TestCompareEmptyExpectedIsMismatch(t *testing.T) {
	e := data.Entry{Name: "x"} // no expected ja4h
	ref := Reflected{JA4H: "ge20nn..."}
	res, _ := Compare(e, ref, []string{"ja4h"})
	if !res.Mismatch {
		t.Error("missing expected value should not silently pass")
	}
}

func TestCompareUnknownField(t *testing.T) {
	if _, err := Compare(data.Entry{}, Reflected{}, []string{"bogus"}); err == nil {
		t.Error("expected error for unknown field")
	}
}
