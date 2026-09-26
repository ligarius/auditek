package osv

import (
	"reflect"
	"testing"
)

func TestParseBatch(t *testing.T) {
	body := []byte(`{
		"results": [
			{"vulns": [{"id": "GHSA-aaaa"}, {"id": "CVE-2020-1"}]},
			{},
			{"vulns": [{"id": "GHSA-bbbb"}]}
		]
	}`)
	got, err := parseBatch(body)
	if err != nil {
		t.Fatalf("parseBatch error: %v", err)
	}
	want := [][]string{{"GHSA-aaaa", "CVE-2020-1"}, nil, {"GHSA-bbbb"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseBatch = %v, want %v", got, want)
	}
}

func TestParseBatchInvalid(t *testing.T) {
	if _, err := parseBatch([]byte("{no json")); err == nil {
		t.Error("se esperaba error con JSON inválido")
	}
}

func TestSeverityOf(t *testing.T) {
	cases := map[string]string{
		"CRITICAL": "critical",
		"HIGH":     "high",
		"MODERATE": "medium",
		"MEDIUM":   "medium",
		"LOW":      "low",
		"":         "medium", // sin dato -> neutro
		"weird":    "medium",
	}
	for in, want := range cases {
		var d vulnDetail
		d.DatabaseSpecific.Severity = in
		if got := severityOf(d); got != want {
			t.Errorf("severityOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPickCVE(t *testing.T) {
	if got := pickCVE([]string{"GHSA-x", "CVE-2021-99", "CVE-2020-1"}, "GHSA-x"); got != "CVE-2021-99" {
		t.Errorf("pickCVE debería preferir el primer CVE-*, got %q", got)
	}
	if got := pickCVE([]string{"GHSA-only"}, "GHSA-only"); got != "GHSA-only" {
		t.Errorf("pickCVE sin CVE debería devolver el id, got %q", got)
	}
}

func TestSummaryOfFallback(t *testing.T) {
	var d vulnDetail
	d.Details = "  Un   detalle   largo con   espacios  "
	if got := summaryOf(d); got != "Un detalle largo con espacios" {
		t.Errorf("summaryOf fallback = %q", got)
	}
	d.Summary = "Resumen corto"
	if got := summaryOf(d); got != "Resumen corto" {
		t.Errorf("summaryOf debería preferir Summary, got %q", got)
	}
}
