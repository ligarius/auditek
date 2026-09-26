package report

import (
	"encoding/json"
	"testing"

	"auditek/internal/findings"
)

func TestBuildSARIF(t *testing.T) {
	fs := []findings.Finding{
		{RuleID: "CVE-2021-41773", RuleName: "Path traversal Apache 2.4.49", Severity: "critical", Target: "https://x.cl", CVE: "CVE-2021-41773", Impact: "RCE posible."},
		{RuleID: "missing-security-headers", RuleName: "Faltan headers", Severity: "medium", Target: "https://x.cl"},
		{RuleID: "CVE-2021-41773", RuleName: "Path traversal Apache 2.4.49 (dup)", Severity: "critical", Target: "https://y.cl", CVE: "CVE-2021-41773"},
	}
	data, err := BuildSARIF("scan-1", "https://x.cl", fs)
	if err != nil {
		t.Fatalf("BuildSARIF error: %v", err)
	}

	var doc sarifLog
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("SARIF no es JSON válido: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "auditek" {
		t.Errorf("driver.name = %q", run.Tool.Driver.Name)
	}
	// CVE-2021-41773 aparece 2 veces pero como UNA sola regla.
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("rules = %d, want 2 (regla única por RuleID)", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 3 {
		t.Errorf("results = %d, want 3", len(run.Results))
	}

	// Nivel mapeado: critical -> error, medium -> warning.
	if run.Results[0].Level != "error" {
		t.Errorf("critical debería ser level error, got %q", run.Results[0].Level)
	}
	if run.Results[1].Level != "warning" {
		t.Errorf("medium debería ser level warning, got %q", run.Results[1].Level)
	}
	// ruleIndex consistente para el CVE repetido.
	if run.Results[0].RuleIndex != run.Results[2].RuleIndex {
		t.Error("el mismo RuleID debería compartir ruleIndex")
	}
	if run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "https://x.cl" {
		t.Error("la location debería reflejar el target del hallazgo")
	}
	if run.Results[0].Properties["cve"] != "CVE-2021-41773" {
		t.Error("la propiedad cve debería estar presente")
	}
}

func TestSarifLevel(t *testing.T) {
	for sev, want := range map[string]string{
		"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note",
	} {
		if got := sarifLevel(sev); got != want {
			t.Errorf("sarifLevel(%q) = %q, want %q", sev, got, want)
		}
	}
}
