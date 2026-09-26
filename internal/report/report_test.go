package report

import (
	"strings"
	"testing"

	"auditek/internal/findings"
)

func TestRenderIncludesRiskPosture(t *testing.T) {
	fs := []findings.Finding{
		{RuleID: "redis-unauthenticated", RuleName: "Redis sin auth", Severity: "high", Target: "10.0.0.5:6379"},
		{RuleID: "path-redis-to-ssh-pivot", RuleName: "Cadena Redis→pivote", Severity: "critical", Target: "varios"},
		{RuleID: "technology-detected", RuleName: "Tecnología: nginx 1.20.0", Severity: "info", Target: "x"},
	}
	data := BuildReportData("scan-test", "10.0.0.5", fs, DefaultBrandContact())

	if data.RiskValue == 0 {
		t.Error("RiskValue no debería ser 0 con hallazgos high + cadena")
	}
	if data.RiskChains != 1 {
		t.Errorf("RiskChains = %d, want 1", data.RiskChains)
	}
	if data.RiskSeverity == "" {
		t.Error("RiskSeverity debería mapearse desde el nivel")
	}

	html, err := Render(data)
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}
	if !strings.Contains(html, "Postura de riesgo") {
		t.Error("el HTML debería incluir el banner de postura de riesgo")
	}
	if !strings.Contains(html, "/100") {
		t.Error("el HTML debería mostrar el score sobre 100")
	}
}
