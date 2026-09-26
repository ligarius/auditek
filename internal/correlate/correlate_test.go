package correlate

import (
	"strings"
	"testing"

	"auditek/internal/findings"
)

func ids(fs []findings.Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.RuleID] = true
	}
	return m
}

func TestCorrelateChains(t *testing.T) {
	// Clave SSH expuesta + superficie lateral -> path-ssh-key-to-lateral.
	fs := []findings.Finding{
		{RuleID: "exposed-ssh-key", RuleName: "Clave SSH expuesta", Severity: "high"},
		{RuleID: "lateral-movement-surface", RuleName: "RDP interno", Severity: "high"},
	}
	got := ids(Correlate("s1", fs))
	if !got["path-ssh-key-to-lateral"] {
		t.Errorf("esperaba path-ssh-key-to-lateral, got %v", got)
	}

	// .git expuesto (single-trigger) -> path-git-source-disclosure.
	got = ids(Correlate("s1", []findings.Finding{
		{RuleID: "exposed-git-config", RuleName: ".git accesible", Severity: "medium"},
	}))
	if !got["path-git-source-disclosure"] {
		t.Errorf("esperaba path-git-source-disclosure, got %v", got)
	}

	// API docs + introspección GraphQL -> path-api-surface-mapped.
	got = ids(Correlate("s1", []findings.Finding{
		{RuleID: "exposed-api-docs", RuleName: "Swagger", Severity: "low"},
		{RuleID: "exposed-graphql-introspection", RuleName: "GraphQL introspection", Severity: "medium"},
	}))
	if !got["path-api-surface-mapped"] {
		t.Errorf("esperaba path-api-surface-mapped, got %v", got)
	}
}

func TestCorrelateNoFalsePositive(t *testing.T) {
	// API docs SIN introspección: la cadena de 2 grupos no debe dispararse.
	got := ids(Correlate("s1", []findings.Finding{
		{RuleID: "exposed-api-docs", RuleName: "Swagger", Severity: "low"},
	}))
	if got["path-api-surface-mapped"] {
		t.Error("path-api-surface-mapped no debería dispararse sin el segundo grupo")
	}
}

func TestCorrelateNarrativePlaceholders(t *testing.T) {
	// Ningún path-* debe quedar con un %s sin reemplazar (desalineación de grupos).
	fs := []findings.Finding{
		{RuleID: "exposed-ssh-key", RuleName: "Clave SSH expuesta", Severity: "high"},
		{RuleID: "lateral-movement-surface", RuleName: "RDP interno", Severity: "high"},
		{RuleID: "exposed-git-config", RuleName: ".git accesible", Severity: "medium"},
	}
	for _, f := range Correlate("s1", fs) {
		if strings.Contains(f.Impact, "%!") || strings.Contains(f.Impact, "%s") {
			t.Errorf("%s tiene placeholders sin resolver: %q", f.RuleID, f.Impact)
		}
	}
}

func TestRiskScore(t *testing.T) {
	// Vacío -> 0 / Ninguno.
	if sc := RiskScore(nil); sc.Value != 0 || sc.Level != "Ninguno" {
		t.Errorf("vacío: got %+v", sc)
	}

	// info no suma.
	if sc := RiskScore([]findings.Finding{{RuleID: "open-port", Severity: "info"}}); sc.Value != 0 {
		t.Errorf("info no debería sumar, got %d", sc.Value)
	}

	// Un high = 20 -> Bajo.
	sc := RiskScore([]findings.Finding{{RuleID: "x", Severity: "high"}})
	if sc.Value != 20 || sc.Level != "Bajo" {
		t.Errorf("un high: got %+v, want 20/Bajo", sc)
	}

	// Cadena de ataque suma boost y se cuenta.
	sc = RiskScore([]findings.Finding{
		{RuleID: "redis-unauthenticated", Severity: "high"},       // 20
		{RuleID: "path-redis-to-ssh-pivot", Severity: "critical"}, // +15 (no 40)
	})
	if sc.Chains != 1 {
		t.Errorf("chains = %d, want 1", sc.Chains)
	}
	if sc.Value != 35 { // 20 + 15
		t.Errorf("value = %d, want 35", sc.Value)
	}

	// Satura en 100.
	many := []findings.Finding{}
	for i := 0; i < 10; i++ {
		many = append(many, findings.Finding{RuleID: "x", Severity: "critical"})
	}
	if sc := RiskScore(many); sc.Value != 100 || sc.Level != "Crítico" {
		t.Errorf("saturación: got %+v, want 100/Crítico", sc)
	}
}
