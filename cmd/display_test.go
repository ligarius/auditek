package cmd

import (
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"auditek/internal/findings"
)

// captureStdout ejecuta fn capturando lo que imprime en os.Stdout.
func captureStdout(fn func()) string {
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = orig
	out, _ := io.ReadAll(r)
	return string(out)
}

// TestDisplayFindingsSummaryMatchesTotal verifica que el desglose por
// severidad suma exactamente el total mostrado y el número real de hallazgos,
// incluyendo hallazgos de correlación (severidad critical) — regresión del #7.
func TestDisplayFindingsSummaryMatchesTotal(t *testing.T) {
	fs := []findings.Finding{
		{RuleName: "a", Severity: "critical"},
		{RuleName: "b", Severity: "high"},
		{RuleName: "c", Severity: "high"},
		{RuleName: "d", Severity: "medium"},
		{RuleName: "e", Severity: "low"},
		{RuleName: "f", Severity: "info"},
		// Hallazgo de correlación (se agrega después del scan): antes del fix
		// no se contaba en el resumen por severidad.
		{RuleName: "correlación", Severity: "critical"},
	}

	out := captureStdout(func() { displayFindings(fs) })

	// Total mostrado.
	mTotal := regexp.MustCompile(`Total: (\d+) hallazgos encontrados`).FindStringSubmatch(out)
	if mTotal == nil {
		t.Fatalf("no se encontró la línea Total en la salida:\n%s", out)
	}
	total, _ := strconv.Atoi(mTotal[1])
	if total != len(fs) {
		t.Errorf("Total mostrado = %d, want %d", total, len(fs))
	}

	// Suma del desglose por severidad (líneas "   <label>: N" tras el resumen).
	sumLine := regexp.MustCompile(`:\s+(\d+)\s*$`)
	sum := 0
	inSummary := false
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Resumen por severidad") {
			inSummary = true
			continue
		}
		if strings.HasPrefix(line, "Total:") {
			break
		}
		if inSummary {
			if m := sumLine.FindStringSubmatch(line); m != nil {
				n, _ := strconv.Atoi(m[1])
				sum += n
			}
		}
	}
	if sum != len(fs) {
		t.Errorf("el desglose por severidad suma %d, pero hay %d hallazgos (#7: correlación no contada)", sum, len(fs))
	}
}
