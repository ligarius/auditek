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

	// Total mostrado (formato: "Total     N hallazgos").
	mTotal := regexp.MustCompile(`Total\s+(\d+) hallazgos`).FindStringSubmatch(out)
	if mTotal == nil {
		t.Fatalf("no se encontró la línea Total en la salida:\n%s", out)
	}
	total, _ := strconv.Atoi(mTotal[1])
	if total != len(fs) {
		t.Errorf("Total mostrado = %d, want %d", total, len(fs))
	}

	// Suma del desglose por severidad: la línea "Resumen  N crítico · N alto · ..."
	// contiene un número por cada severidad; deben sumar el total.
	num := regexp.MustCompile(`\d+`)
	sum := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Resumen") {
			for _, m := range num.FindAllString(line, -1) {
				n, _ := strconv.Atoi(m)
				sum += n
			}
			break
		}
	}
	if sum != len(fs) {
		t.Errorf("el desglose por severidad suma %d, pero hay %d hallazgos (#7: correlación no contada)", sum, len(fs))
	}
}
