package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"auditek/internal/correlate"
	"auditek/internal/findings"
	"auditek/internal/report"
	"auditek/internal/ui"
)

// riskLevelSeverity mapea el nivel de la postura de riesgo a la severidad cuyo
// color reutiliza, para pintar el score con la misma paleta que los hallazgos.
var riskLevelSeverity = map[string]string{
	"Crítico": "critical",
	"Alto":    "high",
	"Medio":   "medium",
	"Bajo":    "low",
	"Ninguno": "info",
}

// printRiskPosture imprime la postura de riesgo agregada del objetivo.
func printRiskPosture(sc correlate.Score) {
	sev := riskLevelSeverity[sc.Level]
	label := ui.ColorBySeverity(sev, fmt.Sprintf("%s (%d/100)", sc.Level, sc.Value))
	line := "  " + ui.Bold("Riesgo") + "    " + label
	if sc.Chains > 0 {
		line += ui.Gray(fmt.Sprintf("  · %d cadena(s) de ataque correlacionada(s)", sc.Chains))
	}
	fmt.Println(line)
}

// severityDisplayOrder es el orden de impresión de hallazgos, de más a menos grave.
var severityDisplayOrder = []string{"critical", "high", "medium", "low", "info"}

// displayFindings muestra hallazgos agrupados por severidad, de más a menos
// grave. Con -v (o más) muestra la evidencia completa; sin él la trunca.
func displayFindings(fs []findings.Finding) {
	if len(fs) == 0 {
		fmt.Println()
		ui.OK("No se encontraron hallazgos")
		return
	}

	bySeverity := make(map[string][]findings.Finding)
	for _, f := range fs {
		bySeverity[f.Severity] = append(bySeverity[f.Severity], f)
	}

	fmt.Println()
	fmt.Println("  " + ui.Bold("HALLAZGOS"))
	fmt.Println("  " + ui.Gray(ui.Rule(66)))

	for _, sev := range severityDisplayOrder {
		for _, f := range bySeverity[sev] {
			fmt.Printf("  %s %s  %s\n", ui.SeverityDot(sev), ui.SeverityBadge(sev), ui.Bold(f.RuleName))
			fmt.Printf("       %s %s\n", ui.Gray("target"), f.Target)
			if f.CVE != "" {
				fmt.Printf("       %s    %s\n", ui.Gray("cve"), ui.Yellow(f.CVE))
			}
			if f.Impact != "" {
				fmt.Printf("       %s %s\n", ui.Gray("riesgo"), f.Impact)
			}
			if f.Evidence != "" {
				evidence := f.Evidence
				if !ui.V(1) && len(evidence) > 100 {
					evidence = evidence[:100] + "…"
				}
				fmt.Printf("       %s %s\n", ui.Gray("evidencia"), ui.Dim(evidence))
			}
			if ui.V(1) && !f.Timestamp.IsZero() {
				fmt.Printf("       %s %s\n", ui.Gray("cuándo"), ui.Dim(f.Timestamp.Format("2006-01-02 15:04:05")))
			}
			fmt.Println()
		}
	}

	fmt.Println("  " + ui.Gray(ui.Rule(66)))
	seg := make([]string, 0, len(severityDisplayOrder))
	for _, sev := range severityDisplayOrder {
		seg = append(seg, ui.SeverityCount(sev, len(bySeverity[sev])))
	}
	fmt.Printf("  %s   %s\n", ui.Bold("Resumen"), strings.Join(seg, ui.Gray(" · ")))
	fmt.Printf("  %s     %s\n", ui.Bold("Total"), fmt.Sprintf("%d hallazgos", len(fs)))
	printRiskPosture(correlate.RiskScore(fs))
}

// promptExportHTML pregunta si exportar a HTML
func promptExportHTML(scanID string) bool {
	fmt.Print("\n¿Exportar reporte a HTML? (s/n): ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "s" || input == "si" || input == "sí" || input == "y" || input == "yes"
}

// maybeExport decide si exportar el reporte según --export:
//   - ""         -> pregunta interactivamente (comportamiento histórico)
//   - "html"     -> exporta sin preguntar
//   - "none"/"no"-> no exporta ni pregunta (útil para automatización)
//   - otro       -> avisa y no exporta
func maybeExport(exportFmt, scanID string, fs []findings.Finding, target string) {
	switch strings.ToLower(strings.TrimSpace(exportFmt)) {
	case "":
		if !promptExportHTML(scanID) {
			return
		}
	case "none", "no":
		return
	case "html":
		// exporta abajo
	case "pdf":
		ui.Warn("Export a PDF aún no soportado (el reporte se genera en HTML). Usa --export html y conviértelo, o abre el HTML e imprime a PDF.")
		return
	default:
		ui.Warn("Formato de --export no reconocido: %q (usa html | none)", exportFmt)
		return
	}
	if err := exportHTMLReport(scanID, fs, target); err != nil {
		ui.Fail("Error exportando HTML: %v", err)
	}
}

// exportHTMLReport genera el reporte HTML y lo guarda en archivo
func exportHTMLReport(scanID string, fs []findings.Finding, target string) error {
	// Usar target del primer finding si no se proporciona
	if target == "" && len(fs) > 0 {
		target = fs[0].Target
	}

	// Construir datos del reporte
	data := report.BuildReportData(scanID, target, fs, report.DefaultBrandContact())

	// Renderizar HTML
	html, err := report.Render(data)
	if err != nil {
		return fmt.Errorf("error renderizando reporte: %w", err)
	}

	// Guardar archivo
	filename := fmt.Sprintf("auditek-report-%s.html", scanID)
	if err := os.WriteFile(filename, []byte(html), 0644); err != nil {
		return fmt.Errorf("error guardando reporte: %w", err)
	}

	fmt.Println()
	ui.OK("Reporte HTML generado: %s", ui.Bold(filename))
	ui.Info("Ábrelo en tu navegador para ver el reporte completo.")
	return nil
}
