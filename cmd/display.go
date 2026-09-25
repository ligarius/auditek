package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"auditek/internal/findings"
	"auditek/internal/report"
)

// displayFindings muestra hallazgos en pantalla agrupados por severidad
func displayFindings(fs []findings.Finding) {
	if len(fs) == 0 {
		fmt.Println("\n✓ No se encontraron hallazgos")
		return
	}

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("HALLAZGOS ENCONTRADOS")
	fmt.Println(strings.Repeat("=", 70))

	// Agrupar por severidad
	bySeverity := make(map[string][]findings.Finding)
	severityOrder := []string{"critical", "high", "medium", "low", "info"}

	for _, f := range fs {
		bySeverity[f.Severity] = append(bySeverity[f.Severity], f)
	}

	for _, sev := range severityOrder {
		items := bySeverity[sev]
		if len(items) == 0 {
			continue
		}

		prefix := ""
		switch sev {
		case "critical":
			prefix = "🔴 CRÍTICO"
		case "high":
			prefix = "🟠 ALTO"
		case "medium":
			prefix = "🟡 MEDIO"
		case "low":
			prefix = "🔵 BAJO"
		case "info":
			prefix = "⚪ INFO"
		}

		fmt.Printf("\n%s (%d encontrados)\n", prefix, len(items))
		fmt.Println(strings.Repeat("-", 70))

		for i, f := range items {
			fmt.Printf("%d. %s\n", i+1, f.RuleName)
			fmt.Printf("   Target: %s\n", f.Target)
			if f.CVE != "" {
				fmt.Printf("   CVE: %s\n", f.CVE)
			}
			if f.Impact != "" {
				fmt.Printf("   Riesgo: %s\n", f.Impact)
			}
			if f.Evidence != "" {
				evidence := f.Evidence
				if len(evidence) > 100 {
					evidence = evidence[:100] + "..."
				}
				fmt.Printf("   Evidence: %s\n", evidence)
			}
			fmt.Println()
		}
	}

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("📊 Resumen por severidad:")
	sevLabels := map[string]string{
		"critical": "🔴 Crítico",
		"high":     "🟠 Alto",
		"medium":   "🟡 Medio",
		"low":      "🔵 Bajo",
		"info":     "⚪ Info",
	}
	for _, sev := range severityOrder {
		if n := len(bySeverity[sev]); n > 0 {
			fmt.Printf("   %s: %d\n", sevLabels[sev], n)
		}
	}
	fmt.Printf("Total: %d hallazgos encontrados\n", len(fs))
}

// promptExportHTML pregunta si exportar a HTML
func promptExportHTML(scanID string) bool {
	fmt.Print("\n¿Exportar reporte a HTML? (s/n): ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "s" || input == "si" || input == "sí" || input == "y" || input == "yes"
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

	fmt.Printf("\n📊 Reporte HTML generado: %s\n", filename)
	fmt.Println("   Abre el archivo en tu navegador para ver el reporte completo.")
	return nil
}
