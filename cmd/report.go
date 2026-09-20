package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"auditek/internal/findings"
	"auditek/internal/report"
)

var severityOrder = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}

func runReportCmd(args []string) error {
	args = reorderArgs(args)

	fs := flag.NewFlagSet("report", flag.ExitOnError)
	format := fs.String("format", "console", "formato: console|json|html")
	fs.Parse(args)

	rest := fs.Args()
	if len(rest) < 1 {
		return fmt.Errorf("uso: auditek report <scan-id> [flags]")
	}
	scanID := rest[0]

	store, err := findings.Open()
	if err != nil {
		return fmt.Errorf("error abriendo base de datos: %w", err)
	}
	defer store.Close()

	results, err := store.GetFindingsByScan(scanID)
	if err != nil {
		return fmt.Errorf("error leyendo hallazgos: %w", err)
	}

	if len(results) == 0 {
		fmt.Println("No se encontraron hallazgos para ese scan-id (o no existe).")
		return nil
	}

	sort.Slice(results, func(i, j int) bool {
		return severityOrder[results[i].Severity] < severityOrder[results[j].Severity]
	})

	switch *format {
	case "json":
		return printJSON(results)
	case "html":
		return generateHTMLReport(scanID, results)
	default:
		return printConsole(scanID, results)
	}
}

func printConsole(scanID string, results []findings.Finding) error {
	fmt.Printf("\n=== Reporte Auditek — %s ===\n\n", scanID)

	counts := map[string]int{}
	for _, f := range results {
		counts[f.Severity]++
	}

	fmt.Println("Resumen:")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if c := counts[sev]; c > 0 {
			fmt.Printf("  %-9s %d\n", sev+":", c)
		}
	}
	fmt.Println()

	for _, f := range results {
		fmt.Printf("[%s] %s\n", severityLabel(f.Severity), f.RuleName)
		fmt.Printf("  Target:   %s\n", f.Target)
		if f.CVE != "" {
			fmt.Printf("  CVE:      %s\n", f.CVE)
		}
		if f.Impact != "" {
			fmt.Printf("  Riesgo:   %s\n", f.Impact)
		}
		if f.Evidence != "" {
			fmt.Printf("  Evidence: %s\n", f.Evidence)
		}
		fmt.Println()
	}

	fmt.Println("---")
	fmt.Println("Auditoría generada con Auditek — servicios de ciberseguridad")

	return nil
}

func printJSON(results []findings.Finding) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func generateHTMLReport(scanID string, results []findings.Finding) error {
	target := ""
	if len(results) > 0 {
		target = results[0].Target
	}

	data := report.BuildReportData(scanID, target, results, report.DefaultBrandContact())
	html, err := report.Render(data)
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("auditek-report-%s.html", scanID)
	if err := os.WriteFile(filename, []byte(html), 0644); err != nil {
		return err
	}

	fmt.Printf("Reporte generado: %s\n", filename)
	return nil
}

func severityLabel(s string) string {
	labels := map[string]string{
		"critical": "CRÍTICO",
		"high":     "ALTO",
		"medium":   "MEDIO",
		"low":      "BAJO",
		"info":     "INFO",
	}
	if l, ok := labels[s]; ok {
		return l
	}
	return s
}
