package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"auditek/internal/correlate"
	"auditek/internal/findings"
	"auditek/internal/report"
	"auditek/internal/ui"
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
		ui.Warn("No se encontraron hallazgos para ese scan-id (o no existe).")
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
	ui.Title("Reporte Auditek", scanID)

	bySeverity := map[string][]findings.Finding{}
	for _, f := range results {
		bySeverity[f.Severity] = append(bySeverity[f.Severity], f)
	}

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
				fmt.Printf("       %s %s\n", ui.Gray("evidencia"), ui.Dim(f.Evidence))
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
	fmt.Printf("  %s     %d hallazgos\n", ui.Bold("Total"), len(results))
	printRiskPosture(correlate.RiskScore(results))
	fmt.Println()
	ui.Info("Auditoría generada con Auditek — servicios de ciberseguridad")

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

	ui.OK("Reporte generado: %s", ui.Bold(filename))
	return nil
}
