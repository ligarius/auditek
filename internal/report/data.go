package report

import (
	"time"

	"auditek/internal/correlate"
	"auditek/internal/findings"
)

type SummaryBox struct {
	Severity string
	Label    string
	Count    int
}

type FindingView struct {
	RuleName      string
	Target        string
	Severity      string
	SeverityLabel string
	Impact        string
	Evidence      string
}

type ReportData struct {
	HasReconnaissance bool
	Target            string
	Date              string
	ScanID            string
	BrandContact      string
	SummaryBoxes      []SummaryBox
	Findings          []FindingView
	// Postura de riesgo agregada (0–100 + nivel), para priorizar de un vistazo.
	RiskValue    int
	RiskLevel    string
	RiskSeverity string // severidad cuyo color reutiliza el banner
	RiskChains   int
}

var severityLabels = map[string]string{
	"critical": "CRÍTICO", "high": "ALTO", "medium": "MEDIO", "low": "BAJO", "info": "INFO",
}

// riskLevelSeverity mapea el nivel de riesgo a la severidad cuyo color reutiliza.
var riskLevelSeverity = map[string]string{
	"Crítico": "critical", "Alto": "high", "Medio": "medium", "Bajo": "low", "Ninguno": "info",
}

func BuildReportData(scanID, target string, fs []findings.Finding, brandContact string) ReportData {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	var views []FindingView

	for _, f := range fs {
		counts[f.Severity]++
		views = append(views, FindingView{
			RuleName:      f.RuleName,
			Target:        f.Target,
			Severity:      f.Severity,
			SeverityLabel: severityLabels[f.Severity],
			Impact:        f.Impact,
			Evidence:      f.Evidence,
		})
	}

	var boxes []SummaryBox
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if counts[sev] > 0 {
			boxes = append(boxes, SummaryBox{Severity: sev, Label: severityLabels[sev], Count: counts[sev]})
		}
	}

	sc := correlate.RiskScore(fs)

	return ReportData{
		HasReconnaissance: false,
		Target:            target,
		Date:              time.Now().Format("02-01-2006 15:04"),
		ScanID:            scanID,
		BrandContact:      brandContact,
		SummaryBoxes:      boxes,
		Findings:          views,
		RiskValue:         sc.Value,
		RiskLevel:         sc.Level,
		RiskSeverity:      riskLevelSeverity[sc.Level],
		RiskChains:        sc.Chains,
	}
}

func DefaultBrandContact() string {
	return "Servicios de ciberseguridad · [tu nombre] · [tu contacto]"
}
