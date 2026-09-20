package report

import (
	"time"

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
	Target       string
	Date         string
	ScanID       string
	BrandContact string
	SummaryBoxes []SummaryBox
	Findings     []FindingView
}

var severityLabels = map[string]string{
	"critical": "CRÍTICO", "high": "ALTO", "medium": "MEDIO", "low": "BAJO", "info": "INFO",
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

	return ReportData{
		Target:       target,
		Date:         time.Now().Format("02-01-2006 15:04"),
		ScanID:       scanID,
		BrandContact: brandContact,
		SummaryBoxes: boxes,
		Findings:     views,
	}
}

func DefaultBrandContact() string {
	return "Servicios de ciberseguridad · [tu nombre] · [tu contacto]"
}
