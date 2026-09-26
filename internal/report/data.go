package report

import (
	"sort"
	"time"

	"auditek/internal/classify"
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
	Domain        string
	Impact        string
	Evidence      string
}

// PhaseGroup agrupa hallazgos por fase de la kill-chain para el reporte HTML.
type PhaseGroup struct {
	Phase    string
	Count    int
	Findings []FindingView
}

type ReportData struct {
	HasReconnaissance bool
	Target            string
	Date              string
	ScanID            string
	BrandContact      string
	SummaryBoxes      []SummaryBox
	PhaseGroups       []PhaseGroup
	// Postura de riesgo agregada (0–100 + nivel), para priorizar de un vistazo.
	RiskValue    int
	RiskLevel    string
	RiskSeverity string // severidad cuyo color reutiliza el banner
	RiskChains   int
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

var severityLabels = map[string]string{
	"critical": "CRÍTICO", "high": "ALTO", "medium": "MEDIO", "low": "BAJO", "info": "INFO",
}

// riskLevelSeverity mapea el nivel de riesgo a la severidad cuyo color reutiliza.
var riskLevelSeverity = map[string]string{
	"Crítico": "critical", "Alto": "high", "Medio": "medium", "Bajo": "low", "Ninguno": "info",
}

func BuildReportData(scanID, target string, fs []findings.Finding, brandContact string) ReportData {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	byPhase := map[string][]FindingView{}

	for _, f := range fs {
		counts[f.Severity]++
		domain, phase := classify.Classify(f.RuleID)
		byPhase[phase] = append(byPhase[phase], FindingView{
			RuleName:      f.RuleName,
			Target:        f.Target,
			Severity:      f.Severity,
			SeverityLabel: severityLabels[f.Severity],
			Domain:        domain,
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

	// Agrupa por fase (orden de impacto), severidad descendente dentro de cada una.
	var groups []PhaseGroup
	for _, phase := range classify.PhaseOrder {
		items := byPhase[phase]
		if len(items) == 0 {
			continue
		}
		sort.SliceStable(items, func(i, j int) bool {
			return severityRank[items[i].Severity] < severityRank[items[j].Severity]
		})
		groups = append(groups, PhaseGroup{Phase: phase, Count: len(items), Findings: items})
	}

	sc := correlate.RiskScore(fs)

	return ReportData{
		HasReconnaissance: false,
		Target:            target,
		Date:              time.Now().Format("02-01-2006 15:04"),
		ScanID:            scanID,
		BrandContact:      brandContact,
		SummaryBoxes:      boxes,
		PhaseGroups:       groups,
		RiskValue:         sc.Value,
		RiskLevel:         sc.Level,
		RiskSeverity:      riskLevelSeverity[sc.Level],
		RiskChains:        sc.Chains,
	}
}

func DefaultBrandContact() string {
	return "Servicios de ciberseguridad · [tu nombre] · [tu contacto]"
}
