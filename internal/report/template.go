package report

import (
	"html/template"
	"strings"
)

const htmlTemplate = `
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<style>
  body { font-family: 'Helvetica Neue', Arial, sans-serif; color: #1a1a2e; margin: 0; padding: 40px; }
  .header { border-bottom: 3px solid #0f3460; padding-bottom: 20px; margin-bottom: 30px; }
  .header h1 { color: #0f3460; margin: 0; font-size: 28px; }
  .header .meta { color: #666; font-size: 13px; margin-top: 8px; }
  .summary { display: flex; gap: 16px; margin-bottom: 30px; }
  .summary-box { flex: 1; padding: 16px; border-radius: 8px; text-align: center; color: #fff; }
  .critical { background: #b91c1c; }
  .high { background: #ea580c; }
  .medium { background: #ca8a04; }
  .low { background: #4b5563; }
  .info { background: #6b7280; }
  .summary-box .count { font-size: 28px; font-weight: bold; display: block; }
  .section-title { margin-top: 40px; margin-bottom: 20px; color: #0f3460; font-size: 20px; border-bottom: 2px solid #0f3460; padding-bottom: 10px; }
  .recon-table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
  .recon-table th { background: #f0f0f0; padding: 10px; text-align: left; border: 1px solid #ddd; font-weight: bold; }
  .recon-table td { padding: 10px; border: 1px solid #ddd; }
  .recon-table tr:nth-child(even) { background: #fafafa; }
  .service { color: #0f3460; font-weight: bold; }
  .banner { font-family: monospace; font-size: 12px; color: #666; word-break: break-all; }
  .finding { border-left: 4px solid #ccc; padding: 14px 18px; margin-bottom: 12px; background: #f9fafb; border-radius: 0 6px 6px 0; }
  .finding.critical { border-color: #b91c1c; }
  .finding.high { border-color: #ea580c; }
  .finding.medium { border-color: #ca8a04; }
  .finding.low { border-color: #4b5563; }
  .finding.info { border-color: #9ca3af; }
  .finding h3 { margin: 0 0 6px 0; font-size: 15px; }
  .finding .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #fff; margin-right: 8px; }
  .finding .target { color: #444; font-size: 13px; font-family: monospace; }
  .finding .impact { color: #333; font-size: 13px; margin-top: 8px; padding: 8px 10px; background: #fff7ed; border-left: 3px solid #ea580c; border-radius: 0 4px 4px 0; }
  .finding .impact strong { color: #9a3412; }
  .finding .evidence { background: #eee; padding: 8px; margin-top: 8px; font-family: monospace; font-size: 12px; border-radius: 4px; white-space: pre-wrap; }
  .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; font-size: 13px; }
  .footer strong { color: #0f3460; }
</style>
</head>
<body>
  <div class="header">
    <h1>Reporte de Auditoría de Seguridad</h1>
    <div class="meta">
      Target: {{.Target}} &nbsp;|&nbsp; Fecha: {{.Date}} &nbsp;|&nbsp; Scan ID: {{.ScanID}}
    </div>
  </div>

  <div class="summary">
    {{range .SummaryBoxes}}
    <div class="summary-box {{.Severity}}">
      <span class="count">{{.Count}}</span>
      {{.Label}}
    </div>
    {{end}}
  </div>

  {{if .HasReconnaissance}}
  <h2 class="section-title">Reconocimiento de Red (Network Reconnaissance)</h2>
  <table class="recon-table">
    <thead>
      <tr>
        <th>Puerto</th>
        <th>Servicio</th>
        <th>Banner / Versión</th>
      </tr>
    </thead>
    <tbody>
      {{range .Reconnaissance}}
      <tr>
        <td>{{.Port}}</td>
        <td class="service">{{.Service}}</td>
        <td class="banner">{{.Banner}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{end}}

  <h2 class="section-title">Hallazgos de Seguridad (Vulnerabilities & Misconfigurations)</h2>
  {{range .Findings}}
  <div class="finding {{.Severity}}">
    <span class="badge {{.Severity}}">{{.SeverityLabel}}</span>
    <h3>{{.RuleName}}</h3>
    <div class="target">{{.Target}}</div>
    {{if .Impact}}<div class="impact"><strong>Riesgo:</strong> {{.Impact}}</div>{{end}}
    {{if .Evidence}}<div class="evidence">{{.Evidence}}</div>{{end}}
  </div>
  {{end}}

  <div class="footer">
    Auditoría generada con <strong>Auditek</strong><br>
    {{.BrandContact}}
  </div>
</body>
</html>
`

func Render(data ReportData) (string, error) {
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		return "", err
	}
	return sb.String(), nil
}
