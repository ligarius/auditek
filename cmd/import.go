package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	"auditek/internal/correlate"
	"auditek/internal/findings"
	"auditek/internal/ui"
)

// ExternalFinding es el contrato de datos para integrar resultados de
// herramientas externas (ej. un scanner de pentesting desarrollado aparte)
// dentro de los reportes/correlación de Auditek. Cualquier herramienta que
// pueda emitir este JSON (un array de estos objetos) puede alimentar el
// mismo pipeline de reportes que usan los scans nativos — sin que Auditek
// necesite conocer ni ejecutar nada de esa herramienta.
//
// Campos obligatorios: rule_id, rule_name, target, severity.
// Severity debe ser uno de: info, low, medium, high, critical.
type ExternalFinding struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Target   string `json:"target"`
	Severity string `json:"severity"`
	CVE      string `json:"cve,omitempty"`
	Impact   string `json:"impact,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

var validSeverities = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true,
}

// ValidateAndConvert revisa un ExternalFinding y lo convierte a
// findings.Finding si es válido. Devuelve (finding, motivo-de-rechazo).
// Compartida entre `import` (manual) y `--exec-hook` (automático durante
// el scan) para que ambos caminos validen exactamente igual.
func (ef ExternalFinding) ValidateAndConvert(scanID string) (findings.Finding, string) {
	if ef.RuleID == "" || ef.RuleName == "" || ef.Target == "" {
		return findings.Finding{}, "faltan campos obligatorios (rule_id, rule_name, target)"
	}
	if !validSeverities[ef.Severity] {
		return findings.Finding{}, fmt.Sprintf("severity inválida %q (debe ser info|low|medium|high|critical)", ef.Severity)
	}
	return findings.Finding{
		ScanID: scanID, RuleID: ef.RuleID, RuleName: ef.RuleName,
		Target: ef.Target, Severity: ef.Severity,
		CVE: ef.CVE, Impact: ef.Impact, Evidence: ef.Evidence,
		Timestamp: time.Now(),
	}, ""
}

func runImportCmd(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	target := fs.String("target", "", "target a asociar con el scan importado (informativo)")
	source := fs.String("source", "external-tool", "nombre de la herramienta de origen, para trazabilidad")
	fs.Parse(args)

	rest := fs.Args()
	if len(rest) < 1 {
		return fmt.Errorf("uso: auditek import <archivo.json> [--target <target>] [--source <nombre>]")
	}
	path := rest[0]

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("error leyendo %s: %w", path, err)
	}

	var external []ExternalFinding
	if err := json.Unmarshal(data, &external); err != nil {
		return fmt.Errorf("JSON inválido (se espera un array de hallazgos): %w", err)
	}
	if len(external) == 0 {
		return fmt.Errorf("el archivo no contiene hallazgos")
	}

	store, err := findings.Open()
	if err != nil {
		return err
	}
	defer store.Close()

	scanID := findings.NewScanID()
	if err := store.SaveScan(findings.Scan{
		ID: scanID, Type: "import:" + *source, Target: *target,
		StartedAt: time.Now(), Stealth: false,
	}); err != nil {
		return err
	}

	var toSave []findings.Finding
	skipped := 0
	for i, ef := range external {
		f, reason := ef.ValidateAndConvert(scanID)
		if reason != "" {
			ui.Warn("hallazgo #%d omitido: %s", i, reason)
			skipped++
			continue
		}
		toSave = append(toSave, f)
	}

	// Los hallazgos importados pasan por la MISMA correlación que los nativos
	// — si un hallazgo externo (ej. una explotación confirmada) coincide con
	// un patrón conocido junto a otros hallazgos del mismo scan, se arma la
	// narrativa igual que si todo viniera de Auditek.
	toSave = append(toSave, correlate.Correlate(scanID, toSave)...)

	if err := store.SaveFindings(scanID, toSave); err != nil {
		return err
	}

	ui.OK("Importados %d hallazgo(s) (%d omitidos) como %s", len(toSave), skipped, scanID)
	ui.Info("Genera el reporte con: auditek report %s", scanID)
	return nil
}

// runExecHook ejecuta un programa externo (ruta dada explícitamente por el
// usuario vía --exec-hook, nunca automático ni descargado) pasándole el
// target como argumento, y espera que imprima en stdout un array JSON de
// ExternalFinding (el mismo contrato que `auditek import`). Auditek no
// contiene, no conoce, y no valida QUÉ hace ese programa — solo sabe
// invocarlo y leer su salida. Si el hook falla o devuelve JSON inválido,
// se avisa y el scan continúa con los hallazgos nativos únicamente; un
// hook roto nunca debe tumbar el scan completo.
func runExecHook(hookPath, target, scanID string) []findings.Finding {
	ui.Detail(2, "comando del hook: %s %s", hookPath, target)

	ctx, cancel := execHookContext()
	defer cancel()

	cmd := exec.CommandContext(ctx, hookPath, target)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		ui.Warn("hook externo falló (%v) — continuando solo con hallazgos nativos. stderr: %s", err, stderr.String())
		return nil
	}

	var external []ExternalFinding
	if err := json.Unmarshal(stdout.Bytes(), &external); err != nil {
		ui.Warn("hook externo devolvió JSON inválido — continuando solo con hallazgos nativos: %v", err)
		return nil
	}

	var out []findings.Finding
	for i, ef := range external {
		f, reason := ef.ValidateAndConvert(scanID)
		if reason != "" {
			ui.Warn("hallazgo #%d del hook omitido: %s", i, reason)
			continue
		}
		out = append(out, f)
	}

	fmt.Printf("Hook externo aportó %d hallazgo(s)\n", len(out))
	return out
}

func execHookContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Minute)
}
