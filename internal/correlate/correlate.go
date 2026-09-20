package correlate

import (
	"fmt"
	"strings"
	"time"

	"auditek/internal/findings"
)

// PathRule describe una combinación de hallazgos que, juntos, representan
// una escalada de riesgo mayor a la suma de sus partes. Esto es SIEMPRE
// narrativa hipotética basada en hallazgos ya confirmados — Auditek nunca
// ejecuta la cadena, solo la explica para que el cliente entienda "hasta
// dónde podría llegar" alguien que sí lo intente.
type PathRule struct {
	ID          string
	Name        string
	// RequireAny: al menos uno de estos IDs debe estar presente por grupo.
	// Cada elemento de RequireAnyGroups es un grupo — TODOS los grupos deben
	// tener al menos un match (AND entre grupos, OR dentro del grupo).
	RequireAnyGroups [][]string
	Severity         string
	Narrative        string // plantilla; %s se reemplaza con los hallazgos disparadores
}

var pathRules = []PathRule{
	{
		ID:   "path-redis-to-ssh-pivot",
		Name: "Escalada posible: Redis sin auth -> persistencia SSH -> pivote interno",
		RequireAnyGroups: [][]string{
			{"redis-unauthenticated"},
			{"lateral-movement-surface"}, // específicamente cuando el puerto es 22, pero a nivel de patrón alcanza con que exista superficie de movimiento lateral
		},
		Severity: "critical",
		Narrative: "%s permite escritura arbitraria en el filesystem del servidor (técnica conocida: " +
			"escribir una clave pública SSH en authorized_keys vía comandos CONFIG SET dir/dbfilename + " +
			"SAVE). Con eso, un atacante gana acceso SSH persistente sin necesitar credenciales. Como " +
			"además existe esta superficie en la misma red interna (%s), ese acceso inicial podría usarse para " +
			"saltar a otras máquinas — no se trata de un hallazgo aislado, sino de una cadena completa: " +
			"exposición -> persistencia -> pivote.",
	},
	{
		ID:   "path-secrets-to-admin",
		Name: "Escalada posible: secretos expuestos -> acceso administrativo",
		RequireAnyGroups: [][]string{
			{"exposed-env-file", "exposed-wp-config-bak", "exposed-git-config"},
			{"exposed-admin-panel", "default-credentials-page"},
		},
		Severity: "critical",
		Narrative: "Se encontraron credenciales o secretos expuestos (%s) Y además %s en el mismo sitio. " +
			"Un atacante no necesita adivinar contraseñas: las credenciales filtradas podrían usarse " +
			"directamente contra el panel encontrado para obtener control administrativo completo del sitio.",
	},
	{
		ID:   "path-rce-plus-lateral",
		Name: "Escalada posible: vulnerabilidad de ejecución remota + superficie de movimiento lateral",
		RequireAnyGroups: [][]string{
			{"CVE_CRITICAL_MARKER"}, // se resuelve dinámicamente: cualquier CVE con severidad critical
			{"lateral-movement-surface"},
		},
		Severity: "critical",
		Narrative: "Se detectó una vulnerabilidad crítica con potencial de ejecución remota de código (%s), " +
			"y ADEMÁS existe esta superficie en la misma red interna (%s). Esto significa que un compromiso " +
			"inicial vía esa vulnerabilidad probablemente no se quedaría en un solo servidor: el atacante " +
			"tendría un camino directo para moverse lateralmente hacia otras máquinas de la red.",
	},
}

// Correlate revisa el set de hallazgos de UN escaneo y agrega hallazgos de
// tipo "camino de ataque" cuando detecta combinaciones conocidas. Solo
// correlaciona dentro del mismo scan (no cruza hallazgos de un scan web con
// uno de red hechos por separado — ver limitación en el README).
func Correlate(scanID string, fs []findings.Finding) []findings.Finding {
	present := map[string][]findings.Finding{}
	hasCriticalCVE := false
	var criticalCVENames []string

	for _, f := range fs {
		present[f.RuleID] = append(present[f.RuleID], f)
		if f.CVE != "" && f.Severity == "critical" {
			hasCriticalCVE = true
			criticalCVENames = append(criticalCVENames, fmt.Sprintf("%s (%s)", f.RuleName, f.CVE))
		}
	}

	var extra []findings.Finding

	for _, rule := range pathRules {
		// groupLabels tiene UNA entrada por grupo (no una por match individual),
		// para que cada %s de la plantilla reciba exactamente lo que le
		// corresponde a ESE grupo, sin duplicar texto entre grupos.
		groupLabels := make([]string, 0, len(rule.RequireAnyGroups))
		allGroupsMatched := true

		for _, group := range rule.RequireAnyGroups {
			var labelsInGroup []string
			for _, id := range group {
				if id == "CVE_CRITICAL_MARKER" {
					if hasCriticalCVE {
						labelsInGroup = append(labelsInGroup, criticalCVENames...)
					}
					continue
				}
				if fs2, ok := present[id]; ok && len(fs2) > 0 {
					labelsInGroup = append(labelsInGroup, fs2[0].RuleName)
				}
			}
			if len(labelsInGroup) == 0 {
				allGroupsMatched = false
				break
			}
			groupLabels = append(groupLabels, strings.Join(labelsInGroup, ", "))
		}

		if !allGroupsMatched {
			continue
		}

		args := make([]interface{}, len(groupLabels))
		for i, l := range groupLabels {
			args[i] = l
		}
		narrative := fmt.Sprintf(rule.Narrative, args...)

		extra = append(extra, findings.Finding{
			ScanID:    scanID,
			RuleID:    rule.ID,
			RuleName:  rule.Name,
			Target:    "múltiples hallazgos correlacionados — ver Riesgo",
			Severity:  rule.Severity,
			Impact:    narrative,
			Evidence:  "Hallazgo derivado de correlación, no de una prueba directa — ver hallazgos individuales que lo componen.",
			Timestamp: time.Now(),
		})
	}

	return extra
}
