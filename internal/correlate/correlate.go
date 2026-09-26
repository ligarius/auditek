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
	ID   string
	Name string
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
	{
		ID:   "path-redis-write-confirmed",
		Name: "Redis: impacto de escritura confirmado (herramienta externa)",
		RequireAnyGroups: [][]string{
			{"redis-write-demonstrated"},
		},
		Severity: "critical",
		Narrative: "Se aportó evidencia de que Redis permite escritura real o acceso demostrable (%s). " +
			"Esto eleva el hallazgo de exposición pasiva a impacto demostrado en el objetivo evaluado. " +
			"Priorizar contención (requirepass, bind, comandos peligrosos deshabilitados) de inmediato.",
	},
	{
		ID:   "path-redis-detected-and-write-confirmed",
		Name: "Redis sin auth detectado + escritura/acceso demostrado",
		RequireAnyGroups: [][]string{
			{"redis-unauthenticated"},
			{"redis-write-demonstrated"},
		},
		Severity: "critical",
		Narrative: "Auditek detectó Redis sin autenticación (%s) y además se confirmó acceso/escritura (%s). " +
			"La cadena exposición → manipulación del servidor queda demostrada en este engagement, " +
			"no solo como hipótesis.",
	},
	{
		ID:   "path-secrets-validated",
		Name: "Secretos expuestos: uso o validez confirmada (herramienta externa)",
		RequireAnyGroups: [][]string{
			{"secrets-validated"},
		},
		Severity: "critical",
		Narrative: "Se aportó evidencia de que secretos encontrados son utilizables o de alto valor (%s). " +
			"Rotar credenciales, retirar archivos expuestos y revisar historial de despliegues.",
	},
	{
		ID:   "path-secrets-detected-and-validated",
		Name: "Secretos detectados + validación confirmada",
		RequireAnyGroups: [][]string{
			{"exposed-env-file", "exposed-wp-config-bak", "exposed-git-config"},
			{"secrets-validated"},
		},
		Severity: "critical",
		Narrative: "Se encontraron archivos/secretos expuestos (%s) y la validación externa confirmó impacto (%s). " +
			"No es solo exposición teórica: hay evidencia de que el material es accionable.",
	},
	{
		ID:   "path-ssh-key-to-lateral",
		Name: "Escalada posible: clave SSH privada expuesta -> acceso directo -> pivote",
		RequireAnyGroups: [][]string{
			{"exposed-ssh-key"},
			{"lateral-movement-surface"},
		},
		Severity: "critical",
		Narrative: "Se encontró una clave SSH privada expuesta (%s) Y además superficie de gestión remota " +
			"en la misma red (%s). Una clave privada filtrada puede dar acceso autenticado directo — sin " +
			"adivinar contraseñas — y desde ahí saltar a otros hosts que confíen en esa clave.",
	},
	{
		ID:   "path-datastore-exposed-internal",
		Name: "Escalada posible: datastore sin auth + superficie de movimiento lateral",
		RequireAnyGroups: [][]string{
			{"memcached-exposed", "exposed-elasticsearch"},
			{"lateral-movement-surface"},
		},
		Severity: "high",
		Narrative: "Un almacén de datos accesible sin autenticación (%s) coexiste con superficie de gestión " +
			"remota en la misma red (%s). Un atacante podría leer/alterar datos sensibles y usar ese punto " +
			"de apoyo para moverse lateralmente hacia otros sistemas internos.",
	},
	{
		ID:   "path-git-source-disclosure",
		Name: "Exposición de código fuente vía .git",
		RequireAnyGroups: [][]string{
			{"exposed-git-config"},
		},
		Severity: "high",
		Narrative: "El directorio .git está accesible públicamente (%s). Permite reconstruir el código fuente " +
			"completo del sitio y revisar su historial en busca de credenciales, claves y lógica interna — " +
			"un punto de partida frecuente para ataques dirigidos.",
	},
	{
		ID:   "path-cicd-supplychain",
		Name: "Exposición de pipeline CI/CD (riesgo de supply chain)",
		RequireAnyGroups: [][]string{
			{"exposed-cicd-config"},
		},
		Severity: "high",
		Narrative: "Hay configuración de CI/CD expuesta (%s). Revela la topología del pipeline de despliegue " +
			"y, a veces, secretos mal manejados — información que facilita comprometer el proceso de build " +
			"y, con ello, la cadena de suministro del software.",
	},
	{
		ID:   "path-subdomain-takeover",
		Name: "Posible toma de control de subdominio (subdomain takeover)",
		RequireAnyGroups: [][]string{
			{"subdomain-takeover-hint"},
		},
		Severity: "high",
		Narrative: "Un subdominio apunta a un servicio de terceros que parece no reclamado (%s). Si un atacante " +
			"reclama ese recurso, puede servir contenido bajo tu dominio — phishing con tu marca, robo de " +
			"cookies de sesión, o bypass de controles que confían en el subdominio.",
	},
	{
		ID:   "path-api-surface-mapped",
		Name: "Superficie de API expuesta y documentada",
		RequireAnyGroups: [][]string{
			{"exposed-api-docs"},
			{"exposed-graphql-introspection"},
		},
		Severity: "medium",
		Narrative: "La documentación de la API está accesible (%s) junto con introspección GraphQL habilitada (%s). " +
			"Juntas entregan a un atacante el mapa completo de endpoints, tipos y operaciones — reduce el trabajo " +
			"de reconocimiento y facilita encontrar operaciones sensibles mal protegidas.",
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

// Score resume la postura de riesgo agregada de un objetivo en un solo número
// 0–100 y un nivel legible, para priorizar en vez de leer una lista plana.
type Score struct {
	Value      int            // 0–100 (saturado)
	Level      string         // Crítico | Alto | Medio | Bajo | Ninguno
	BySeverity map[string]int // conteo por severidad (incluye info)
	Chains     int            // nº de caminos de ataque correlacionados (path-*)
}

// severityWeight pondera cada severidad al calcular el score. `info`
// (puertos abiertos, subdominios, etc.) no suma: es contexto, no riesgo.
var severityWeight = map[string]int{
	"critical": 40,
	"high":     20,
	"medium":   8,
	"low":      3,
	"info":     0,
}

// chainBoost es cuánto suma cada camino de ataque correlacionado, por encima de
// los hallazgos que lo componen: una cadena vale más que sus partes sueltas.
const chainBoost = 15

// RiskScore calcula la postura de riesgo agregada a partir de todos los
// hallazgos de un scan (incluidos los path-* de correlación, que ya deben estar
// presentes en fs). El valor se satura en 100. Es una heurística de priorización
// para el reporte, no un CVSS.
func RiskScore(fs []findings.Finding) Score {
	bySev := map[string]int{}
	sum := 0
	chains := 0
	for _, f := range fs {
		bySev[f.Severity]++
		if strings.HasPrefix(f.RuleID, "path-") {
			chains++
			sum += chainBoost
			continue
		}
		sum += severityWeight[f.Severity]
	}
	if sum > 100 {
		sum = 100
	}
	return Score{Value: sum, Level: riskLevel(sum), BySeverity: bySev, Chains: chains}
}

func riskLevel(v int) string {
	switch {
	case v >= 75:
		return "Crítico"
	case v >= 50:
		return "Alto"
	case v >= 25:
		return "Medio"
	case v > 0:
		return "Bajo"
	default:
		return "Ninguno"
	}
}
