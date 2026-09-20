package engine

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"auditek/internal/cvedb"
)

// manifestJSON cubre los dos formatos que nos interesan (package.json y
// composer.json) con el mismo shape simplificado: un mapa de nombre de
// paquete a constraint de versión (string), sea "dependencies" (npm) o
// "require" (composer).
type manifestJSON struct {
	Dependencies map[string]string `json:"dependencies"`
	Require      map[string]string `json:"require"`
}

// looseVersionRe detecta constraints de versión "sueltas" (no fijadas a un
// valor exacto) — cualquier prefijo de rango, wildcard, o "latest".
var looseVersionRe = regexp.MustCompile(`^[\^~><=]|\*|latest`)

// versionDigitsRe extrae la parte numérica tipo x.y.z de un constraint,
// para poder cruzarla (de forma aproximada) contra la CVE db. Es una
// heurística: "^3.4.0" no garantiza que la versión INSTALADA sea 3.4.0
// exacta, pero es la mejor referencia disponible sin ejecutar el proyecto.
var versionDigitsRe = regexp.MustCompile(`\d+\.\d+(\.\d+)?`)

// AnalyzeDependencyManifest parsea un package.json/composer.json ya
// descargado y genera hallazgos: (a) CVEs conocidos si la versión declarada
// cae en un rango vulnerable de nuestra cvedb, (b) constraints de versión
// sueltas (^, ~, *, latest) que podrían instalar una versión futura sin
// que nadie lo note.
func AnalyzeDependencyManifest(body, target, source string) []Finding {
	var m manifestJSON
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return nil
	}

	deps := m.Dependencies
	if len(deps) == 0 {
		deps = m.Require
	}
	if len(deps) == 0 {
		return nil
	}

	var findings []Finding

	for name, constraint := range deps {
		if name == "php" {
			continue // no es una dependencia de terceros, es el runtime
		}

		if looseVersionRe.MatchString(constraint) {
			findings = append(findings, Finding{
				RuleID:    "loose-dependency-version",
				RuleName:  "Dependencia sin versión fijada",
				Target:    target,
				Severity:  "low",
				Impact:    "Una constraint de versión suelta (" + constraint + ") permite que se instale automáticamente una versión futura de " + name + " sin revisión — si esa versión futura resulta comprometida (ataque de supply chain) o tiene una vulnerabilidad nueva, el proyecto la hereda sin que nadie lo note explícitamente.",
				Timestamp: time.Now(),
				Evidence:  source + ": \"" + name + "\": \"" + constraint + "\"",
			})
		}

		approxVersion := versionDigitsRe.FindString(constraint)
		if approxVersion == "" {
			continue
		}
		// completar a x.y.z si vino como x.y (ej. "^7.4" de composer)
		if strings.Count(approxVersion, ".") == 1 {
			approxVersion += ".0"
		}

		for _, cve := range cvedb.Lookup(strings.ToLower(name), approxVersion) {
			findings = append(findings, Finding{
				RuleID:    cve.CVE,
				RuleName:  cve.Description + " (" + name + " " + approxVersion + ", aproximado desde \"" + constraint + "\")",
				Target:    target,
				Severity:  cve.Severity,
				CVE:       []string{cve.CVE},
				Impact:    cve.Impact,
				Timestamp: time.Now(),
				Evidence:  source + ": \"" + name + "\": \"" + constraint + "\" (versión exacta instalada puede variar)",
			})
		}
	}

	return findings
}
