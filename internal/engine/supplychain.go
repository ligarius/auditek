package engine

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"

	"auditek/internal/cvedb"
	"auditek/internal/osv"
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
func AnalyzeDependencyManifest(body, target, source, ecosystem string, useOSV, skipVersionMatch bool) []Finding {
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
	resolved := map[string]string{} // paquete -> versión aproximada del constraint

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
		resolved[name] = approxVersion
	}

	// Si un lockfile del mismo ecosistema ya aportó versiones EXACTAS, no
	// duplicamos el cruce aproximado (los loose-version de arriba sí quedan).
	if !skipVersionMatch {
		findings = append(findings, crossReferenceVersions(resolved, target, source, ecosystem, useOSV, false)...)
	}

	return findings
}

// crossReferenceVersions cruza un mapa paquete->versión contra la cvedb local y,
// si useOSV, contra OSV. `exact` distingue lockfiles (versión instalada) de
// manifiestos (versión aproximada del constraint) solo en el texto del hallazgo.
func crossReferenceVersions(deps map[string]string, target, source, ecosystem string, useOSV, exact bool) []Finding {
	if len(deps) == 0 {
		return nil
	}

	verNote, evNote, osvNote, osvEv := ", aproximado desde el manifiesto", " (versión exacta instalada puede variar)", "aproximado desde el manifiesto", "; versión exacta instalada puede variar"
	if exact {
		verNote, evNote, osvNote, osvEv = ", versión instalada (lockfile)", "", "versión instalada (lockfile)", ""
	}

	var findings []Finding
	seenCVE := map[string]bool{}

	for _, name := range sortedKeys(deps) {
		version := deps[name]
		for _, cve := range cvedb.Lookup(strings.ToLower(name), version) {
			seenCVE[strings.ToLower(name)+"|"+cve.CVE] = true
			findings = append(findings, Finding{
				RuleID:    cve.CVE,
				RuleName:  cve.Description + " (" + name + " " + version + verNote + ")",
				Target:    target,
				Severity:  cve.Severity,
				CVE:       []string{cve.CVE},
				Impact:    cve.Impact,
				Timestamp: time.Now(),
				Evidence:  source + ": " + name + " " + version + evNote,
			})
		}
	}

	if useOSV && ecosystem != "" {
		vulns, err := osv.ScanDependencies(ecosystem, deps, 25*time.Second)
		if err == nil {
			for _, v := range vulns {
				if seenCVE[strings.ToLower(v.Package)+"|"+v.CVE] {
					continue // ya reportado por la cvedb local
				}
				summary := v.Summary
				if summary == "" {
					summary = "Vulnerabilidad conocida en " + v.Package + " " + v.Version + " (ver " + v.ID + ")."
				}
				findings = append(findings, Finding{
					RuleID:    v.ID,
					RuleName:  v.ID + ": " + v.Package + " " + v.Version + " (OSV, " + osvNote + ")",
					Target:    target,
					Severity:  v.Severity,
					CVE:       []string{v.CVE},
					Impact:    summary,
					Timestamp: time.Now(),
					Evidence:  source + ": " + v.Package + " " + v.Version + " — OSV/osv.dev (" + ecosystem + ")" + osvEv,
				})
			}
		}
	}

	return findings
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
