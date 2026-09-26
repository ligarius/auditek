package engine

import (
	"bufio"
	"encoding/json"
	"regexp"
	"strings"
)

// --- yarn.lock (npm) — v1 (clásico) y berry (v2+) ---

var yarnVersionRe = regexp.MustCompile(`(?m)^\s+version:?\s+"?([0-9][^"\s]*)"?`)

// parseYarnLock recorre los bloques de yarn.lock: una cabecera a columna 0 con
// uno o más especificadores (ej. `lodash@^4.17.0, lodash@~4.17.11:`) seguida de
// una línea `version "x"` (v1) o `version: x` (berry).
func parseYarnLock(body string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)

	var currentNames []string
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			// cabecera de bloque: uno o más specifiers separados por coma, con ":" al final
			header := strings.TrimSuffix(strings.TrimSpace(line), ":")
			currentNames = currentNames[:0]
			for _, spec := range strings.Split(header, ",") {
				if n := yarnPkgName(spec); n != "" {
					currentNames = append(currentNames, n)
				}
			}
			continue
		}
		if m := yarnVersionRe.FindStringSubmatch(line); m != nil {
			for _, n := range currentNames {
				addLockDep(out, n, m[1])
			}
			currentNames = currentNames[:0]
		}
	}
	return out
}

// yarnPkgName extrae el nombre de paquete de un specifier de yarn:
// `lodash@^4.17.0` -> lodash, `@scope/pkg@npm:^1` -> @scope/pkg,
// `"@scope/pkg@1.2.3"` -> @scope/pkg.
func yarnPkgName(spec string) string {
	spec = strings.TrimSpace(spec)
	spec = strings.Trim(spec, `"`)
	if spec == "" {
		return ""
	}
	// El "@" que separa nombre de rango es el ÚLTIMO; en scoped, el nombre
	// conserva su "@" inicial.
	at := strings.LastIndex(spec, "@")
	if at <= 0 { // sin rango, o "@" solo al inicio
		return spec
	}
	return spec[:at]
}

// --- requirements.txt (PyPI) — solo versiones fijadas con == ---

var pipPinnedRe = regexp.MustCompile(`^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*==\s*([0-9][A-Za-z0-9.\-]*)`)

func parseRequirementsTxt(body string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue // comentario, o flags como -r/-e/--hash
		}
		if m := pipPinnedRe.FindStringSubmatch(line); m != nil {
			addLockDep(out, m[1], m[2])
		}
	}
	return out
}

// --- Pipfile.lock (PyPI) — JSON con version "==x.y.z" ---

type pipfileLock struct {
	Default map[string]pipfileDep `json:"default"`
	Develop map[string]pipfileDep `json:"develop"`
}
type pipfileDep struct {
	Version string `json:"version"`
}

func parsePipfileLock(body string) map[string]string {
	var pl pipfileLock
	if err := json.Unmarshal([]byte(body), &pl); err != nil {
		return nil
	}
	out := map[string]string{}
	for _, group := range []map[string]pipfileDep{pl.Default, pl.Develop} {
		for name, d := range group {
			addLockDep(out, name, strings.TrimPrefix(strings.TrimSpace(d.Version), "=="))
		}
	}
	return out
}

// --- go.mod (Go) — require de una línea y en bloque ---

var goRequireLineRe = regexp.MustCompile(`^(?:require\s+)?([^\s]+/[^\s]+)\s+v([0-9][^\s]*)`)

func parseGoMod(body string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(body))
	inBlock := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "require (") {
			inBlock = true
			continue
		}
		if inBlock && line == ")" {
			inBlock = false
			continue
		}
		// quita comentario en línea (ej. "// indirect")
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if m := goRequireLineRe.FindStringSubmatch(line); m != nil {
			addLockDep(out, m[1], m[2]) // m[2] ya sin la "v"
		}
	}
	return out
}
