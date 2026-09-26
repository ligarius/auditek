package engine

import (
	"encoding/json"
	"strings"
)

// --- composer.lock (Packagist) ---

type composerLock struct {
	Packages    []composerPkg `json:"packages"`
	PackagesDev []composerPkg `json:"packages-dev"`
}
type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func parseComposerLock(body string) map[string]string {
	var cl composerLock
	if err := json.Unmarshal([]byte(body), &cl); err != nil {
		return nil
	}
	out := map[string]string{}
	for _, p := range cl.Packages {
		addLockDep(out, p.Name, p.Version)
	}
	for _, p := range cl.PackagesDev {
		addLockDep(out, p.Name, p.Version)
	}
	return out
}

// --- package-lock.json (npm), v1 (dependencies) y v2/v3 (packages) ---

type packageLock struct {
	Packages     map[string]plPackage `json:"packages"`
	Dependencies map[string]plDep     `json:"dependencies"`
}
type plPackage struct {
	Version string `json:"version"`
}
type plDep struct {
	Version      string           `json:"version"`
	Dependencies map[string]plDep `json:"dependencies"`
}

func parsePackageLock(body string) map[string]string {
	var pl packageLock
	if err := json.Unmarshal([]byte(body), &pl); err != nil {
		return nil
	}
	out := map[string]string{}

	// v2/v3: "packages" con claves "node_modules/<name>" (o "" para la raíz).
	for path, p := range pl.Packages {
		if name := nodeModulesName(path); name != "" {
			addLockDep(out, name, p.Version)
		}
	}

	// v1: "dependencies" recursivo.
	var walk func(deps map[string]plDep)
	walk = func(deps map[string]plDep) {
		for name, d := range deps {
			if _, seen := out[name]; !seen {
				addLockDep(out, name, d.Version)
			}
			if len(d.Dependencies) > 0 {
				walk(d.Dependencies)
			}
		}
	}
	walk(pl.Dependencies)

	return out
}

// nodeModulesName extrae el nombre de paquete de una clave de "packages" de
// package-lock v2/v3: "node_modules/foo" -> "foo",
// "node_modules/a/node_modules/@scope/b" -> "@scope/b", "" (raíz) -> "".
func nodeModulesName(path string) string {
	const marker = "node_modules/"
	idx := strings.LastIndex(path, marker)
	if idx < 0 {
		return ""
	}
	return path[idx+len(marker):]
}

// addLockDep normaliza y agrega un par nombre/versión si ambos son válidos.
func addLockDep(out map[string]string, name, version string) {
	name = strings.TrimSpace(name)
	version = normalizeLockVersion(version)
	if name == "" || version == "" {
		return
	}
	out[name] = version
}

// normalizeLockVersion limpia la versión de un lockfile: quita el prefijo "v"
// (composer usa "v1.2.3") y el metadato de build ("+abc"), que el matcher no usa.
func normalizeLockVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i > 0 {
		v = v[:i]
	}
	return v
}

// AnalyzeLockfile parsea un lockfile (composer.lock / package-lock.json), que
// trae las versiones EXACTAS instaladas, y las cruza contra la cvedb local y
// OSV — sin la salvedad de "versión aproximada" de los manifiestos.
func AnalyzeLockfile(body, target, source, ecosystem string, useOSV bool) []Finding {
	var deps map[string]string
	switch ecosystem {
	case "Packagist":
		deps = parseComposerLock(body)
	case "npm":
		deps = parsePackageLock(body)
	}
	return crossReferenceVersions(deps, target, source, ecosystem, useOSV, true)
}
