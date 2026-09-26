package engine

import "testing"

func checkDeps(t *testing.T, got map[string]string, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseYarnLockV1(t *testing.T) {
	body := `# yarn lockfile v1

lodash@^4.17.0, lodash@~4.17.11:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

"@babel/core@^7.0.0":
  version "7.12.3"
`
	checkDeps(t, parseYarnLock(body), map[string]string{
		"lodash":      "4.17.21",
		"@babel/core": "7.12.3",
	})
}

func TestParseYarnLockBerry(t *testing.T) {
	body := `"lodash@npm:^4.17.0":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"

"@scope/pkg@npm:^1.0.0":
  version: 1.2.3
`
	checkDeps(t, parseYarnLock(body), map[string]string{
		"lodash":     "4.17.21",
		"@scope/pkg": "1.2.3",
	})
}

func TestParseRequirementsTxt(t *testing.T) {
	body := `# comentario
Django==3.2.1
requests == 2.25.1
flask[async]==2.0.0
numpy>=1.20   # no fijada, se ignora
-r otro.txt
`
	got := parseRequirementsTxt(body)
	checkDeps(t, got, map[string]string{
		"Django":   "3.2.1",
		"requests": "2.25.1",
		"flask":    "2.0.0",
	})
	if _, ok := got["numpy"]; ok {
		t.Error("numpy>=1.20 no debería incluirse (no está fijada con ==)")
	}
}

func TestParsePipfileLock(t *testing.T) {
	body := `{
		"default": {"django": {"version": "==3.2.1"}, "requests": {"version": "==2.25.1"}},
		"develop": {"pytest": {"version": "==6.2.0"}}
	}`
	checkDeps(t, parsePipfileLock(body), map[string]string{
		"django":   "3.2.1",
		"requests": "2.25.1",
		"pytest":   "6.2.0",
	})
}

func TestParseGoMod(t *testing.T) {
	body := `module github.com/foo/bar

go 1.22

require github.com/gin-gonic/gin v1.9.0

require (
	github.com/stretchr/testify v1.8.1
	golang.org/x/crypto v0.14.0 // indirect
)
`
	got := parseGoMod(body)
	checkDeps(t, got, map[string]string{
		"github.com/gin-gonic/gin":    "1.9.0",
		"github.com/stretchr/testify": "1.8.1",
		"golang.org/x/crypto":         "0.14.0",
	})
	if _, ok := got["github.com/foo/bar"]; ok {
		t.Error("la línea module no debería tratarse como dependencia")
	}
}

func TestAnalyzeLockfileDispatch(t *testing.T) {
	// go.mod sin CVEs conocidos ni OSV: no debe fallar, devuelve sin findings de versión.
	fs := AnalyzeLockfile("module x\n\nrequire github.com/a/b v1.0.0\n", "http://x", "/go.mod", "Go", false)
	if len(fs) != 0 {
		t.Errorf("sin cvedb ni OSV no debería haber findings, got %d", len(fs))
	}
}
