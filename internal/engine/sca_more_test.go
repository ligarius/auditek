package engine

import "testing"

func TestParseGoSum(t *testing.T) {
	body := "github.com/gin-gonic/gin v1.9.0 h1:aaa=\n" +
		"github.com/gin-gonic/gin v1.9.0/go.mod h1:bbb=\n" +
		"golang.org/x/crypto v0.14.0 h1:ccc=\n" +
		"golang.org/x/crypto v0.14.0/go.mod h1:ddd=\n"
	checkDeps(t, parseGoSum(body), map[string]string{
		"github.com/gin-gonic/gin": "1.9.0",
		"golang.org/x/crypto":      "0.14.0",
	})
}

func TestParseGemfileLock(t *testing.T) {
	body := "GEM\n  remote: https://rubygems.org/\n  specs:\n" +
		"    rails (6.1.4)\n" +
		"      actionpack (= 6.1.4)\n" + // dependencia (6 espacios) -> se ignora
		"    nokogiri (1.11.7)\n" +
		"\nPLATFORMS\n  ruby\n"
	got := parseGemfileLock(body)
	checkDeps(t, got, map[string]string{"rails": "6.1.4", "nokogiri": "1.11.7"})
	if _, ok := got["actionpack"]; ok {
		t.Error("las dependencias anidadas (6 espacios) no deberían incluirse")
	}
}

func TestParsePoetryLock(t *testing.T) {
	body := `[[package]]
name = "django"
version = "3.2.1"
description = "..."

[[package]]
name = "requests"
version = "2.25.1"
`
	checkDeps(t, parsePoetryLock(body), map[string]string{
		"django":   "3.2.1",
		"requests": "2.25.1",
	})
}

func TestParsePnpmLock(t *testing.T) {
	// v6 (pkg@ver) y v5 (pkg/ver), con scoped y sufijo de peers.
	body := "lockfileVersion: '6.0'\n\npackages:\n\n" +
		"  /lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n" +
		"  /@babel/core@7.12.3:\n    resolution: {integrity: sha512-y}\n" +
		"  /react-dom@18.2.0(react@18.2.0):\n    resolution: {integrity: sha512-z}\n" +
		"  /old-style/1.0.0:\n    resolution: {integrity: sha512-w}\n"
	checkDeps(t, parsePnpmLock(body), map[string]string{
		"lodash":      "4.17.21",
		"@babel/core": "7.12.3",
		"react-dom":   "18.2.0",
		"old-style":   "1.0.0",
	})
}
