package scope

import (
	"os"
	"path/filepath"
	"testing"
)

func writeScope(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("no se pudo escribir scope de prueba: %v", err)
	}
	return path
}

func TestLoadValidScope(t *testing.T) {
	path := writeScope(t, `
authorized_by: "Jane Doe"
date_signed: "2024-01-15"
targets:
  - domain: example.com
    subdomains: true
  - ip_range: 10.0.0.0/24
excluded:
  - admin.example.com
`)

	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error inesperado: %v", err)
	}
	if s.AuthorizedBy != "Jane Doe" {
		t.Errorf("AuthorizedBy = %q, want %q", s.AuthorizedBy, "Jane Doe")
	}
	if len(s.Targets) != 2 {
		t.Fatalf("len(Targets) = %d, want 2", len(s.Targets))
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("/no/existe/scope.yaml"); err == nil {
		t.Fatal("esperaba error al cargar archivo inexistente")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	path := writeScope(t, "not: [valid: yaml")
	if _, err := Load(path); err == nil {
		t.Fatal("esperaba error con YAML inválido")
	}
}

func TestValidateMissingAuthorizedBy(t *testing.T) {
	path := writeScope(t, `
date_signed: "2024-01-15"
targets:
  - domain: example.com
`)
	if _, err := Load(path); err == nil {
		t.Fatal("esperaba error por falta de authorized_by")
	}
}

func TestValidateNoTargets(t *testing.T) {
	path := writeScope(t, `
authorized_by: "Jane Doe"
date_signed: "2024-01-15"
targets: []
`)
	if _, err := Load(path); err == nil {
		t.Fatal("esperaba error por falta de targets")
	}
}

func TestValidateBadDate(t *testing.T) {
	path := writeScope(t, `
authorized_by: "Jane Doe"
date_signed: "15-01-2024"
targets:
  - domain: example.com
`)
	if _, err := Load(path); err == nil {
		t.Fatal("esperaba error por date_signed con formato inválido")
	}
}

func TestIsAuthorizedDomain(t *testing.T) {
	s := &Scope{
		Targets: []Target{
			{Domain: "example.com", Subdomains: false},
		},
	}
	if !s.IsAuthorized("example.com") {
		t.Error("example.com debería estar autorizado")
	}
	if !s.IsAuthorized("EXAMPLE.com") {
		t.Error("la comparación de dominio debería ignorar mayúsculas")
	}
	if s.IsAuthorized("sub.example.com") {
		t.Error("sub.example.com no debería estar autorizado sin subdomains:true")
	}
	if s.IsAuthorized("other.com") {
		t.Error("other.com no debería estar autorizado")
	}
}

func TestIsAuthorizedSubdomains(t *testing.T) {
	s := &Scope{
		Targets: []Target{
			{Domain: "example.com", Subdomains: true},
		},
	}
	if !s.IsAuthorized("api.example.com") {
		t.Error("api.example.com debería estar autorizado con subdomains:true")
	}
	if !s.IsAuthorized("example.com") {
		t.Error("el dominio raíz debería seguir autorizado")
	}
	if s.IsAuthorized("notexample.com") {
		t.Error("notexample.com no debería matchear por sufijo parcial")
	}
}

func TestIsAuthorizedIPRange(t *testing.T) {
	s := &Scope{
		Targets: []Target{
			{IPRange: "192.168.1.0/24"},
		},
	}
	if !s.IsAuthorized("192.168.1.50") {
		t.Error("192.168.1.50 debería estar dentro del rango autorizado")
	}
	if s.IsAuthorized("192.168.2.50") {
		t.Error("192.168.2.50 no debería estar autorizado")
	}
	if s.IsAuthorized("not-an-ip") {
		t.Error("un target no-IP no debería matchear contra un IPRange")
	}
}

func TestIsAuthorizedExcludedOverridesTarget(t *testing.T) {
	s := &Scope{
		Targets: []Target{
			{Domain: "example.com", Subdomains: true},
		},
		Excluded: []string{"admin.example.com"},
	}
	if s.IsAuthorized("admin.example.com") {
		t.Error("admin.example.com está excluido explícitamente y no debería estar autorizado")
	}
	if !s.IsAuthorized("api.example.com") {
		t.Error("api.example.com no está excluido y sí debería estar autorizado")
	}
}

func TestIsExcludedSuffixMatch(t *testing.T) {
	s := &Scope{Excluded: []string{"internal.example.com"}}
	if !s.IsExcluded("db.internal.example.com") {
		t.Error("un subdominio de un excluido también debería estar excluido")
	}
	if !s.IsExcluded("INTERNAL.example.com") {
		t.Error("IsExcluded debería ignorar mayúsculas/minúsculas")
	}
	if s.IsExcluded("notinternal.example.com") {
		t.Error("no debería matchear por sufijo de string sin punto separador")
	}
}
