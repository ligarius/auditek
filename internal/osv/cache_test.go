package osv

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFresh(t *testing.T) {
	now := time.Now()
	if !fresh(cacheEntry{FetchedAt: now.Add(-time.Hour)}, now, cacheTTL) {
		t.Error("una entrada de hace 1h debería estar fresca (TTL 24h)")
	}
	if fresh(cacheEntry{FetchedAt: now.Add(-48 * time.Hour)}, now, cacheTTL) {
		t.Error("una entrada de hace 48h no debería estar fresca")
	}
	if fresh(cacheEntry{}, now, cacheTTL) {
		t.Error("una entrada sin timestamp no debería estar fresca")
	}
}

func TestCacheKey(t *testing.T) {
	if cacheKey("npm", "lodash", "4.17.0") != "npm|lodash|4.17.0" {
		t.Error("formato de clave inesperado")
	}
}

func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	orig := cachePathFn
	cachePathFn = func() string { return filepath.Join(dir, "osv-cache.json") }
	defer func() { cachePathFn = orig }()

	// Carga inicial vacía.
	if m := loadCache(); len(m) != 0 {
		t.Errorf("cache inicial debería estar vacía, got %d", len(m))
	}

	in := map[string]cacheEntry{
		cacheKey("npm", "lodash", "4.17.21"): {FetchedAt: time.Now(), Vulns: nil},
		cacheKey("PyPI", "django", "3.2.1"): {FetchedAt: time.Now(), Vulns: []Vuln{
			{ID: "GHSA-x", CVE: "CVE-2021-1", Package: "django", Version: "3.2.1", Severity: "high"},
		}},
	}
	saveCache(in)

	got := loadCache()
	if len(got) != 2 {
		t.Fatalf("esperaba 2 entradas, got %d", len(got))
	}
	e := got[cacheKey("PyPI", "django", "3.2.1")]
	if len(e.Vulns) != 1 || e.Vulns[0].CVE != "CVE-2021-1" {
		t.Errorf("no se preservó la vuln cacheada: %+v", e)
	}
}
