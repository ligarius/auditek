package osv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// cacheTTL es cuánto se considera fresca una respuesta cacheada de OSV. Repetir
// scans dentro de la ventana no vuelve a consultar la red (y funciona offline
// para lo ya visto). Los paquetes "limpios" también se cachean, para no
// reconsultarlos.
const cacheTTL = 24 * time.Hour

type cacheEntry struct {
	FetchedAt time.Time `json:"fetched_at"`
	Vulns     []Vuln    `json:"vulns"`
}

// cachePathFn se puede sobrescribir en tests.
var cachePathFn = defaultCachePath

var cacheMu sync.Mutex

func defaultCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".auditek", "osv-cache.json")
}

func loadCache() map[string]cacheEntry {
	path := cachePathFn()
	m := map[string]cacheEntry{}
	if path == "" {
		return m
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	_ = json.Unmarshal(b, &m)
	if m == nil {
		m = map[string]cacheEntry{}
	}
	return m
}

func saveCache(m map[string]cacheEntry) {
	path := cachePathFn()
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, b, 0600)
}

func cacheKey(ecosystem, name, version string) string {
	return ecosystem + "|" + name + "|" + version
}

func fresh(e cacheEntry, now time.Time, ttl time.Duration) bool {
	return !e.FetchedAt.IsZero() && now.Sub(e.FetchedAt) < ttl
}
