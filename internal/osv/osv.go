// Package osv consulta la base pública de vulnerabilidades OSV (osv.dev) para
// dependencias de software (npm, Packagist, PyPI, Go, ...). A diferencia del
// set curado local + NVD por keyword, OSV cubre advisories de ecosistemas de
// paquetes (GHSA/CVE) con rangos de versión precisos.
//
// Contacta un tercero (api.osv.dev) sobre datos públicos; en el CLI es opt-in
// (--osv). No envía nada del objetivo salvo nombres+versiones de paquetes ya
// leídos de un manifiesto expuesto públicamente.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

const apiBase = "https://api.osv.dev"

// Vuln es una vulnerabilidad de OSV ya normalizada para el reporte de auditek.
type Vuln struct {
	ID       string // ID de OSV (GHSA-... o CVE-...)
	CVE      string // alias CVE si existe, si no el ID
	Summary  string // resumen corto
	Severity string // critical | high | medium | low
	Package  string // paquete afectado
	Version  string // versión consultada
}

// --- shapes de la API ---

type batchPkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}
type batchQuery struct {
	Package batchPkg `json:"package"`
	Version string   `json:"version"`
}
type batchReq struct {
	Queries []batchQuery `json:"queries"`
}
type batchResp struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

type vulnDetail struct {
	ID               string   `json:"id"`
	Summary          string   `json:"summary"`
	Details          string   `json:"details"`
	Aliases          []string `json:"aliases"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

// ScanDependencies consulta OSV por cada paquete+versión y devuelve las
// vulnerabilidades encontradas. Hace UNA request batch para saber qué paquetes
// tienen vulnerabilidades y luego pide el detalle solo de esos IDs (que suelen
// ser pocos), para minimizar el tráfico.
func ScanDependencies(ecosystem string, deps map[string]string, timeout time.Duration) ([]Vuln, error) {
	if len(deps) == 0 {
		return nil, nil
	}
	if timeout <= 0 {
		timeout = 25 * time.Second
	}

	now := time.Now()
	cacheMu.Lock()
	cache := loadCache()
	cacheMu.Unlock()

	// Separa lo que ya está fresco en cache de lo que hay que consultar.
	var out []Vuln
	var miss []string
	for name, ver := range deps {
		if e, ok := cache[cacheKey(ecosystem, name, ver)]; ok && fresh(e, now, cacheTTL) {
			out = append(out, e.Vulns...)
		} else {
			miss = append(miss, name)
		}
	}
	if len(miss) == 0 {
		return out, nil // todo servido desde cache (sin red)
	}
	sort.Strings(miss)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	queries := make([]batchQuery, len(miss))
	for i, n := range miss {
		queries[i] = batchQuery{Package: batchPkg{Name: n, Ecosystem: ecosystem}, Version: deps[n]}
	}
	idsPerQuery, err := queryBatch(ctx, queries)
	if err != nil {
		// Sin red: devolvemos lo cacheado (best-effort), sin romper el scan.
		return out, err
	}

	fetched := map[string][]Vuln{}
	for i, ids := range idsPerQuery {
		if i >= len(miss) {
			break
		}
		name := miss[i]
		fetched[name] = nil // registra "consultado" aunque salga limpio
		seen := map[string]bool{}
		for _, id := range ids {
			if seen[id] {
				continue
			}
			seen[id] = true
			v := Vuln{ID: id, CVE: id, Package: name, Version: deps[name], Severity: "medium"}
			if d, derr := getVuln(ctx, id); derr == nil {
				v.Summary = summaryOf(d)
				v.Severity = severityOf(d)
				v.CVE = pickCVE(d.Aliases, id)
			}
			fetched[name] = append(fetched[name], v)
			out = append(out, v)
		}
	}

	// Persiste lo consultado (incl. paquetes limpios) con timestamp.
	cacheMu.Lock()
	cache = loadCache()
	for name, vulns := range fetched {
		cache[cacheKey(ecosystem, name, deps[name])] = cacheEntry{FetchedAt: now, Vulns: vulns}
	}
	saveCache(cache)
	cacheMu.Unlock()

	return out, nil
}

func queryBatch(ctx context.Context, queries []batchQuery) ([][]string, error) {
	payload, err := json.Marshal(batchReq{Queries: queries})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/v1/querybatch", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "auditek-sca")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv querybatch respondió %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return nil, err
	}
	return parseBatch(body)
}

// parseBatch extrae, por cada query en orden, la lista de IDs de vulnerabilidad.
func parseBatch(body []byte) ([][]string, error) {
	var br batchResp
	if err := json.Unmarshal(body, &br); err != nil {
		return nil, fmt.Errorf("respuesta batch de OSV inválida: %w", err)
	}
	out := make([][]string, len(br.Results))
	for i, r := range br.Results {
		for _, v := range r.Vulns {
			out[i] = append(out[i], v.ID)
		}
	}
	return out, nil
}

func getVuln(ctx context.Context, id string) (vulnDetail, error) {
	var d vulnDetail
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1/vulns/"+id, nil)
	if err != nil {
		return d, err
	}
	req.Header.Set("User-Agent", "auditek-sca")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return d, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return d, fmt.Errorf("osv vulns/%s respondió %d", id, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return d, err
	}
	return d, nil
}

func summaryOf(d vulnDetail) string {
	if s := strings.TrimSpace(d.Summary); s != "" {
		return s
	}
	return truncate(strings.TrimSpace(d.Details), 160)
}

// severityOf normaliza la severidad. Los advisories GHSA (npm/Packagist/PyPI)
// traen database_specific.severity ("CRITICAL"/"HIGH"/"MODERATE"/"LOW"); si no
// está, no intentamos parsear el vector CVSS y usamos "medium" como neutro.
func severityOf(d vulnDetail) string {
	switch strings.ToUpper(strings.TrimSpace(d.DatabaseSpecific.Severity)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MODERATE", "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "medium"
	}
}

// pickCVE devuelve el primer alias CVE-*, o el id de OSV si no hay ninguno.
func pickCVE(aliases []string, id string) string {
	for _, a := range aliases {
		if strings.HasPrefix(strings.ToUpper(a), "CVE-") {
			return a
		}
	}
	return id
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
