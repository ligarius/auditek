package cvedb

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// NVDResponse refleja el subset de campos que usamos de la API NVD CVE 2.0.
// Schema real: https://nvd.nist.gov/developers/vulnerabilities
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseSeverity string `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			Configurations []struct {
				Nodes []struct {
					CpeMatch []struct {
						Criteria              string `json:"criteria"`
						VersionStartIncluding string `json:"versionStartIncluding"`
						VersionEndExcluding   string `json:"versionEndExcluding"`
						VersionEndIncluding   string `json:"versionEndIncluding"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

const nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// FetchFromNVD busca CVEs por palabra clave de producto (ej. "Apache HTTP Server")
// y devuelve entradas normalizadas al formato local de cvedb.
//
// baseURL permite apuntar a un servidor distinto para pruebas; pasar "" usa
// el endpoint real de NVD.
//
// LIMITACIÓN CONOCIDA: la NVD limita a ~5 requests/30s sin API key — para
// consultar varios productos en `update-db`, hay que espaciar las llamadas
// o registrar una key gratuita (ver https://nvd.nist.gov/developers/request-an-api-key).
func FetchFromNVD(product string, client *http.Client) ([]Entry, error) {
	return fetchFromNVD(product, client, nvdBaseURL)
}

// FetchFromNVDAt es como FetchFromNVD pero permite apuntar a un baseURL
// distinto — usado en tests/validación para no depender de la red real.
func FetchFromNVDAt(product, baseURL string, client *http.Client) ([]Entry, error) {
	return fetchFromNVD(product, client, baseURL)
}

func fetchFromNVD(product string, client *http.Client, baseURL string) ([]Entry, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	q := url.Values{}
	q.Set("keywordSearch", product)
	q.Set("resultsPerPage", "20")

	req, err := http.NewRequest("GET", baseURL+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error consultando NVD: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("NVD rate limit alcanzado — espera ~30s o usa una API key (ver NVD developers)")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NVD respondió %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var parsed nvdResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("error parseando respuesta NVD: %w", err)
	}

	return normalizeNVD(product, parsed), nil
}

// normalizeNVD convierte el formato verboso de NVD a nuestras Entry simples.
// Toma la primera condición de versión (versionStartIncluding/versionEndExcluding)
// de cada CVE que tenga configuración de CPE — suficiente para el modelo simple
// de Min/MaxVersion que ya usa el motor de matching.
func normalizeNVD(product string, r nvdResponse) []Entry {
	var entries []Entry

	for _, v := range r.Vulnerabilities {
		desc := ""
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}

		severity := "medium"
		if len(v.CVE.Metrics.CvssMetricV31) > 0 {
			s := v.CVE.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
			if s != "" {
				severity = s
			}
		}

		for _, cfg := range v.CVE.Configurations {
			for _, node := range cfg.Nodes {
				for _, cpe := range node.CpeMatch {
					if cpe.VersionStartIncluding == "" && cpe.VersionEndExcluding == "" && cpe.VersionEndIncluding == "" {
						continue // sin rango de versión útil, no lo podemos mapear a nuestro modelo
					}
					e := Entry{
						Product:     product,
						MinVersion:  cpe.VersionStartIncluding,
						CVE:         v.CVE.ID,
						Severity:    normalizeSeverity(severity),
						Description: truncateDesc(desc, 150),
						Impact:      desc, // NVD no separa "impact" de "description"; usamos la misma
					}
					if cpe.VersionEndExcluding != "" {
						e.MaxVersion = cpe.VersionEndExcluding
					} else if cpe.VersionEndIncluding != "" {
						e.MaxVersion = cpe.VersionEndIncluding + ".999" // aproximación: incluir la versión tope
					}
					entries = append(entries, e)
				}
			}
		}
	}
	return entries
}

func normalizeSeverity(s string) string {
	switch s {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "medium"
	}
}

func truncateDesc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// --- Cache local ---

func cacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".auditek")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

// SaveCache persiste entradas descargadas de NVD en ~/.auditek/cve-cache.json
func SaveCache(entries []Entry) error {
	dir, err := cacheDir()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cve-cache.json"), data, 0644)
}

// LoadCache lee las entradas cacheadas, si existen. No falla si el archivo no existe.
func LoadCache() ([]Entry, error) {
	dir, err := cacheDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "cve-cache.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}
