package subdomain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ctEntry refleja el subset del JSON de crt.sh que usamos.
type ctEntry struct {
	NameValue string `json:"name_value"`
}

// FetchCTLogs consulta Certificate Transparency (crt.sh) por certificados
// emitidos para *.<domain> y devuelve los labels de subdominio únicos
// (relativos a domain), sin comodines ni el apex.
//
// Es reconocimiento PASIVO sobre datos públicos de CT: no toca la
// infraestructura del objetivo. Pero sí contacta un tercero (crt.sh), por eso
// en el CLI es opt-in (--ct). Los labels devueltos se resuelven luego por DNS
// como cualquier otro candidato, así que un nombre histórico que ya no resuelve
// simplemente no aparece en los resultados finales.
func FetchCTLogs(domain string, timeout time.Duration) ([]string, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	endpoint := "https://crt.sh/?q=%25." + domain + "&output=json"

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "auditek-subdomain-recon")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh respondió %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20)) // tope 20 MB
	if err != nil {
		return nil, err
	}
	return parseCTNames(body, domain)
}

// parseCTNames extrae labels de subdominio únicos del JSON de crt.sh. Cada
// entrada puede traer varios nombres separados por "\n" y comodines (*.x).
func parseCTNames(body []byte, domain string) ([]string, error) {
	var entries []ctEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("JSON de crt.sh inválido: %w", err)
	}

	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	suffix := "." + domain

	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(name))
			name = strings.TrimSuffix(name, ".")
			if name == "" || strings.HasPrefix(name, "*") {
				continue // comodines no se resuelven como tal
			}
			if name == domain {
				continue // el apex, no un subdominio
			}
			if !strings.HasSuffix(name, suffix) {
				continue // fuera del dominio objetivo
			}
			label := strings.TrimSuffix(name, suffix)
			if label == "" || seen[label] {
				continue
			}
			seen[label] = true
			out = append(out, label)
		}
	}
	return out, nil
}

// MergeCandidates une dos listas de labels quitando duplicados y vacíos,
// preservando el orden (primero los de a, luego los nuevos de b).
func MergeCandidates(a, b []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, s := range b {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
