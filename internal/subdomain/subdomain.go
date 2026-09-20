package subdomain

import (
	"bufio"
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// LoadWordlistFile lee una wordlist externa (una entrada por línea, tipo
// SecLists) — permite usar listas de miles de entradas sin embeberlas en
// el binario. Líneas vacías y que empiezan con # se ignoran.
func LoadWordlistFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, scanner.Err()
}

// categorizedSubdomains agrupa la wordlist por "qué tipo de exposición busca
// encontrar" — así se puede acotar el escaneo a lo que interesa en vez de
// tirar siempre la lista completa. Las categorías no son mutuamente
// excluyentes en la práctica (un subdominio puede calzar en más de un
// concepto), pero cada entrada vive en UNA categoría acá para simplicidad.
var categorizedSubdomains = map[string][]string{
	"admin": {
		"admin", "administrator", "panel", "cpanel", "portal",
		"phpmyadmin", "adminer", "manage", "management",
	},
	"dev": {
		"dev", "develop", "development", "staging", "stage",
		"test", "testing", "qa", "uat", "demo", "preprod", "pre", "beta",
	},
	"infra": {
		"mail", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
		"ftp", "sftp", "autodiscover", "mx",
	},
	"remote-access": {
		"vpn", "remote", "gateway", "proxy", "ssh", "rdp",
	},
	"devops": {
		"jenkins", "gitlab", "git", "ci", "jira", "confluence", "grafana", "kibana",
	},
	"web": {
		"www", "cdn", "static", "assets", "media", "blog", "shop", "store", "app", "api",
	},
	"sensitive": {
		"secure", "login", "auth", "sso", "vault", "backup",
		"old", "new", "internal", "intranet", "private",
	},
	"data": {
		"db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
	},
}

// depthCategories define qué categorías entran en cada nivel de profundidad,
// cuando no se pide un --focus específico.
var depthCategories = map[string][]string{
	"fast":   {"admin", "dev", "infra"},
	"normal": {"admin", "dev", "infra", "remote-access", "devops", "web"},
	"deep":   {"admin", "dev", "infra", "remote-access", "devops", "web", "sensitive", "data"},
}

// BuildWordlist arma la lista final de subdominios a probar, combinando
// depth (fast|normal|deep) y focus (categorías específicas, si se piden).
// focus, si no está vacío, GANA sobre depth — permite acotar a exactamente
// lo que se busca (ej. --focus admin,dev para enfocarse en exposición de
// paneles/entornos, ignorando infra de correo).
func BuildWordlist(depth string, focus []string) []string {
	var categories []string
	if len(focus) > 0 {
		categories = focus
	} else {
		cats, ok := depthCategories[depth]
		if !ok {
			cats = depthCategories["normal"]
		}
		categories = cats
	}

	seen := map[string]bool{}
	var out []string
	for _, cat := range categories {
		for _, sub := range categorizedSubdomains[cat] {
			if !seen[sub] {
				seen[sub] = true
				out = append(out, sub)
			}
		}
	}
	return out
}

type Result struct {
	Subdomain string
	FQDN      string
	IPs       []string
}

// Enumerate resuelve cada entrada de `wordlist` contra `domain` con un
// worker pool concurrente. Solo hace resolución DNS (net.LookupHost) — no
// se conecta a nada, no envía requests, es reconocimiento pasivo puro.
func Enumerate(domain string, wordlist []string, concurrency int, timeout time.Duration) []Result {
	if concurrency <= 0 {
		concurrency = 20
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	resolver := &net.Resolver{}

	for _, sub := range wordlist {
		wg.Add(1)
		sem <- struct{}{}

		go func(sub string) {
			defer wg.Done()
			defer func() { <-sem }()

			fqdn := sub + "." + domain
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			ips, err := resolver.LookupHost(ctx, fqdn)
			if err != nil || len(ips) == 0 {
				return
			}

			mu.Lock()
			results = append(results, Result{Subdomain: sub, FQDN: fqdn, IPs: ips})
			mu.Unlock()
		}(sub)
	}

	wg.Wait()
	return results
}
